use std::{
    fs::File,
    io,
    io::{BufReader, Read, Seek, SeekFrom},
    mem::size_of,
    path::{Component, Path, PathBuf},
};

use zerocopy::{big_endian::U32, AsBytes, FromBytes, FromZeroes};

use crate::{
    array_ref,
    disc::{
        wii::{read_partition_info, HASHES_SIZE},
        SECTOR_SIZE,
    },
    io::{aes_decrypt, aes_encrypt, split::SplitFileReader, DiscIO, KeyBytes, MagicBytes},
    static_assert,
    streams::ReadStream,
    util::reader::read_from,
    DiscHeader, Error, OpenOptions, Result, ResultContext,
};

pub const NFS_MAGIC: MagicBytes = *b"EGGS";
pub const NFS_END_MAGIC: MagicBytes = *b"SGGE";

#[derive(Clone, Debug, PartialEq, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub struct LBARange {
    pub start_sector: U32,
    pub num_sectors: U32,
}

#[derive(Clone, Debug, PartialEq, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub struct NFSHeader {
    pub magic: MagicBytes,
    pub version: U32,
    pub unk1: U32,
    pub unk2: U32,
    pub num_lba_ranges: U32,
    pub lba_ranges: [LBARange; 61],
    pub end_magic: MagicBytes,
}

static_assert!(size_of::<NFSHeader>() == 0x200);

impl NFSHeader {
    pub fn validate(&self) -> Result<()> {
        if self.magic != NFS_MAGIC {
            return Err(Error::DiscFormat("Invalid NFS magic".to_string()));
        }
        if self.num_lba_ranges.get() > 61 {
            return Err(Error::DiscFormat("Invalid NFS LBA range count".to_string()));
        }
        if self.end_magic != NFS_END_MAGIC {
            return Err(Error::DiscFormat("Invalid NFS end magic".to_string()));
        }
        Ok(())
    }

    pub fn lba_ranges(&self) -> &[LBARange] {
        &self.lba_ranges[..self.num_lba_ranges.get() as usize]
    }

    pub fn calculate_num_files(&self) -> u32 {
        let sector_count =
            self.lba_ranges().iter().fold(0u32, |acc, range| acc + range.num_sectors.get());
        (((sector_count as u64) * (SECTOR_SIZE as u64)
            + (size_of::<NFSHeader>() as u64 + 0xF9FFFFFu64))
            / 0xFA00000u64) as u32
    }

    pub fn phys_sector(&self, sector: u32) -> u32 {
        let mut cur_sector = 0u32;
        for range in self.lba_ranges().iter() {
            if sector >= range.start_sector.get()
                && sector - range.start_sector.get() < range.num_sectors.get()
            {
                return cur_sector + (sector - range.start_sector.get());
            }
            cur_sector += range.num_sectors.get();
        }
        u32::MAX
    }
}

pub struct DiscIONFS {
    pub inner: SplitFileReader,
    pub header: NFSHeader,
    pub raw_size: u64,
    pub disc_size: u64,
    pub key: KeyBytes,
    pub encrypt: bool,
}

impl DiscIONFS {
    pub fn new(directory: &Path, options: &OpenOptions) -> Result<DiscIONFS> {
        let mut disc_io = DiscIONFS {
            inner: SplitFileReader::empty(),
            header: NFSHeader::new_zeroed(),
            raw_size: 0,
            disc_size: 0,
            key: [0; 16],
            encrypt: options.rebuild_encryption,
        };
        disc_io.load_files(directory)?;
        Ok(disc_io)
    }
}

pub struct NFSReadStream {
    /// Underlying file reader
    inner: SplitFileReader,
    /// NFS file header
    header: NFSHeader,
    /// Inner disc header
    disc_header: Option<DiscHeader>,
    /// Estimated disc size
    disc_size: u64,
    /// Current offset
    pos: u64,
    /// Current sector
    sector: u32,
    /// Current decrypted sector
    buf: [u8; SECTOR_SIZE],
    /// AES key
    key: KeyBytes,
    /// Wii partition info
    part_info: Vec<PartitionInfo>,
}

struct PartitionInfo {
    start_sector: u32,
    end_sector: u32,
    key: KeyBytes,
}

impl NFSReadStream {
    fn read_sector(&mut self, sector: u32) -> io::Result<()> {
        // Calculate physical sector
        let phys_sector = self.header.phys_sector(sector);
        if phys_sector == u32::MAX {
            // Logical zero sector
            self.buf.fill(0u8);
            return Ok(());
        }

        // Read sector
        let offset = size_of::<NFSHeader>() as u64 + phys_sector as u64 * SECTOR_SIZE as u64;
        self.inner.seek(SeekFrom::Start(offset))?;
        self.inner.read_exact(&mut self.buf)?;

        // Decrypt
        let iv_bytes = sector.to_be_bytes();
        #[rustfmt::skip]
        let iv: KeyBytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            iv_bytes[0], iv_bytes[1], iv_bytes[2], iv_bytes[3],
        ];
        aes_decrypt(&self.key, iv, &mut self.buf);

        if sector == 0 {
            if let Some(header) = &self.disc_header {
                // Replace disc header in buffer
                let header_bytes = header.as_bytes();
                self.buf[..header_bytes.len()].copy_from_slice(header_bytes);
            }
        }

        // Re-encrypt if needed
        if let Some(part) = self
            .part_info
            .iter()
            .find(|part| sector >= part.start_sector && sector < part.end_sector)
        {
            // Encrypt hashes
            aes_encrypt(&part.key, [0u8; 16], &mut self.buf[..HASHES_SIZE]);
            // Encrypt data using IV from H2
            aes_encrypt(&part.key, *array_ref![self.buf, 0x3d0, 16], &mut self.buf[HASHES_SIZE..]);
        }

        Ok(())
    }
}

impl Read for NFSReadStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let sector = (self.pos / SECTOR_SIZE as u64) as u32;
        let sector_off = (self.pos % SECTOR_SIZE as u64) as usize;
        if sector != self.sector {
            self.read_sector(sector)?;
            self.sector = sector;
        }

        let read = buf.len().min(SECTOR_SIZE - sector_off);
        buf[..read].copy_from_slice(&self.buf[sector_off..sector_off + read]);
        self.pos += read as u64;
        Ok(read)
    }
}

impl Seek for NFSReadStream {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "NFSReadStream: SeekFrom::End is not supported",
                ));
            }
            SeekFrom::Current(v) => self.pos.saturating_add_signed(v),
        };
        Ok(self.pos)
    }

    fn stream_position(&mut self) -> io::Result<u64> { Ok(self.pos) }
}

impl ReadStream for NFSReadStream {
    fn stable_stream_len(&mut self) -> io::Result<u64> { Ok(self.disc_size) }

    fn as_dyn(&mut self) -> &mut dyn ReadStream { self }
}

impl DiscIO for DiscIONFS {
    fn open(&self) -> Result<Box<dyn ReadStream>> {
        let mut stream = NFSReadStream {
            inner: self.inner.clone(),
            header: self.header.clone(),
            disc_header: None,
            disc_size: self.disc_size,
            pos: 0,
            sector: u32::MAX,
            buf: [0; SECTOR_SIZE],
            key: self.key,
            part_info: vec![],
        };
        let mut disc_header: DiscHeader = read_from(&mut stream).context("Reading disc header")?;
        if !self.encrypt {
            // If we're not re-encrypting, disable partition encryption in disc header
            disc_header.no_partition_encryption = 1;
        }

        // Read partition info so we can re-encrypt
        if self.encrypt && disc_header.is_wii() {
            for part in read_partition_info(&mut stream)? {
                let start = part.offset + part.header.data_off();
                let end = start + part.header.data_size();
                if start % SECTOR_SIZE as u64 != 0 || end % SECTOR_SIZE as u64 != 0 {
                    return Err(Error::DiscFormat(format!(
                        "Partition start / end not aligned to sector size: {} / {}",
                        start, end
                    )));
                }
                stream.part_info.push(PartitionInfo {
                    start_sector: (start / SECTOR_SIZE as u64) as u32,
                    end_sector: (end / SECTOR_SIZE as u64) as u32,
                    key: part.header.ticket.title_key,
                });
            }
        }

        stream.disc_header = Some(disc_header);
        // Reset stream position
        stream.pos = 0;
        stream.sector = u32::MAX;
        Ok(Box::new(stream))
    }

    fn disc_size(&self) -> Option<u64> { None }
}

fn get_path<P>(directory: &Path, path: P) -> PathBuf
where P: AsRef<Path> {
    let mut buf = directory.to_path_buf();
    for component in path.as_ref().components() {
        match component {
            Component::ParentDir => {
                buf.pop();
            }
            _ => buf.push(component),
        }
    }
    buf
}

fn get_nfs(directory: &Path, num: u32) -> Result<PathBuf> {
    let path = get_path(directory, format!("hif_{:06}.nfs", num));
    if path.exists() {
        Ok(path)
    } else {
        Err(Error::DiscFormat(format!("Failed to locate {}", path.display())))
    }
}

impl DiscIONFS {
    pub fn load_files(&mut self, directory: &Path) -> Result<()> {
        {
            // Load key file
            let primary_key_path =
                get_path(directory, ["..", "code", "htk.bin"].iter().collect::<PathBuf>());
            let secondary_key_path = get_path(directory, "htk.bin");
            let mut key_path = primary_key_path.canonicalize();
            if key_path.is_err() {
                key_path = secondary_key_path.canonicalize();
            }
            if key_path.is_err() {
                return Err(Error::DiscFormat(format!(
                    "Failed to locate {} or {}",
                    primary_key_path.display(),
                    secondary_key_path.display()
                )));
            }
            let resolved_path = key_path.unwrap();
            File::open(resolved_path.as_path())
                .map_err(|v| Error::Io(format!("Failed to open {}", resolved_path.display()), v))?
                .read(&mut self.key)
                .map_err(|v| Error::Io(format!("Failed to read {}", resolved_path.display()), v))?;
        }

        {
            // Load header from first file
            let path = get_nfs(directory, 0)?;
            self.inner.add(&path)?;

            let mut file = BufReader::new(
                File::open(&path).with_context(|| format!("Opening file {}", path.display()))?,
            );
            let header: NFSHeader = read_from(&mut file)
                .with_context(|| format!("Reading NFS header from file {}", path.display()))?;
            header.validate()?;
            // log::debug!("{:?}", header);

            // Ensure remaining files exist
            for i in 1..header.calculate_num_files() {
                self.inner.add(&get_nfs(directory, i)?)?;
            }

            // Calculate sizes
            let num_sectors =
                header.lba_ranges().iter().map(|range| range.num_sectors.get()).sum::<u32>();
            let max_sector = header
                .lba_ranges()
                .iter()
                .map(|range| range.start_sector.get() + range.num_sectors.get())
                .max()
                .unwrap();
            let raw_size = size_of::<NFSHeader>() + (num_sectors as usize * SECTOR_SIZE);
            let data_size = max_sector as usize * SECTOR_SIZE;
            if raw_size > self.inner.len() as usize {
                return Err(Error::DiscFormat(format!(
                    "NFS raw size mismatch: expected at least {}, got {}",
                    raw_size,
                    self.inner.len()
                )));
            }

            self.header = header;
            self.raw_size = raw_size as u64;
            self.disc_size = data_size as u64;
        }
        Ok(())
    }
}
