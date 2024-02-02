use std::{
    fs::File,
    io,
    io::{BufReader, Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

use aes::{
    cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit},
    Aes128,
};

use crate::{
    disc::SECTOR_SIZE,
    io::DiscIO,
    streams::ReadStream,
    util::reader::{read_vec, struct_size, FromReader},
    Error, Result, ResultContext,
};

type Aes128Cbc = cbc::Decryptor<Aes128>;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LBARange {
    pub(crate) start_block: u32,
    pub(crate) num_blocks: u32,
}

impl FromReader for LBARange {
    type Args<'a> = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // start_block
        u32::STATIC_SIZE, // num_blocks
    ]);

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        Ok(LBARange {
            start_block: u32::from_reader(reader)?,
            num_blocks: u32::from_reader(reader)?,
        })
    }
}

type MagicBytes = [u8; 4];

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct NFSHeader {
    pub(crate) version: u32,
    pub(crate) unk1: u32,
    pub(crate) unk2: u32,
    pub(crate) lba_ranges: Vec<LBARange>,
}

impl FromReader for NFSHeader {
    type Args<'a> = ();

    const STATIC_SIZE: usize = struct_size([
        MagicBytes::STATIC_SIZE,    // magic
        u32::STATIC_SIZE,           // version
        u32::STATIC_SIZE,           // unk1
        u32::STATIC_SIZE,           // unk2
        u32::STATIC_SIZE,           // lba_range_count
        LBARange::STATIC_SIZE * 61, // lba_ranges
        MagicBytes::STATIC_SIZE,    // end_magic
    ]);

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        if MagicBytes::from_reader(reader)? != *b"EGGS" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid NFS magic"));
        }
        let version = u32::from_reader(reader)?;
        let unk1 = u32::from_reader(reader)?;
        let unk2 = u32::from_reader(reader)?;
        let lba_range_count = u32::from_reader(reader)?;
        let mut lba_ranges = read_vec(reader, 61)?;
        lba_ranges.truncate(lba_range_count as usize);
        if MagicBytes::from_reader(reader)? != *b"SGGE" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid NFS end magic"));
        }
        Ok(NFSHeader { version, unk1, unk2, lba_ranges })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Fbo {
    pub(crate) file: u32,
    pub(crate) block: u32,
    pub(crate) l_block: u32,
    pub(crate) offset: u32,
}

impl Default for Fbo {
    fn default() -> Self {
        Fbo { file: u32::MAX, block: u32::MAX, l_block: u32::MAX, offset: u32::MAX }
    }
}

impl NFSHeader {
    pub(crate) fn calculate_num_files(&self) -> u32 {
        let total_block_count =
            self.lba_ranges.iter().fold(0u32, |acc, range| acc + range.num_blocks);
        (((total_block_count as u64) * 0x8000u64 + (0x200u64 + 0xF9FFFFFu64)) / 0xFA00000u64) as u32
    }

    pub(crate) fn logical_to_fbo(&self, offset: u64) -> Fbo {
        let block_div = (offset / 0x8000) as u32;
        let block_off = (offset % 0x8000) as u32;
        let mut block = u32::MAX;
        let mut physical_block = 0u32;
        for range in self.lba_ranges.iter() {
            if block_div >= range.start_block && block_div - range.start_block < range.num_blocks {
                block = physical_block + (block_div - range.start_block);
                break;
            }
            physical_block += range.num_blocks;
        }
        if block == u32::MAX {
            Fbo::default()
        } else {
            Fbo { file: block / 8000, block: block % 8000, l_block: block_div, offset: block_off }
        }
    }
}

pub(crate) struct DiscIONFS {
    pub(crate) directory: PathBuf,
    pub(crate) key: [u8; 16],
    pub(crate) header: Option<NFSHeader>,
}

impl DiscIONFS {
    pub(crate) fn new(directory: &Path) -> Result<DiscIONFS> {
        let mut disc_io = DiscIONFS { directory: directory.to_owned(), key: [0; 16], header: None };
        disc_io.validate_files()?;
        Ok(disc_io)
    }
}

pub(crate) struct NFSReadStream<'a> {
    disc_io: &'a DiscIONFS,
    file: Option<File>,
    crypto: [u8; 16],
    // Physical address - all UINT32_MAX indicates logical zero block
    phys_addr: Fbo,
    // Logical address
    offset: u64,
    // Active file stream and its offset as set in the system.
    // Block is typically one ahead of the presently decrypted block.
    cur_file: u32,
    cur_block: u32,
    buf: [u8; SECTOR_SIZE],
}

impl<'a> NFSReadStream<'a> {
    fn set_cur_file(&mut self, cur_file: u32) -> Result<()> {
        if cur_file >= self.disc_io.header.as_ref().unwrap().calculate_num_files() {
            return Err(Error::DiscFormat(format!("Out of bounds NFS file access: {}", cur_file)));
        }
        self.cur_file = cur_file;
        self.cur_block = u32::MAX;
        let path = self.disc_io.get_nfs(cur_file)?;
        self.file = Option::from(
            File::open(&path).with_context(|| format!("Opening file {}", path.display()))?,
        );
        Ok(())
    }

    fn set_cur_block(&mut self, cur_block: u32) -> io::Result<()> {
        self.cur_block = cur_block;
        self.file
            .as_ref()
            .unwrap()
            .seek(SeekFrom::Start(self.cur_block as u64 * SECTOR_SIZE as u64 + 0x200u64))?;
        Ok(())
    }

    fn set_phys_addr(&mut self, phys_addr: Fbo) -> Result<()> {
        // If we're just changing the offset, nothing else needs to be done
        if self.phys_addr.file == phys_addr.file && self.phys_addr.block == phys_addr.block {
            self.phys_addr.offset = phys_addr.offset;
            return Ok(());
        }
        self.phys_addr = phys_addr;

        // Set logical zero block
        if phys_addr.file == u32::MAX {
            self.buf.fill(0u8);
            return Ok(());
        }

        // Make necessary file and block current with system
        if phys_addr.file != self.cur_file {
            self.set_cur_file(phys_addr.file)?;
        }
        if phys_addr.block != self.cur_block {
            self.set_cur_block(phys_addr.block)
                .with_context(|| format!("Seeking to NFS block {}", phys_addr.block))?;
        }

        // Read block, handling 0x200 overlap case
        if phys_addr.block == 7999 {
            self.file
                .as_ref()
                .unwrap()
                .read_exact(&mut self.buf[..SECTOR_SIZE - 0x200])
                .context("Reading NFS block 7999 part 1")?;
            self.set_cur_file(self.cur_file + 1)?;
            self.file
                .as_ref()
                .unwrap()
                .read_exact(&mut self.buf[SECTOR_SIZE - 0x200..])
                .context("Reading NFS block 7999 part 2")?;
            self.cur_block = 0;
        } else {
            self.file
                .as_ref()
                .unwrap()
                .read_exact(&mut self.buf)
                .with_context(|| format!("Reading NFS block {}", phys_addr.block))?;
            self.cur_block += 1;
        }

        // Decrypt
        #[rustfmt::skip]
        let iv: [u8; 16] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            (phys_addr.l_block & 0xFF) as u8,
            ((phys_addr.l_block >> 8) & 0xFF) as u8,
            ((phys_addr.l_block >> 16) & 0xFF) as u8,
            ((phys_addr.l_block >> 24) & 0xFF) as u8,
        ];
        Aes128Cbc::new(self.crypto.as_ref().into(), &iv.into())
            .decrypt_padded_mut::<NoPadding>(&mut self.buf)?;

        Ok(())
    }

    fn set_logical_addr(&mut self, addr: u64) -> Result<()> {
        self.set_phys_addr(self.disc_io.header.as_ref().unwrap().logical_to_fbo(addr))
    }
}

impl<'a> Read for NFSReadStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rem = buf.len();
        let mut read: usize = 0;
        while rem > 0 {
            let mut read_size = rem;
            let block_offset: usize =
                if self.phys_addr.offset == u32::MAX { 0 } else { self.phys_addr.offset as usize };
            if read_size + block_offset > SECTOR_SIZE {
                read_size = SECTOR_SIZE - block_offset
            }
            buf[read..read + read_size]
                .copy_from_slice(&self.buf[block_offset..block_offset + read_size]);
            read += read_size;
            rem -= read_size;
            self.offset += read_size as u64;
            self.set_logical_addr(self.offset).map_err(|e| match e {
                Error::Io(s, e) => io::Error::new(e.kind(), s),
                _ => io::Error::from(io::ErrorKind::Other),
            })?;
        }
        Ok(read)
    }
}

impl<'a> Seek for NFSReadStream<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.offset = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(v) => (self.stable_stream_len()? as i64 + v) as u64,
            SeekFrom::Current(v) => (self.offset as i64 + v) as u64,
        };
        self.set_logical_addr(self.offset).map_err(|v| match v {
            Error::Io(_, v) => v,
            _ => io::Error::from(io::ErrorKind::Other),
        })?;
        Ok(self.offset)
    }

    fn stream_position(&mut self) -> io::Result<u64> { Ok(self.offset) }
}

impl<'a> ReadStream for NFSReadStream<'a> {
    fn stable_stream_len(&mut self) -> io::Result<u64> { todo!() }

    fn as_dyn(&mut self) -> &mut dyn ReadStream { self }
}

impl DiscIO for DiscIONFS {
    fn begin_read_stream(&mut self, offset: u64) -> io::Result<Box<dyn ReadStream + '_>> {
        Ok(Box::from(NFSReadStream {
            disc_io: self,
            file: None,
            crypto: self.key,
            phys_addr: Fbo::default(),
            offset,
            cur_file: u32::MAX,
            cur_block: u32::MAX,
            buf: [0; SECTOR_SIZE],
        }))
    }

    fn has_wii_crypto(&self) -> bool { false }
}

impl DiscIONFS {
    fn get_path<P>(&self, path: P) -> PathBuf
    where P: AsRef<Path> {
        let mut buf = self.directory.clone();
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

    fn get_nfs(&self, num: u32) -> Result<PathBuf> {
        let path = self.get_path(format!("hif_{:06}.nfs", num));
        if path.exists() {
            Ok(path)
        } else {
            Err(Error::DiscFormat(format!("Failed to locate {}", path.display())))
        }
    }

    pub(crate) fn validate_files(&mut self) -> Result<()> {
        {
            // Load key file
            let primary_key_path =
                self.get_path(["..", "code", "htk.bin"].iter().collect::<PathBuf>());
            let secondary_key_path = self.get_path("htk.bin");
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
            let path = self.get_nfs(0)?;
            let mut file = BufReader::new(
                File::open(&path).with_context(|| format!("Opening file {}", path.display()))?,
            );
            let header = NFSHeader::from_reader(&mut file)
                .with_context(|| format!("Reading NFS header from file {}", path.display()))?;
            // Ensure remaining files exist
            for i in 1..header.calculate_num_files() {
                self.get_nfs(i)?;
            }
            self.header = Option::from(header);
        }
        Ok(())
    }
}
