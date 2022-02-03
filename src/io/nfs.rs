use std::{
    fs::File,
    io,
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

use aes::{Aes128, NewBlockCipher};
use binrw::{binread, BinRead, BinReaderExt};
use block_modes::{block_padding::NoPadding, BlockMode, Cbc};

use crate::{disc::BUFFER_SIZE, io::DiscIO, streams::ReadStream, Error, Result};

type Aes128Cbc = Cbc<Aes128, NoPadding>;

#[derive(Clone, Debug, PartialEq, BinRead)]
pub(crate) struct LBARange {
    pub(crate) start_block: u32,
    pub(crate) num_blocks: u32,
}

#[binread]
#[derive(Clone, Debug, PartialEq)]
#[br(magic = b"EGGS", assert(end_magic == * b"SGGE"))]
pub(crate) struct NFSHeader {
    pub(crate) version: u32,
    pub(crate) unk1: u32,
    pub(crate) unk2: u32,
    pub(crate) lba_range_count: u32,
    #[br(count = 61)]
    pub(crate) lba_ranges: Vec<LBARange>,
    #[br(temp)]
    pub(crate) end_magic: [u8; 4],
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct FBO {
    pub(crate) file: u32,
    pub(crate) block: u32,
    pub(crate) l_block: u32,
    pub(crate) offset: u32,
}

impl Default for FBO {
    fn default() -> Self {
        FBO { file: u32::MAX, block: u32::MAX, l_block: u32::MAX, offset: u32::MAX }
    }
}

impl NFSHeader {
    pub(crate) fn calculate_num_files(&self) -> u32 {
        let total_block_count = self
            .lba_ranges
            .iter()
            .take(self.lba_range_count as usize)
            .fold(0u32, |acc, range| acc + range.num_blocks);
        (((total_block_count as u64) * 0x8000u64 + (0x200u64 + 0xF9FFFFFu64)) / 0xFA00000u64) as u32
    }

    pub(crate) fn logical_to_fbo(&self, offset: u64) -> FBO {
        let block_div = (offset / 0x8000) as u32;
        let block_off = (offset % 0x8000) as u32;
        let mut block = u32::MAX;
        let mut physical_block = 0u32;
        for range in self.lba_ranges.iter().take(self.lba_range_count as usize) {
            if block_div >= range.start_block && block_div - range.start_block < range.num_blocks {
                block = physical_block + (block_div - range.start_block);
                break;
            }
            physical_block += range.num_blocks;
        }
        if block == u32::MAX {
            FBO::default()
        } else {
            FBO { file: block / 8000, block: block % 8000, l_block: block_div, offset: block_off }
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
        let mut disc_io =
            DiscIONFS { directory: directory.to_owned(), key: [0; 16], header: Option::None };
        disc_io.validate_files()?;
        Result::Ok(disc_io)
    }
}

pub(crate) struct NFSReadStream<'a> {
    disc_io: &'a DiscIONFS,
    file: Option<File>,
    crypto: Aes128,
    // Physical address - all UINT32_MAX indicates logical zero block
    phys_addr: FBO,
    // Logical address
    offset: u64,
    // Active file stream and its offset as set in the system.
    // Block is typically one ahead of the presently decrypted block.
    cur_file: u32,
    cur_block: u32,
    buf: [u8; BUFFER_SIZE],
}

impl<'a> NFSReadStream<'a> {
    fn set_cur_file(&mut self, cur_file: u32) -> Result<()> {
        if cur_file >= self.disc_io.header.as_ref().unwrap().calculate_num_files() {
            return Result::Err(Error::DiscFormat("Out of bounds NFS file access".to_string()));
        }
        self.cur_file = cur_file;
        self.cur_block = u32::MAX;
        self.file = Option::from(File::open(self.disc_io.get_nfs(cur_file)?)?);
        Result::Ok(())
    }

    fn set_cur_block(&mut self, cur_block: u32) -> io::Result<()> {
        self.cur_block = cur_block;
        self.file
            .as_ref()
            .unwrap()
            .seek(SeekFrom::Start(self.cur_block as u64 * BUFFER_SIZE as u64 + 0x200u64))?;
        io::Result::Ok(())
    }

    fn set_phys_addr(&mut self, phys_addr: FBO) -> Result<()> {
        // If we're just changing the offset, nothing else needs to be done
        if self.phys_addr.file == phys_addr.file && self.phys_addr.block == phys_addr.block {
            self.phys_addr.offset = phys_addr.offset;
            return Result::Ok(());
        }
        self.phys_addr = phys_addr;

        // Set logical zero block
        if phys_addr.file == u32::MAX {
            self.buf.fill(0u8);
            return Result::Ok(());
        }

        // Make necessary file and block current with system
        if phys_addr.file != self.cur_file {
            self.set_cur_file(phys_addr.file)?;
        }
        if phys_addr.block != self.cur_block {
            self.set_cur_block(phys_addr.block)?;
        }

        // Read block, handling 0x200 overlap case
        if phys_addr.block == 7999 {
            self.file.as_ref().unwrap().read(&mut self.buf[..BUFFER_SIZE - 0x200])?;
            self.set_cur_file(self.cur_file + 1)?;
            self.file.as_ref().unwrap().read(&mut self.buf[BUFFER_SIZE - 0x200..])?;
            self.cur_block = 0;
        } else {
            self.file.as_ref().unwrap().read(&mut self.buf)?;
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
        Aes128Cbc::new(self.crypto.clone(), &iv.into()).decrypt(&mut self.buf)?;

        Result::Ok(())
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
            if read_size + block_offset > BUFFER_SIZE {
                read_size = BUFFER_SIZE - block_offset
            }
            buf[read..read + read_size]
                .copy_from_slice(&mut self.buf[block_offset..block_offset + read_size]);
            read += read_size;
            rem -= read_size;
            self.offset += read_size as u64;
            self.set_logical_addr(self.offset).map_err(|v| match v {
                Error::Io(_, v) => v,
                _ => io::Error::from(io::ErrorKind::Other),
            })?;
        }
        io::Result::Ok(read)
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
        io::Result::Ok(self.offset)
    }

    fn stream_position(&mut self) -> io::Result<u64> { io::Result::Ok(self.offset) }
}

impl<'a> ReadStream for NFSReadStream<'a> {
    fn stable_stream_len(&mut self) -> io::Result<u64> { todo!() }

    fn as_dyn(&mut self) -> &mut dyn ReadStream { self }
}

impl DiscIO for DiscIONFS {
    fn begin_read_stream(&mut self, offset: u64) -> io::Result<Box<dyn ReadStream + '_>> {
        io::Result::Ok(Box::from(NFSReadStream {
            disc_io: self,
            file: Option::None,
            crypto: Aes128::new(&self.key.into()),
            phys_addr: FBO::default(),
            offset,
            cur_file: u32::MAX,
            cur_block: u32::MAX,
            buf: [0; BUFFER_SIZE],
        }))
    }

    fn has_wii_crypto(&self) -> bool { false }
}

impl DiscIONFS {
    fn get_path<P: AsRef<Path>>(&self, path: P) -> PathBuf {
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
            Result::Ok(path)
        } else {
            Result::Err(Error::DiscFormat(format!("Failed to locate {}", path.to_string_lossy())))
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
                return Result::Err(Error::DiscFormat(format!(
                    "Failed to locate {} or {}",
                    primary_key_path.to_string_lossy(),
                    secondary_key_path.to_string_lossy()
                )));
            }
            let resolved_path = key_path.unwrap();
            File::open(resolved_path.as_path())
                .map_err(|v| {
                    Error::Io(format!("Failed to open {}", resolved_path.to_string_lossy()), v)
                })?
                .read(&mut self.key)
                .map_err(|v| {
                    Error::Io(format!("Failed to read {}", resolved_path.to_string_lossy()), v)
                })?;
        }
        {
            // Load header from first file
            let header: NFSHeader = File::open(self.get_nfs(0)?)?.read_be()?;
            // Ensure remaining files exist
            for i in 1..header.calculate_num_files() {
                self.get_nfs(i)?;
            }
            self.header = Option::from(header)
        }
        Result::Ok(())
    }
}
