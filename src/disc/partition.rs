use std::{
    cmp::min,
    io,
    io::{Read, Seek, SeekFrom},
};

use sha1::{Digest, Sha1};
use zerocopy::FromZeroes;

use crate::{
    array_ref,
    disc::wii::{as_digest, HASHES_SIZE, SECTOR_DATA_SIZE},
    io::block::{BPartitionInfo, Block, BlockIO},
    util::div_rem,
    Result, SECTOR_SIZE,
};

pub struct PartitionReader {
    io: Box<dyn BlockIO>,
    partition: BPartitionInfo,
    block: Option<Block>,
    block_buf: Box<[u8]>,
    block_idx: u32,
    sector_buf: Box<[u8; SECTOR_SIZE]>,
    sector: u32,
    pos: u64,
    verify: bool,
}

impl Clone for PartitionReader {
    fn clone(&self) -> Self {
        Self {
            io: self.io.clone(),
            partition: self.partition.clone(),
            block: None,
            block_buf: <u8>::new_box_slice_zeroed(self.block_buf.len()),
            block_idx: u32::MAX,
            sector_buf: <[u8; SECTOR_SIZE]>::new_box_zeroed(),
            sector: u32::MAX,
            pos: 0,
            verify: self.verify,
        }
    }
}

impl PartitionReader {
    pub fn new(inner: Box<dyn BlockIO>, partition: &BPartitionInfo) -> Result<Self> {
        let block_size = inner.block_size();
        Ok(Self {
            io: inner,
            partition: partition.clone(),
            block: None,
            block_buf: <u8>::new_box_slice_zeroed(block_size as usize),
            block_idx: u32::MAX,
            sector_buf: <[u8; SECTOR_SIZE]>::new_box_zeroed(),
            sector: u32::MAX,
            pos: 0,
            verify: false,
        })
    }
}

impl Read for PartitionReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let partition_sector = (self.pos / SECTOR_DATA_SIZE as u64) as u32;
        let sector = self.partition.data_start_sector + partition_sector;
        if sector >= self.partition.data_end_sector {
            return Ok(0);
        }
        let block_idx = (sector as u64 * SECTOR_SIZE as u64 / self.block_buf.len() as u64) as u32;

        // Read new block if necessary
        if block_idx != self.block_idx {
            self.block =
                self.io.read_block(self.block_buf.as_mut(), block_idx, Some(&self.partition))?;
            self.block_idx = block_idx;
        }

        // Decrypt sector if necessary
        if sector != self.sector {
            let Some(block) = &self.block else {
                return Ok(0);
            };
            block.decrypt(
                &mut self.sector_buf,
                self.block_buf.as_ref(),
                block_idx,
                sector,
                &self.partition,
            )?;

            if self.verify {
                verify_hashes(&self.sector_buf, sector)?;
            }

            self.sector = sector;
        }

        let offset = (self.pos % SECTOR_DATA_SIZE as u64) as usize;
        let len = min(buf.len(), SECTOR_DATA_SIZE - offset);
        buf[..len]
            .copy_from_slice(&self.sector_buf[HASHES_SIZE + offset..HASHES_SIZE + offset + len]);
        self.pos += len as u64;
        Ok(len)
    }
}

impl Seek for PartitionReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "PartitionReader: SeekFrom::End is not supported".to_string(),
                ));
            }
            SeekFrom::Current(v) => self.pos.saturating_add_signed(v),
        };
        Ok(self.pos)
    }
}

fn verify_hashes(buf: &[u8; SECTOR_SIZE], sector: u32) -> io::Result<()> {
    let (mut group, sub_group) = div_rem(sector as usize, 8);
    group %= 8;

    // H0 hashes
    for i in 0..31 {
        let mut hash = Sha1::new();
        hash.update(array_ref![buf, (i + 1) * 0x400, 0x400]);
        let expected = as_digest(array_ref![buf, i * 20, 20]);
        let output = hash.finalize();
        if output != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid H0 hash! (block {:?}) {:x}\n\texpected {:x}", i, output, expected),
            ));
        }
    }

    // H1 hash
    {
        let mut hash = Sha1::new();
        hash.update(array_ref![buf, 0, 0x26C]);
        let expected = as_digest(array_ref![buf, 0x280 + sub_group * 20, 20]);
        let output = hash.finalize();
        if output != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid H1 hash! (subgroup {:?}) {:x}\n\texpected {:x}",
                    sub_group, output, expected
                ),
            ));
        }
    }

    // H2 hash
    {
        let mut hash = Sha1::new();
        hash.update(array_ref![buf, 0x280, 0xA0]);
        let expected = as_digest(array_ref![buf, 0x340 + group * 20, 20]);
        let output = hash.finalize();
        if output != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid H2 hash! (group {:?}) {:x}\n\texpected {:x}",
                    group, output, expected
                ),
            ));
        }
    }
    // TODO H3 hash
    Ok(())
}
