use std::{
    io,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use crate::{
    disc::SECTOR_SIZE,
    io::{
        block::{Block, BlockIO, PartitionInfo},
        split::SplitFileReader,
        Format,
    },
    DiscMeta, Result,
};

#[derive(Clone)]
pub struct DiscIOISO {
    inner: SplitFileReader,
}

impl DiscIOISO {
    pub fn new(filename: &Path) -> Result<Box<Self>> {
        let inner = SplitFileReader::new(filename)?;
        Ok(Box::new(Self { inner }))
    }
}

impl BlockIO for DiscIOISO {
    fn read_block_internal(
        &mut self,
        out: &mut [u8],
        block: u32,
        _partition: Option<&PartitionInfo>,
    ) -> io::Result<Block> {
        let offset = block as u64 * SECTOR_SIZE as u64;
        let total_size = self.inner.len();
        if offset >= total_size {
            // End of file
            return Ok(Block::Zero);
        }

        self.inner.seek(SeekFrom::Start(offset))?;
        if offset + SECTOR_SIZE as u64 > total_size {
            // If the last block is not a full sector, fill the rest with zeroes
            let read = (total_size - offset) as usize;
            self.inner.read_exact(&mut out[..read])?;
            out[read..].fill(0);
        } else {
            self.inner.read_exact(out)?;
        }
        Ok(Block::Raw)
    }

    fn block_size_internal(&self) -> u32 { SECTOR_SIZE as u32 }

    fn meta(&self) -> DiscMeta {
        DiscMeta {
            format: Format::Iso,
            lossless: true,
            disc_size: Some(self.inner.len()),
            ..Default::default()
        }
    }
}
