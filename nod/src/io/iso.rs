use std::{
    io,
    io::{Read, Seek},
    path::Path,
};

use crate::{
    disc::SECTOR_SIZE,
    io::{
        block::{Block, BlockIO, PartitionInfo},
        split::SplitFileReader,
        Format,
    },
    DiscMeta, Error, Result,
};

#[derive(Clone)]
pub struct DiscIOISO {
    inner: SplitFileReader,
}

impl DiscIOISO {
    pub fn new(filename: &Path) -> Result<Box<Self>> {
        let inner = SplitFileReader::new(filename)?;
        if inner.len() % SECTOR_SIZE as u64 != 0 {
            return Err(Error::DiscFormat(
                "ISO size is not a multiple of sector size (0x8000 bytes)".to_string(),
            ));
        }
        Ok(Box::new(Self { inner }))
    }
}

impl BlockIO for DiscIOISO {
    fn read_block(
        &mut self,
        out: &mut [u8],
        block: u32,
        _partition: Option<&PartitionInfo>,
    ) -> io::Result<Option<Block>> {
        let offset = block as u64 * SECTOR_SIZE as u64;
        if offset >= self.inner.len() {
            // End of file
            return Ok(None);
        }

        self.inner.seek(io::SeekFrom::Start(offset))?;
        self.inner.read_exact(out)?;
        Ok(Some(Block::Raw))
    }

    fn block_size(&self) -> u32 { SECTOR_SIZE as u32 }

    fn meta(&self) -> DiscMeta {
        DiscMeta {
            format: Format::Iso,
            lossless: true,
            disc_size: Some(self.inner.len()),
            ..Default::default()
        }
    }
}
