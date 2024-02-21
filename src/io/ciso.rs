use std::{
    io,
    io::{Read, Seek, SeekFrom},
    mem::size_of,
    path::Path,
};

use zerocopy::{little_endian::*, AsBytes, FromBytes, FromZeroes};

use crate::{
    disc::SECTOR_SIZE,
    io::{
        block::{BPartitionInfo, Block, BlockIO},
        nkit::NKitHeader,
        split::SplitFileReader,
        MagicBytes,
    },
    static_assert,
    util::read::read_from,
    DiscMeta, Error, Result, ResultContext,
};

pub const CISO_MAGIC: MagicBytes = *b"CISO";
pub const CISO_MAP_SIZE: usize = SECTOR_SIZE - 8;

#[derive(Clone, Debug, PartialEq, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
struct CISOHeader {
    magic: MagicBytes,
    // little endian
    block_size: U32,
    block_present: [u8; CISO_MAP_SIZE],
}

static_assert!(size_of::<CISOHeader>() == SECTOR_SIZE);

pub struct DiscIOCISO {
    inner: SplitFileReader,
    header: CISOHeader,
    block_map: [u16; CISO_MAP_SIZE],
    nkit_header: Option<NKitHeader>,
}

impl Clone for DiscIOCISO {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            header: self.header.clone(),
            block_map: self.block_map,
            nkit_header: self.nkit_header.clone(),
        }
    }
}

impl DiscIOCISO {
    pub fn new(filename: &Path) -> Result<Box<Self>> {
        let mut inner = SplitFileReader::new(filename)?;

        // Read header
        let header: CISOHeader = read_from(&mut inner).context("Reading CISO header")?;
        if header.magic != CISO_MAGIC {
            return Err(Error::DiscFormat("Invalid CISO magic".to_string()));
        }

        // Build block map
        let mut block_map = [0u16; CISO_MAP_SIZE];
        let mut block = 0u16;
        for (presence, out) in header.block_present.iter().zip(block_map.iter_mut()) {
            if *presence == 1 {
                *out = block;
                block += 1;
            } else {
                *out = u16::MAX;
            }
        }
        let file_size = SECTOR_SIZE as u64 + block as u64 * header.block_size.get() as u64;
        if file_size > inner.len() {
            return Err(Error::DiscFormat(format!(
                "CISO file size mismatch: expected at least {} bytes, got {}",
                file_size,
                inner.len()
            )));
        }

        // Read NKit header if present (after CISO data)
        let nkit_header = if inner.len() > file_size + 4 {
            inner.seek(SeekFrom::Start(file_size)).context("Seeking to NKit header")?;
            NKitHeader::try_read_from(&mut inner, header.block_size.get(), true)
        } else {
            None
        };

        // Reset reader
        inner.reset();
        Ok(Box::new(Self { inner, header, block_map, nkit_header }))
    }
}

impl BlockIO for DiscIOCISO {
    fn read_block(
        &mut self,
        out: &mut [u8],
        block: u32,
        _partition: Option<&BPartitionInfo>,
    ) -> io::Result<Option<Block>> {
        if block >= CISO_MAP_SIZE as u32 {
            // Out of bounds
            return Ok(None);
        }

        // Find the block in the map
        let phys_block = self.block_map[block as usize];
        if phys_block == u16::MAX {
            // Check if block is junk data
            if self.nkit_header.as_ref().is_some_and(|h| h.is_junk_block(block).unwrap_or(false)) {
                return Ok(Some(Block::Junk));
            };

            // Otherwise, read zeroes
            return Ok(Some(Block::Zero));
        }

        // Read block
        let file_offset = size_of::<CISOHeader>() as u64
            + phys_block as u64 * self.header.block_size.get() as u64;
        self.inner.seek(SeekFrom::Start(file_offset))?;
        self.inner.read_exact(out)?;
        Ok(Some(Block::Raw))
    }

    fn block_size(&self) -> u32 { self.header.block_size.get() }

    fn meta(&self) -> Result<DiscMeta> {
        Ok(self.nkit_header.as_ref().map(DiscMeta::from).unwrap_or_default())
    }
}
