use std::{
    io,
    io::{Read, Seek, SeekFrom},
    mem::size_of,
    path::Path,
};

use zerocopy::{big_endian::*, AsBytes, FromBytes, FromZeroes};

use crate::{
    io::{
        block::{Block, BlockIO, PartitionInfo},
        nkit::NKitHeader,
        split::SplitFileReader,
        DiscMeta, Format, MagicBytes,
    },
    util::read::{read_box_slice, read_from},
    Error, Result, ResultContext,
};

pub const WBFS_MAGIC: MagicBytes = *b"WBFS";

#[derive(Debug, Clone, PartialEq, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
struct WBFSHeader {
    magic: MagicBytes,
    num_sectors: U32,
    sector_size_shift: u8,
    block_size_shift: u8,
    _pad: [u8; 2],
}

impl WBFSHeader {
    fn sector_size(&self) -> u32 { 1 << self.sector_size_shift }

    fn block_size(&self) -> u32 { 1 << self.block_size_shift }

    // fn align_lba(&self, x: u32) -> u32 { (x + self.sector_size() - 1) & !(self.sector_size() - 1) }
    //
    // fn num_wii_sectors(&self) -> u32 {
    //     (self.num_sectors.get() / SECTOR_SIZE as u32) * self.sector_size()
    // }
    //
    // fn max_wii_sectors(&self) -> u32 { NUM_WII_SECTORS }
    //
    // fn num_wbfs_sectors(&self) -> u32 {
    //     self.num_wii_sectors() >> (self.wbfs_sector_size_shift - 15)
    // }

    fn max_blocks(&self) -> u32 { NUM_WII_SECTORS >> (self.block_size_shift - 15) }
}

const DISC_HEADER_SIZE: usize = 0x100;
const NUM_WII_SECTORS: u32 = 143432 * 2; // Double layer discs

#[derive(Clone)]
pub struct DiscIOWBFS {
    inner: SplitFileReader,
    /// WBFS header
    header: WBFSHeader,
    /// Map of Wii LBAs to WBFS LBAs
    block_table: Box<[U16]>,
    /// Optional NKit header
    nkit_header: Option<NKitHeader>,
}

impl DiscIOWBFS {
    pub fn new(filename: &Path) -> Result<Box<Self>> {
        let mut inner = SplitFileReader::new(filename)?;

        let header: WBFSHeader = read_from(&mut inner).context("Reading WBFS header")?;
        if header.magic != WBFS_MAGIC {
            return Err(Error::DiscFormat("Invalid WBFS magic".to_string()));
        }
        let file_len = inner.len();
        let expected_file_len = header.num_sectors.get() as u64 * header.sector_size() as u64;
        if file_len != expected_file_len {
            return Err(Error::DiscFormat(format!(
                "Invalid WBFS file size: {}, expected {}",
                file_len, expected_file_len
            )));
        }

        let disc_table: Box<[u8]> =
            read_box_slice(&mut inner, header.sector_size() as usize - size_of::<WBFSHeader>())
                .context("Reading WBFS disc table")?;
        if disc_table[0] != 1 {
            return Err(Error::DiscFormat("WBFS doesn't contain a disc".to_string()));
        }
        if disc_table[1../*max_disc as usize*/].iter().any(|&x| x != 0) {
            return Err(Error::DiscFormat("Only single WBFS discs are supported".to_string()));
        }

        // Read WBFS LBA table
        inner
            .seek(SeekFrom::Start(header.sector_size() as u64 + DISC_HEADER_SIZE as u64))
            .context("Seeking to WBFS LBA table")?; // Skip header
        let block_table: Box<[U16]> = read_box_slice(&mut inner, header.max_blocks() as usize)
            .context("Reading WBFS LBA table")?;

        // Read NKit header if present (always at 0x10000)
        inner.seek(SeekFrom::Start(0x10000)).context("Seeking to NKit header")?;
        let nkit_header = NKitHeader::try_read_from(&mut inner, header.block_size(), true);

        // Reset reader
        inner.reset();
        Ok(Box::new(Self { inner, header, block_table, nkit_header }))
    }
}

impl BlockIO for DiscIOWBFS {
    fn read_block(
        &mut self,
        out: &mut [u8],
        block: u32,
        _partition: Option<&PartitionInfo>,
    ) -> io::Result<Option<Block>> {
        let block_size = self.header.block_size();
        if block >= self.header.max_blocks() {
            return Ok(None);
        }

        // Check if block is junk data
        if self.nkit_header.as_ref().is_some_and(|h| h.is_junk_block(block).unwrap_or(false)) {
            return Ok(Some(Block::Junk));
        }

        // Read block
        let block_start = block_size as u64 * self.block_table[block as usize].get() as u64;
        self.inner.seek(SeekFrom::Start(block_start))?;
        self.inner.read_exact(out)?;
        Ok(Some(Block::Raw))
    }

    fn block_size(&self) -> u32 { self.header.block_size() }

    fn meta(&self) -> DiscMeta {
        let mut result = DiscMeta {
            format: Format::Wbfs,
            block_size: Some(self.header.block_size()),
            ..Default::default()
        };
        if let Some(nkit_header) = &self.nkit_header {
            nkit_header.apply(&mut result);
        }
        result
    }
}
