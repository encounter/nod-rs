use std::{
    io,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use zerocopy::{big_endian::U32, AsBytes, FromBytes, FromZeroes};

use crate::{
    disc::SECTOR_SIZE,
    io::{
        block::{Block, BlockIO, PartitionInfo},
        split::SplitFileReader,
        Format, MagicBytes,
    },
    util::read::{read_box_slice, read_from},
    DiscHeader, DiscMeta, Error, Node, PartitionHeader, Result, ResultContext,
};

pub const TGC_MAGIC: MagicBytes = [0xae, 0x0f, 0x38, 0xa2];

/// TGC header (big endian)
#[derive(Clone, Debug, PartialEq, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
struct TGCHeader {
    /// Magic bytes
    magic: MagicBytes,
    /// TGC version
    version: U32,
    /// Offset to the start of the GCM header
    header_offset: U32,
    /// Size of the GCM header
    header_size: U32,
    /// Offset to the FST
    fst_offset: U32,
    /// Size of the FST
    fst_size: U32,
    /// Maximum size of the FST across discs
    fst_max_size: U32,
    /// Offset to the DOL
    dol_offset: U32,
    /// Size of the DOL
    dol_size: U32,
    /// Offset to user data
    user_offset: U32,
    /// Size of user data
    user_size: U32,
    /// Offset to the banner
    banner_offset: U32,
    /// Size of the banner
    banner_size: U32,
    /// Original user data offset in the GCM
    gcm_user_offset: U32,
}

#[derive(Clone)]
pub struct DiscIOTGC {
    inner: SplitFileReader,
    header: TGCHeader,
    fst: Box<[u8]>,
}

impl DiscIOTGC {
    pub fn new(filename: &Path) -> Result<Box<Self>> {
        let mut inner = SplitFileReader::new(filename)?;

        // Read header
        let header: TGCHeader = read_from(&mut inner).context("Reading TGC header")?;
        if header.magic != TGC_MAGIC {
            return Err(Error::DiscFormat("Invalid TGC magic".to_string()));
        }
        if header.version.get() != 0 {
            return Err(Error::DiscFormat(format!(
                "Unsupported TGC version {}",
                header.version.get()
            )));
        }

        // Read FST and adjust offsets
        inner
            .seek(SeekFrom::Start(header.fst_offset.get() as u64))
            .context("Seeking to TGC FST")?;
        let mut fst = read_box_slice(&mut inner, header.fst_size.get() as usize)
            .context("Reading TGC FST")?;
        let root_node = Node::ref_from_prefix(&fst)
            .ok_or_else(|| Error::DiscFormat("Invalid TGC FST".to_string()))?;
        let node_count = root_node.length() as usize;
        let (nodes, _) = Node::mut_slice_from_prefix(&mut fst, node_count)
            .ok_or_else(|| Error::DiscFormat("Invalid TGC FST".to_string()))?;
        for node in nodes {
            if node.is_file() {
                node.offset = node.offset - header.gcm_user_offset
                    + (header.user_offset - header.header_offset);
            }
        }

        Ok(Box::new(Self { inner, header, fst }))
    }
}

impl BlockIO for DiscIOTGC {
    fn read_block_internal(
        &mut self,
        out: &mut [u8],
        block: u32,
        _partition: Option<&PartitionInfo>,
    ) -> io::Result<Block> {
        let offset = self.header.header_offset.get() as u64 + block as u64 * SECTOR_SIZE as u64;
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

        // Adjust internal GCM header
        if block == 0 {
            let partition_header = PartitionHeader::mut_from(
                &mut out[size_of::<DiscHeader>()
                    ..size_of::<DiscHeader>() + size_of::<PartitionHeader>()],
            )
            .unwrap();
            partition_header.dol_offset = self.header.dol_offset - self.header.header_offset;
            partition_header.fst_offset = self.header.fst_offset - self.header.header_offset;
        }

        // Copy modified FST to output
        if offset + out.len() as u64 > self.header.fst_offset.get() as u64
            && offset < self.header.fst_offset.get() as u64 + self.header.fst_size.get() as u64
        {
            let out_offset = (self.header.fst_offset.get() as u64).saturating_sub(offset) as usize;
            let fst_offset = offset.saturating_sub(self.header.fst_offset.get() as u64) as usize;
            let copy_len =
                (out.len() - out_offset).min(self.header.fst_size.get() as usize - fst_offset);
            out[out_offset..out_offset + copy_len]
                .copy_from_slice(&self.fst[fst_offset..fst_offset + copy_len]);
        }

        Ok(Block::Raw)
    }

    fn block_size_internal(&self) -> u32 { SECTOR_SIZE as u32 }

    fn meta(&self) -> DiscMeta {
        DiscMeta {
            format: Format::Tgc,
            lossless: true,
            disc_size: Some(self.inner.len() - self.header.header_offset.get() as u64),
            ..Default::default()
        }
    }
}
