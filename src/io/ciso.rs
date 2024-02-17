use std::{
    cmp::min,
    io,
    io::{BufReader, Read, Seek, SeekFrom},
    mem::size_of,
    path::Path,
};

use zerocopy::{little_endian::*, AsBytes, FromBytes, FromZeroes};

use crate::{
    disc::{gcn::DiscGCN, wii::DiscWii, DiscBase, DL_DVD_SIZE, SECTOR_SIZE},
    io::{nkit::NKitHeader, split::SplitFileReader, DiscIO, MagicBytes},
    static_assert,
    util::{
        lfg::LaggedFibonacci,
        reader::{read_box_slice, read_from},
    },
    DiscHeader, DiscMeta, Error, PartitionInfo, ReadStream, Result, ResultContext,
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
    junk_blocks: Option<Box<[u8]>>,
    partitions: Vec<PartitionInfo>,
    disc_num: u8,
}

impl DiscIOCISO {
    pub fn new(filename: &Path) -> Result<Self> {
        let mut inner = BufReader::new(SplitFileReader::new(filename)?);

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
        if file_size > inner.get_ref().len() {
            return Err(Error::DiscFormat(format!(
                "CISO file size mismatch: expected at least {} bytes, got {}",
                file_size,
                inner.get_ref().len()
            )));
        }

        // Read NKit header if present (after CISO data)
        let nkit_header = if inner.get_ref().len() > file_size + 4 {
            inner.seek(SeekFrom::Start(file_size)).context("Seeking to NKit header")?;
            NKitHeader::try_read_from(&mut inner)
        } else {
            None
        };

        // Read junk data bitstream if present (after NKit header)
        let junk_blocks = if nkit_header.is_some() {
            let n = 1 + DL_DVD_SIZE / header.block_size.get() as u64 / 8;
            Some(read_box_slice(&mut inner, n as usize).context("Reading NKit bitstream")?)
        } else {
            None
        };

        let (partitions, disc_num) = if junk_blocks.is_some() {
            let mut stream: Box<dyn ReadStream> = Box::new(CISOReadStream {
                inner: BufReader::new(inner.get_ref().clone()),
                block_size: header.block_size.get(),
                block_map,
                cur_block: u16::MAX,
                pos: 0,
                junk_blocks: None,
                partitions: vec![],
                disc_num: 0,
            });
            let header: DiscHeader = read_from(stream.as_mut()).context("Reading disc header")?;
            let disc_num = header.disc_num;
            let disc_base: Box<dyn DiscBase> = if header.is_wii() {
                Box::new(DiscWii::new(stream.as_mut(), header, None)?)
            } else if header.is_gamecube() {
                Box::new(DiscGCN::new(stream.as_mut(), header, None)?)
            } else {
                return Err(Error::DiscFormat(format!(
                    "Invalid GC/Wii magic: {:#010X}/{:#010X}",
                    header.gcn_magic.get(),
                    header.wii_magic.get()
                )));
            };
            (disc_base.partitions(), disc_num)
        } else {
            (vec![], 0)
        };

        // Reset reader
        let mut inner = inner.into_inner();
        inner.reset();
        Ok(Self { inner, header, block_map, nkit_header, junk_blocks, partitions, disc_num })
    }
}

impl DiscIO for DiscIOCISO {
    fn open(&self) -> Result<Box<dyn ReadStream>> {
        Ok(Box::new(CISOReadStream {
            inner: BufReader::new(self.inner.clone()),
            block_size: self.header.block_size.get(),
            block_map: self.block_map,
            cur_block: u16::MAX,
            pos: 0,
            junk_blocks: self.junk_blocks.clone(),
            partitions: self.partitions.clone(),
            disc_num: self.disc_num,
        }))
    }

    fn meta(&self) -> Result<DiscMeta> {
        Ok(self.nkit_header.as_ref().map(DiscMeta::from).unwrap_or_default())
    }

    fn disc_size(&self) -> Option<u64> { self.nkit_header.as_ref().and_then(|h| h.size) }
}

struct CISOReadStream {
    inner: BufReader<SplitFileReader>,
    block_size: u32,
    block_map: [u16; CISO_MAP_SIZE],
    cur_block: u16,
    pos: u64,

    // Data for recreating junk data
    junk_blocks: Option<Box<[u8]>>,
    partitions: Vec<PartitionInfo>,
    disc_num: u8,
}

impl CISOReadStream {
    fn read_junk_data(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(junk_blocks) = self.junk_blocks.as_deref() else {
            return Ok(0);
        };
        let block_size = self.block_size as u64;
        let block = (self.pos / block_size) as u16;
        if junk_blocks[(block / 8) as usize] & (1 << (7 - (block & 7))) == 0 {
            return Ok(0);
        }
        let Some(partition) = self.partitions.iter().find(|p| {
            let start = p.part_offset + p.data_offset;
            start <= self.pos && self.pos < start + p.data_size
        }) else {
            log::warn!("No partition found for junk data at offset {:#x}", self.pos);
            return Ok(0);
        };
        let offset = self.pos - (partition.part_offset + partition.data_offset);
        let to_read = min(
            buf.len(),
            // The LFG is only valid for a single sector
            SECTOR_SIZE - (offset % SECTOR_SIZE as u64) as usize,
        );
        let mut lfg = LaggedFibonacci::default();
        lfg.init_with_seed(partition.lfg_seed, self.disc_num, offset);
        lfg.fill(&mut buf[..to_read]);
        self.pos += to_read as u64;
        Ok(to_read)
    }
}

impl Read for CISOReadStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let block_size = self.block_size as u64;
        let block = (self.pos / block_size) as u16;
        let block_offset = self.pos & (block_size - 1);
        if block != self.cur_block {
            if block >= CISO_MAP_SIZE as u16 {
                return Ok(0);
            }

            // Find the block in the map
            let phys_block = self.block_map[block as usize];
            if phys_block == u16::MAX {
                // Try to recreate junk data
                let read = self.read_junk_data(buf)?;
                if read > 0 {
                    return Ok(read);
                }

                // Otherwise, read zeroes
                let to_read = min(buf.len(), (block_size - block_offset) as usize);
                buf[..to_read].fill(0);
                self.pos += to_read as u64;
                return Ok(to_read);
            }

            // Seek to the new block
            let file_offset =
                size_of::<CISOHeader>() as u64 + phys_block as u64 * block_size + block_offset;
            self.inner.seek(SeekFrom::Start(file_offset))?;
            self.cur_block = block;
        }

        let to_read = min(buf.len(), (block_size - block_offset) as usize);
        let read = self.inner.read(&mut buf[..to_read])?;
        self.pos += read as u64;
        Ok(read)
    }
}

impl Seek for CISOReadStream {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "CISOReadStream: SeekFrom::End is not supported",
                ));
            }
            SeekFrom::Current(v) => self.pos.saturating_add_signed(v),
        };

        let block_size = self.block_size as u64;
        let new_block = (self.pos / block_size) as u16;
        if new_block == self.cur_block {
            // Seek within the same block
            self.inner.seek(SeekFrom::Current(new_pos as i64 - self.pos as i64))?;
        } else {
            // Seek to a different block, handled by next read
            self.cur_block = u16::MAX;
        }

        self.pos = new_pos;
        Ok(new_pos)
    }
}

impl ReadStream for CISOReadStream {
    fn stable_stream_len(&mut self) -> io::Result<u64> {
        Ok(self.block_size as u64 * CISO_MAP_SIZE as u64)
    }

    fn as_dyn(&mut self) -> &mut dyn ReadStream { self }
}
