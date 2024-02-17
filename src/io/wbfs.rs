use std::{
    cmp::min,
    io,
    io::{BufReader, Read, Seek, SeekFrom},
    mem::size_of,
    path::Path,
};

use zerocopy::{big_endian::*, AsBytes, FromBytes, FromZeroes};

use crate::{
    disc::SECTOR_SIZE,
    io::{nkit::NKitHeader, split::SplitFileReader, DiscIO, DiscMeta, MagicBytes},
    util::reader::{read_from, read_vec},
    Error, ReadStream, Result, ResultContext,
};

pub const WBFS_MAGIC: MagicBytes = *b"WBFS";

#[derive(Debug, Clone, PartialEq, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
struct WBFSHeader {
    magic: MagicBytes,
    num_sectors: U32,
    sector_size_shift: u8,
    wbfs_sector_size_shift: u8,
    _pad: [u8; 2],
}

impl WBFSHeader {
    fn sector_size(&self) -> u32 { 1 << self.sector_size_shift }

    fn wbfs_sector_size(&self) -> u32 { 1 << self.wbfs_sector_size_shift }

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

    fn max_wbfs_sectors(&self) -> u32 { NUM_WII_SECTORS >> (self.wbfs_sector_size_shift - 15) }
}

const DISC_HEADER_SIZE: usize = 0x100;
const NUM_WII_SECTORS: u32 = 143432 * 2; // Double layer discs

pub struct DiscIOWBFS {
    pub inner: SplitFileReader,
    /// WBFS header
    header: WBFSHeader,
    /// Map of Wii LBAs to WBFS LBAs
    wlba_table: Vec<U16>,
    /// Optional NKit header
    nkit_header: Option<NKitHeader>,
}

impl DiscIOWBFS {
    pub fn new(filename: &Path) -> Result<Self> {
        let mut inner = BufReader::new(SplitFileReader::new(filename)?);

        let header: WBFSHeader = read_from(&mut inner).context("Reading WBFS header")?;
        if header.magic != WBFS_MAGIC {
            return Err(Error::DiscFormat("Invalid WBFS magic".to_string()));
        }
        // log::debug!("{:?}", header);
        // log::debug!("sector_size: {}", header.sector_size());
        // log::debug!("wbfs_sector_size: {}", header.wbfs_sector_size());
        let file_len = inner.stable_stream_len().context("Getting WBFS file size")?;
        let expected_file_len = header.num_sectors.get() as u64 * header.sector_size() as u64;
        if file_len != expected_file_len {
            return Err(Error::DiscFormat(format!(
                "Invalid WBFS file size: {}, expected {}",
                file_len, expected_file_len
            )));
        }

        let disc_table: Vec<u8> =
            read_vec(&mut inner, header.sector_size() as usize - size_of::<WBFSHeader>())
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
        let wlba_table: Vec<U16> = read_vec(&mut inner, header.max_wbfs_sectors() as usize)
            .context("Reading WBFS LBA table")?;

        // Read NKit header if present (always at 0x10000)
        inner.seek(SeekFrom::Start(0x10000)).context("Seeking to NKit header")?;
        let nkit_header = NKitHeader::try_read_from(&mut inner);

        // Reset reader
        let mut inner = inner.into_inner();
        inner.reset();
        Ok(Self { inner, header, wlba_table, nkit_header })
    }
}

impl DiscIO for DiscIOWBFS {
    fn open(&self) -> Result<Box<dyn ReadStream>> {
        Ok(Box::new(WBFSReadStream {
            inner: BufReader::new(self.inner.clone()),
            header: self.header.clone(),
            wlba_table: self.wlba_table.clone(),
            wlba: u32::MAX,
            pos: 0,
            disc_size: self.nkit_header.as_ref().and_then(|h| h.size),
        }))
    }

    fn meta(&self) -> Result<DiscMeta> {
        Ok(self.nkit_header.as_ref().map(DiscMeta::from).unwrap_or_default())
    }

    fn disc_size(&self) -> Option<u64> { self.nkit_header.as_ref().and_then(|h| h.size) }
}

struct WBFSReadStream {
    /// File reader
    inner: BufReader<SplitFileReader>,
    /// WBFS header
    header: WBFSHeader,
    /// Map of Wii LBAs to WBFS LBAs
    wlba_table: Vec<U16>,
    /// Current WBFS LBA
    wlba: u32,
    /// Current stream offset
    pos: u64,
    /// Optional known size
    disc_size: Option<u64>,
}

impl WBFSReadStream {
    fn disc_size(&self) -> u64 {
        self.disc_size.unwrap_or(NUM_WII_SECTORS as u64 * SECTOR_SIZE as u64)
    }
}

impl Read for WBFSReadStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let wlba = (self.pos >> self.header.wbfs_sector_size_shift) as u32;
        let wlba_size = self.header.wbfs_sector_size() as u64;
        let wlba_offset = self.pos & (wlba_size - 1);
        if wlba != self.wlba {
            if self.pos >= self.disc_size() || wlba >= self.header.max_wbfs_sectors() {
                return Ok(0);
            }
            let wlba_start = wlba_size * self.wlba_table[wlba as usize].get() as u64;
            self.inner.seek(SeekFrom::Start(wlba_start + wlba_offset))?;
            self.wlba = wlba;
        }

        let to_read = min(buf.len(), (wlba_size - wlba_offset) as usize);
        let read = self.inner.read(&mut buf[..to_read])?;
        self.pos += read as u64;
        Ok(read)
    }
}

impl Seek for WBFSReadStream {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "WBFSReadStream: SeekFrom::End is not supported",
                ));
            }
            SeekFrom::Current(v) => self.pos.saturating_add_signed(v),
        };

        let new_wlba = (self.pos >> self.header.wbfs_sector_size_shift) as u32;
        if new_wlba == self.wlba {
            // Seek within the same WBFS LBA
            self.inner.seek(SeekFrom::Current(new_pos as i64 - self.pos as i64))?;
        } else {
            // Seek to a different WBFS LBA, handled by next read
            self.wlba = u32::MAX;
        }

        self.pos = new_pos;
        Ok(new_pos)
    }
}

impl ReadStream for WBFSReadStream {
    fn stable_stream_len(&mut self) -> io::Result<u64> { Ok(self.disc_size()) }

    fn as_dyn(&mut self) -> &mut dyn ReadStream { self }
}
