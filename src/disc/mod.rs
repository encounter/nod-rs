//! Disc type related logic (GameCube, Wii)

use std::{
    borrow::Cow,
    ffi::CStr,
    fmt::{Debug, Display, Formatter},
    io,
    mem::size_of,
    str::from_utf8,
};

use zerocopy::{big_endian::*, AsBytes, FromBytes, FromZeroes};

use crate::{
    disc::{
        gcn::DiscGCN,
        wii::{DiscWii, Ticket, TmdHeader, WiiPartitionHeader},
    },
    fst::Node,
    io::DiscIO,
    static_assert,
    streams::{ReadStream, SharedWindowedReadStream},
    util::read::read_from,
    Error, Fst, OpenOptions, Result, ResultContext,
};

pub(crate) mod gcn;
pub(crate) mod hashes;
pub mod partition;
pub mod reader;
pub(crate) mod wii;

pub const SECTOR_SIZE: usize = 0x8000;

/// Shared GameCube & Wii disc header
#[derive(Clone, Debug, PartialEq, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub struct DiscHeader {
    /// Game ID (e.g. GM8E01 for Metroid Prime)
    pub game_id: [u8; 6],
    /// Used in multi-disc games
    pub disc_num: u8,
    /// Disc version
    pub disc_version: u8,
    /// Audio streaming enabled
    pub audio_streaming: u8,
    /// Audio streaming buffer size
    pub audio_stream_buf_size: u8,
    /// Padding
    _pad1: [u8; 14],
    /// If this is a Wii disc, this will be 0x5D1C9EA3
    pub wii_magic: U32,
    /// If this is a GameCube disc, this will be 0xC2339F3D
    pub gcn_magic: U32,
    /// Game title
    pub game_title: [u8; 64],
    /// If 1, disc omits partition hashes
    pub no_partition_hashes: u8,
    /// If 1, disc omits partition encryption
    pub no_partition_encryption: u8,
    /// Padding
    _pad2: [u8; 926],
}

static_assert!(size_of::<DiscHeader>() == 0x400);

impl DiscHeader {
    /// Game ID as a string.
    pub fn game_id_str(&self) -> &str { from_utf8(&self.game_id).unwrap_or("[invalid]") }

    /// Game title as a string.
    pub fn game_title_str(&self) -> &str {
        CStr::from_bytes_until_nul(&self.game_title)
            .ok()
            .and_then(|c| c.to_str().ok())
            .unwrap_or("[invalid]")
    }

    /// Whether this is a GameCube disc.
    pub fn is_gamecube(&self) -> bool { self.gcn_magic.get() == 0xC2339F3D }

    /// Whether this is a Wii disc.
    pub fn is_wii(&self) -> bool { self.wii_magic.get() == 0x5D1C9EA3 }
}

/// Partition header
#[derive(Clone, Debug, PartialEq, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub struct PartitionHeader {
    /// Debug monitor offset
    pub debug_mon_off: U32,
    /// Debug monitor load address
    pub debug_load_addr: U32,
    /// Padding
    _pad1: [u8; 0x18],
    /// Offset to main DOL (Wii: >> 2)
    pub dol_off: U32,
    /// Offset to file system table (Wii: >> 2)
    pub fst_off: U32,
    /// File system size (Wii: >> 2)
    pub fst_sz: U32,
    /// File system max size (Wii: >> 2)
    pub fst_max_sz: U32,
    /// File system table load address
    pub fst_memory_address: U32,
    /// User position
    pub user_position: U32,
    /// User size
    pub user_sz: U32,
    /// Padding
    _pad2: [u8; 4],
}

static_assert!(size_of::<PartitionHeader>() == 0x40);

impl PartitionHeader {
    pub fn dol_off(&self, is_wii: bool) -> u64 {
        if is_wii {
            self.dol_off.get() as u64 * 4
        } else {
            self.dol_off.get() as u64
        }
    }

    pub fn fst_off(&self, is_wii: bool) -> u64 {
        if is_wii {
            self.fst_off.get() as u64 * 4
        } else {
            self.fst_off.get() as u64
        }
    }

    pub fn fst_sz(&self, is_wii: bool) -> u64 {
        if is_wii {
            self.fst_sz.get() as u64 * 4
        } else {
            self.fst_sz.get() as u64
        }
    }

    pub fn fst_max_sz(&self, is_wii: bool) -> u64 {
        if is_wii {
            self.fst_max_sz.get() as u64 * 4
        } else {
            self.fst_max_sz.get() as u64
        }
    }
}

/// Apploader header
#[derive(Debug, PartialEq, Clone, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub struct AppLoaderHeader {
    /// Apploader build date
    pub date: [u8; 16],
    /// Entry point
    pub entry_point: U32,
    /// Apploader size
    pub size: U32,
    /// Apploader trailer size
    pub trailer_size: U32,
    /// Padding
    _pad: [u8; 4],
}

impl AppLoaderHeader {
    /// Apploader build date as a string
    pub fn date_str(&self) -> Option<&str> {
        CStr::from_bytes_until_nul(&self.date).ok().and_then(|c| c.to_str().ok())
    }
}

/// Maximum number of text sections in a DOL
pub const DOL_MAX_TEXT_SECTIONS: usize = 7;
/// Maximum number of data sections in a DOL
pub const DOL_MAX_DATA_SECTIONS: usize = 11;

/// DOL header
#[derive(Debug, Clone, FromBytes, FromZeroes)]
pub struct DolHeader {
    /// Text section offsets
    pub text_offs: [U32; DOL_MAX_TEXT_SECTIONS],
    /// Data section offsets
    pub data_offs: [U32; DOL_MAX_DATA_SECTIONS],
    /// Text section addresses
    pub text_addrs: [U32; DOL_MAX_TEXT_SECTIONS],
    /// Data section addresses
    pub data_addrs: [U32; DOL_MAX_DATA_SECTIONS],
    /// Text section sizes
    pub text_sizes: [U32; DOL_MAX_TEXT_SECTIONS],
    /// Data section sizes
    pub data_sizes: [U32; DOL_MAX_DATA_SECTIONS],
    /// BSS address
    pub bss_addr: U32,
    /// BSS size
    pub bss_size: U32,
    /// Entry point
    pub entry_point: U32,
    /// Padding
    _pad: [u8; 0x1C],
}

static_assert!(size_of::<DolHeader>() == 0x100);

/// Partition type
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PartitionKind {
    Data,
    Update,
    Channel,
    Other(u32),
}

impl Display for PartitionKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data => write!(f, "Data"),
            Self::Update => write!(f, "Update"),
            Self::Channel => write!(f, "Channel"),
            Self::Other(v) => {
                let bytes = v.to_be_bytes();
                write!(f, "Other ({:08X}, {})", v, String::from_utf8_lossy(&bytes))
            }
        }
    }
}

impl PartitionKind {
    /// Returns the directory name for the partition kind.
    pub fn dir_name(&self) -> Cow<str> {
        match self {
            Self::Data => Cow::Borrowed("DATA"),
            Self::Update => Cow::Borrowed("UPDATE"),
            Self::Channel => Cow::Borrowed("CHANNEL"),
            Self::Other(v) => {
                let bytes = v.to_be_bytes();
                Cow::Owned(format!("P-{}", String::from_utf8_lossy(&bytes)))
            }
        }
    }
}

impl From<u32> for PartitionKind {
    fn from(v: u32) -> Self {
        match v {
            0 => Self::Data,
            1 => Self::Update,
            2 => Self::Channel,
            v => Self::Other(v),
        }
    }
}

/// Information about a GameCube or Wii disc partition.
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    /// Partition group index
    pub group_index: u32,
    /// Partition index within the group
    pub part_index: u32,
    /// Partition offset within disc
    pub part_offset: u64,
    /// Partition kind
    pub kind: PartitionKind,
    /// Data offset within partition
    pub data_offset: u64,
    /// Data size
    pub data_size: u64,
    /// Raw Wii partition header
    pub header: Option<WiiPartitionHeader>,
    /// Lagged Fibonacci generator seed (for junk data)
    pub lfg_seed: [u8; 4],
    // /// Junk data start offset
    // pub junk_start: u64,
}

/// Contains a disc's header & partition information.
pub trait DiscBase: Send + Sync {
    /// Retrieves the disc's header.
    fn header(&self) -> &DiscHeader;

    /// A list of partitions on the disc.
    fn partitions(&self) -> Vec<PartitionInfo>;

    /// Opens a new, decrypted partition read stream for the specified partition index.
    ///
    /// `validate_hashes`: Validate Wii disc hashes while reading (slow!)
    fn open_partition<'a>(
        &self,
        disc_io: &'a dyn DiscIO,
        index: usize,
        options: &OpenOptions,
    ) -> Result<Box<dyn PartitionBase + 'a>>;

    /// Opens a new partition read stream for the first partition matching
    /// the specified type.
    ///
    /// `validate_hashes`: Validate Wii disc hashes while reading (slow!)
    fn open_partition_kind<'a>(
        &self,
        disc_io: &'a dyn DiscIO,
        part_type: PartitionKind,
        options: &OpenOptions,
    ) -> Result<Box<dyn PartitionBase + 'a>>;

    /// The disc's size in bytes, or an estimate if not stored by the format.
    fn disc_size(&self) -> u64;
}

/// Creates a new [`DiscBase`] instance.
pub fn new(disc_io: &mut dyn DiscIO) -> Result<Box<dyn DiscBase>> {
    let disc_size = disc_io.disc_size();
    let mut stream = disc_io.open()?;
    let header: DiscHeader = read_from(stream.as_mut()).context("Reading disc header")?;
    if header.is_wii() {
        Ok(Box::new(DiscWii::new(stream.as_mut(), header, disc_size)?))
    } else if header.is_gamecube() {
        Ok(Box::new(DiscGCN::new(stream.as_mut(), header, disc_size)?))
    } else {
        Err(Error::DiscFormat(format!(
            "Invalid GC/Wii magic: {:#010X}/{:#010X}",
            header.gcn_magic.get(),
            header.wii_magic.get()
        )))
    }
}

/// An open read stream for a disc partition.
pub trait PartitionBase: ReadStream {
    /// Reads the partition header and file system table.
    fn meta(&mut self) -> Result<Box<PartitionMeta>>;

    /// Seeks the read stream to the specified file system node
    /// and returns a windowed stream.
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```no_run
    /// use std::io::Read;
    ///
    /// use nod::{Disc, PartitionKind};
    ///
    /// fn main() -> nod::Result<()> {
    ///     let disc = Disc::new("path/to/file.iso")?;
    ///     let mut partition = disc.open_partition_kind(PartitionKind::Data)?;
    ///     let meta = partition.meta()?;
    ///     let fst = meta.fst()?;
    ///     if let Some((_, node)) = fst.find("/MP3/Worlds.txt") {
    ///         let mut s = String::new();
    ///         partition
    ///             .open_file(node)
    ///             .expect("Failed to open file stream")
    ///             .read_to_string(&mut s)
    ///             .expect("Failed to read file");
    ///         println!("{}", s);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    fn open_file(&mut self, node: &Node) -> io::Result<SharedWindowedReadStream>;

    /// The ideal size for buffered reads from this partition.
    /// GameCube discs have a data block size of 0x8000,
    /// whereas Wii discs have a data block size of 0x7c00.
    fn ideal_buffer_size(&self) -> usize;
}

/// Size of the disc header and partition header (boot.bin)
pub const BOOT_SIZE: usize = size_of::<DiscHeader>() + size_of::<PartitionHeader>();
/// Size of the debug and region information (bi2.bin)
pub const BI2_SIZE: usize = 0x2000;

/// Disc partition metadata
#[derive(Clone, Debug)]
pub struct PartitionMeta {
    /// Disc and partition header (boot.bin)
    pub raw_boot: Box<[u8; BOOT_SIZE]>,
    /// Debug and region information (bi2.bin)
    pub raw_bi2: Box<[u8; BI2_SIZE]>,
    /// Apploader (apploader.bin)
    pub raw_apploader: Box<[u8]>,
    /// File system table (fst.bin)
    pub raw_fst: Box<[u8]>,
    /// Main binary (main.dol)
    pub raw_dol: Box<[u8]>,
    /// Ticket (ticket.bin, Wii only)
    pub raw_ticket: Option<Box<[u8]>>,
    /// TMD (tmd.bin, Wii only)
    pub raw_tmd: Option<Box<[u8]>>,
    /// Certificate chain (cert.bin, Wii only)
    pub raw_cert_chain: Option<Box<[u8]>>,
    /// H3 hash table (h3.bin, Wii only)
    pub raw_h3_table: Option<Box<[u8]>>,
}

impl PartitionMeta {
    pub fn header(&self) -> &DiscHeader {
        DiscHeader::ref_from(&self.raw_boot[..size_of::<DiscHeader>()]).unwrap()
    }

    pub fn partition_header(&self) -> &PartitionHeader {
        PartitionHeader::ref_from(&self.raw_boot[size_of::<DiscHeader>()..]).unwrap()
    }

    pub fn apploader_header(&self) -> &AppLoaderHeader {
        AppLoaderHeader::ref_from_prefix(&self.raw_apploader).unwrap()
    }

    pub fn fst(&self) -> Result<Fst, &'static str> { Fst::new(&self.raw_fst) }

    pub fn dol_header(&self) -> &DolHeader { DolHeader::ref_from_prefix(&self.raw_dol).unwrap() }

    pub fn ticket(&self) -> Option<&Ticket> {
        self.raw_ticket.as_ref().and_then(|v| Ticket::ref_from(v))
    }

    pub fn tmd_header(&self) -> Option<&TmdHeader> {
        self.raw_tmd.as_ref().and_then(|v| TmdHeader::ref_from_prefix(v))
    }
}

pub const MINI_DVD_SIZE: u64 = 1_459_978_240;
pub const SL_DVD_SIZE: u64 = 4_699_979_776;
pub const DL_DVD_SIZE: u64 = 8_511_160_320;
