//! Disc type related logic (GameCube, Wii)

use std::{ffi::CStr, fmt::Debug, io, io::Read};

use crate::{
    disc::{gcn::DiscGCN, wii::DiscWii},
    fst::{Node, NodeType},
    io::DiscIO,
    streams::{ReadStream, SharedWindowedReadStream},
    util::reader::{skip_bytes, struct_size, FromReader},
    Error, Result, ResultContext,
};

pub(crate) mod gcn;
pub(crate) mod wii;

/// Shared GameCube & Wii disc header
#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    /// Game ID (e.g. GM8E01 for Metroid Prime)
    pub game_id: [u8; 6],
    /// Used in multi-disc games
    pub disc_num: u8,
    /// Disc version
    pub disc_version: u8,
    /// Audio streaming enabled (bool)
    pub audio_streaming: u8,
    /// Audio streaming buffer size
    pub audio_stream_buf_size: u8,
    /// If this is a Wii disc, this will be 0x5D1C9EA3
    pub wii_magic: u32,
    /// If this is a GameCube disc, this will be 0xC2339F3D
    pub gcn_magic: u32,
    /// Game title
    pub game_title: String,
    /// Disable hash verification
    pub disable_hash_verification: u8,
    /// Disable disc encryption and H3 hash table loading and verification
    pub disable_disc_enc: u8,
}

fn from_c_str(bytes: &[u8]) -> io::Result<String> {
    CStr::from_bytes_until_nul(bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .to_str()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        .map(|s| s.to_string())
}

impl FromReader for Header {
    type Args<'a> = ();

    const STATIC_SIZE: usize = 0x400;

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        let game_id = <[u8; 6]>::from_reader(reader)?;
        let disc_num = u8::from_reader(reader)?;
        let disc_version = u8::from_reader(reader)?;
        let audio_streaming = u8::from_reader(reader)?;
        let audio_stream_buf_size = u8::from_reader(reader)?;
        skip_bytes::<14, _>(reader)?; // padding
        let wii_magic = u32::from_reader(reader)?;
        let gcn_magic = u32::from_reader(reader)?;
        let game_title = from_c_str(&<[u8; 64]>::from_reader(reader)?)?;
        let disable_hash_verification = u8::from_reader(reader)?;
        let disable_disc_enc = u8::from_reader(reader)?;
        skip_bytes::<926, _>(reader)?; // padding
        Ok(Self {
            game_id,
            disc_num,
            disc_version,
            audio_streaming,
            audio_stream_buf_size,
            wii_magic,
            gcn_magic,
            game_title,
            disable_hash_verification,
            disable_disc_enc,
        })
    }
}

/// Partition header
#[derive(Clone, Debug, PartialEq)]
pub struct PartitionHeader {
    /// Debug monitor offset
    pub debug_mon_off: u32,
    /// Debug monitor load address
    pub debug_load_addr: u32,
    /// Offset to main DOL (Wii: >> 2)
    pub dol_off: u32,
    /// Offset to file system table (Wii: >> 2)
    pub fst_off: u32,
    /// File system size
    pub fst_sz: u32,
    /// File system max size
    pub fst_max_sz: u32,
    /// File system table load address
    pub fst_memory_address: u32,
    /// User position
    pub user_position: u32,
    /// User size
    pub user_sz: u32,
}

impl FromReader for PartitionHeader {
    type Args<'a> = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // debug_mon_off
        u32::STATIC_SIZE, // debug_load_addr
        0x18,             // padding
        u32::STATIC_SIZE, // dol_off
        u32::STATIC_SIZE, // fst_off
        u32::STATIC_SIZE, // fst_sz
        u32::STATIC_SIZE, // fst_max_sz
        u32::STATIC_SIZE, // fst_memory_address
        u32::STATIC_SIZE, // user_position
        u32::STATIC_SIZE, // user_sz
        4,                // padding
    ]);

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        let debug_mon_off = u32::from_reader(reader)?;
        let debug_load_addr = u32::from_reader(reader)?;
        skip_bytes::<0x18, _>(reader)?; // padding
        let dol_off = u32::from_reader(reader)?;
        let fst_off = u32::from_reader(reader)?;
        let fst_sz = u32::from_reader(reader)?;
        let fst_max_sz = u32::from_reader(reader)?;
        let fst_memory_address = u32::from_reader(reader)?;
        let user_position = u32::from_reader(reader)?;
        let user_sz = u32::from_reader(reader)?;
        skip_bytes::<4, _>(reader)?; // padding
        Ok(Self {
            debug_mon_off,
            debug_load_addr,
            dol_off,
            fst_off,
            fst_sz,
            fst_max_sz,
            fst_memory_address,
            user_position,
            user_sz,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct AppLoaderHeader {
    pub date: String,
    pub entry_point: u32,
    pub size: u32,
    pub trailer_size: u32,
}

impl FromReader for AppLoaderHeader {
    type Args<'a> = ();

    const STATIC_SIZE: usize = struct_size([
        16,               // date
        u32::STATIC_SIZE, // entry_point
        u32::STATIC_SIZE, // size
        u32::STATIC_SIZE, // trailer_size
        4,                // padding
    ]);

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        let date = from_c_str(&<[u8; 16]>::from_reader(reader)?)?;
        let entry_point = u32::from_reader(reader)?;
        let size = u32::from_reader(reader)?;
        let trailer_size = u32::from_reader(reader)?;
        skip_bytes::<4, _>(reader)?; // padding
        Ok(Self { date, entry_point, size, trailer_size })
    }
}

pub const DOL_MAX_TEXT_SECTIONS: usize = 7;
pub const DOL_MAX_DATA_SECTIONS: usize = 11;

#[derive(Debug, Clone)]
pub struct DolHeader {
    pub text_offs: [u32; DOL_MAX_TEXT_SECTIONS],
    pub data_offs: [u32; DOL_MAX_DATA_SECTIONS],
    pub text_addrs: [u32; DOL_MAX_TEXT_SECTIONS],
    pub data_addrs: [u32; DOL_MAX_DATA_SECTIONS],
    pub text_sizes: [u32; DOL_MAX_TEXT_SECTIONS],
    pub data_sizes: [u32; DOL_MAX_DATA_SECTIONS],
    pub bss_addr: u32,
    pub bss_size: u32,
    pub entry_point: u32,
}

impl FromReader for DolHeader {
    type Args<'a> = ();

    const STATIC_SIZE: usize = 0x100;

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        let result = Self {
            text_offs: <_>::from_reader(reader)?,
            data_offs: <_>::from_reader(reader)?,
            text_addrs: <_>::from_reader(reader)?,
            data_addrs: <_>::from_reader(reader)?,
            text_sizes: <_>::from_reader(reader)?,
            data_sizes: <_>::from_reader(reader)?,
            bss_addr: <_>::from_reader(reader)?,
            bss_size: <_>::from_reader(reader)?,
            entry_point: <_>::from_reader(reader)?,
        };
        skip_bytes::<0x1C, _>(reader)?; // padding
        Ok(result)
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PartitionType {
    Data,
    Update,
    Channel,
}

pub(crate) const SECTOR_SIZE: usize = 0x8000;

/// Contains a disc's header & partition information.
pub trait DiscBase: Send + Sync {
    /// Retrieves the disc's header.
    fn get_header(&self) -> &Header;

    /// Opens a new partition read stream for the first data partition.
    ///
    /// `validate_hashes`: Validate Wii disc hashes while reading (slow!)
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```no_run
    /// use nod::{
    ///     disc::new_disc_base,
    ///     io::{new_disc_io, DiscIOOptions},
    /// };
    ///
    /// # fn main() -> nod::Result<()> {
    /// let options = DiscIOOptions::default();
    /// let mut disc_io = new_disc_io("path/to/file.iso".as_ref(), &options)?;
    /// let disc_base = new_disc_base(disc_io.as_mut())?;
    /// let mut partition = disc_base.get_data_partition(disc_io.as_mut(), false)?;
    /// # Ok(())
    /// # }
    /// ```
    fn get_data_partition<'a>(
        &self,
        disc_io: &'a mut dyn DiscIO,
        validate_hashes: bool,
    ) -> Result<Box<dyn PartReadStream + 'a>>;

    /// Opens a new partition read stream for the first partition matching
    /// the specified type.
    ///
    /// `validate_hashes`: Validate Wii disc hashes while reading (slow!)
    fn get_partition<'a>(
        &self,
        disc_io: &'a mut dyn DiscIO,
        part_type: PartitionType,
        validate_hashes: bool,
    ) -> Result<Box<dyn PartReadStream + 'a>>;
}

/// Creates a new [`DiscBase`] instance.
///
/// # Examples
///
/// Basic usage:
/// ```no_run
/// use nod::{
///     disc::new_disc_base,
///     io::{new_disc_io, DiscIOOptions},
/// };
///
/// # fn main() -> nod::Result<()> {
/// let options = DiscIOOptions::default();
/// let mut disc_io = new_disc_io("path/to/file.iso".as_ref(), &options)?;
/// let disc_base = new_disc_base(disc_io.as_mut())?;
/// disc_base.get_header();
/// # Ok(())
/// # }
/// ```
pub fn new_disc_base(disc_io: &mut dyn DiscIO) -> Result<Box<dyn DiscBase>> {
    let mut stream = disc_io.begin_read_stream(0).context("Opening disc stream")?;
    let header_bytes =
        <[u8; Header::STATIC_SIZE]>::from_reader(&mut stream).context("Reading disc header")?;
    let header =
        Header::from_reader(&mut header_bytes.as_slice()).context("Parsing disc header")?;
    if header.wii_magic == 0x5D1C9EA3 {
        Ok(Box::from(DiscWii::new(stream.as_mut(), header)?))
    } else if header.gcn_magic == 0xC2339F3D {
        Ok(Box::from(DiscGCN::new(header)?))
    } else {
        Err(Error::DiscFormat(format!("Invalid GC/Wii magic: {:#010X}", header.wii_magic)))
    }
}

/// An open read stream for a disc partition.
pub trait PartReadStream: ReadStream {
    /// Seeks the read stream to the specified file system node
    /// and returns a windowed stream.
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```no_run
    /// use std::io::Read;
    ///
    /// use nod::{
    ///     disc::{new_disc_base, PartHeader},
    ///     fst::NodeType,
    ///     io::{new_disc_io, DiscIOOptions},
    /// };
    ///
    /// fn main() -> nod::Result<()> {
    ///     let options = DiscIOOptions::default();
    ///     let mut disc_io = new_disc_io("path/to/file.iso".as_ref(), &options)?;
    ///     let disc_base = new_disc_base(disc_io.as_mut())?;
    ///     let mut partition = disc_base.get_data_partition(disc_io.as_mut(), false)?;
    ///     let header = partition.read_header()?;
    ///     if let Some(NodeType::File(node)) = header.find_node("/MP3/Worlds.txt") {
    ///         let mut s = String::new();
    ///         partition.begin_file_stream(node)?.read_to_string(&mut s).expect("Failed to read file");
    ///         println!("{}", s);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    fn begin_file_stream(&mut self, node: &Node) -> io::Result<SharedWindowedReadStream>;

    /// Reads the partition header and file system table.
    fn read_header(&mut self) -> Result<Box<dyn PartHeader>>;

    /// The ideal size for buffered reads from this partition.
    /// GameCube discs have a data block size of 0x8000,
    /// whereas Wii discs have a data block size of 0x7c00.
    fn ideal_buffer_size(&self) -> usize;
}

/// Disc partition header with file system table.
pub trait PartHeader: Debug + Send + Sync {
    /// The root node for the filesystem.
    fn root_node(&self) -> &NodeType;

    /// Finds a particular file or directory by path.
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```no_run
    /// use nod::{
    ///     disc::{new_disc_base, PartHeader},
    ///     fst::NodeType,
    ///     io::{new_disc_io, DiscIOOptions},
    /// };
    ///
    /// fn main() -> nod::Result<()> {
    ///     let options = DiscIOOptions::default();
    ///     let mut disc_io = new_disc_io("path/to/file.iso".as_ref(), &options)?;
    ///     let disc_base = new_disc_base(disc_io.as_mut())?;
    ///     let mut partition = disc_base.get_data_partition(disc_io.as_mut(), false)?;
    ///     let header = partition.read_header()?;
    ///     if let Some(NodeType::File(node)) = header.find_node("/MP1/Metroid1.pak") {
    ///         println!("{}", node.name);
    ///     }
    ///     if let Some(NodeType::Directory(node, children)) = header.find_node("/MP1") {
    ///         println!("Number of files: {}", children.len());
    ///     }
    ///     Ok(())
    /// }
    /// ```
    fn find_node(&self, path: &str) -> Option<&NodeType>;

    /// Disc and partition header (boot.bin)
    fn boot_bytes(&self) -> &[u8];

    /// Debug and region information (bi2.bin)
    fn bi2_bytes(&self) -> &[u8];

    /// Apploader (apploader.bin)
    fn apploader_bytes(&self) -> &[u8];

    /// File system table (fst.bin)
    fn fst_bytes(&self) -> &[u8];

    /// Main binary (main.dol)
    fn dol_bytes(&self) -> &[u8];

    /// Disc header
    fn disc_header(&self) -> &Header;

    /// Partition header
    fn partition_header(&self) -> &PartitionHeader;

    /// Apploader header
    fn apploader_header(&self) -> &AppLoaderHeader;

    /// DOL header
    fn dol_header(&self) -> &DolHeader;
}
