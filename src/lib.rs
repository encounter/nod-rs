//! Library for traversing & reading GameCube and Wii disc images.
//!
//! Based on the C++ library [nod](https://github.com/AxioDL/nod),
//! but does not currently support authoring.
//!
//! Currently supported file formats:
//! - ISO
//! - NFS (Wii U VC files, e.g. `hif_000000.nfs`)
//!
//! # Examples
//!
//! Opening a disc image and reading a file:
//! ```
//! use nod::disc::{new_disc_base, PartHeader};
//! use nod::fst::NodeType;
//! use nod::io::new_disc_io;
//! use std::io::Read;
//!
//! let mut disc_io = new_disc_io("path/to/file".as_ref())?;
//! let disc_base = new_disc_base(disc_io.as_mut())?;
//! let mut partition = disc_base.get_data_partition(disc_io.as_mut())?;
//! let header = partition.read_header()?;
//! if let Some(NodeType::File(node)) = header.find_node("/MP3/Worlds.txt") {
//!     let mut s = String::new();
//!     partition.begin_file_stream(node)?.read_to_string(&mut s);
//!     println!(s);
//! }
//! ```
pub mod fst;
pub mod disc;
pub mod io;
pub mod streams;

#[derive(Debug)]
pub enum Error {
    BinaryFormat(binread::Error),
    Encryption(block_modes::BlockModeError),
    Io(String, std::io::Error),
    DiscFormat(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<std::io::Error> for Error {
    fn from(v: std::io::Error) -> Self {
        Error::Io("I/O error".to_string(), v)
    }
}

impl From<binread::Error> for Error {
    fn from(v: binread::Error) -> Self {
        Error::BinaryFormat(v)
    }
}

impl From<block_modes::BlockModeError> for Error {
    fn from(v: block_modes::BlockModeError) -> Self {
        Error::Encryption(v)
    }
}

#[inline(always)]
pub(crate) fn div_rem<T: std::ops::Div<Output=T> + std::ops::Rem<Output=T> + Copy>(x: T, y: T) -> (T, T) {
    let quot = x / y;
    let rem = x % y;
    (quot, rem)
}
