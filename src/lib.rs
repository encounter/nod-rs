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
//! ```no_run
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
//!     println!("{}", s);
//! }
//! # Ok::<(), nod::Error>(())
//! ```
use thiserror::Error;

pub mod disc;
pub mod fst;
pub mod io;
pub mod streams;

#[derive(Error, Debug)]
pub enum Error {
    #[error("binary format")]
    BinaryFormat(#[from] binrw::Error),
    #[error("encryption")]
    Encryption(#[from] block_modes::BlockModeError),
    #[error("io error: `{0}`")]
    Io(String, #[source] std::io::Error),
    #[error("disc format error: `{0}`")]
    DiscFormat(String),
}

pub type Result<T> = anyhow::Result<T, Error>;

impl From<std::io::Error> for Error {
    fn from(v: std::io::Error) -> Self { Error::Io("I/O error".to_string(), v) }
}

#[inline(always)]
pub(crate) fn div_rem<T: std::ops::Div<Output = T> + std::ops::Rem<Output = T> + Copy>(
    x: T,
    y: T,
) -> (T, T) {
    let quot = x / y;
    let rem = x % y;
    (quot, rem)
}
