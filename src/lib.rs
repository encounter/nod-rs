// #![warn(missing_docs, rustdoc::missing_doc_code_examples)]
//! Library for traversing & reading GameCube and Wii disc images.
//!
//! Based on the C++ library [nod](https://github.com/AxioDL/nod),
//! but does not currently support authoring.
//!
//! Currently supported file formats:
//! - ISO (GCM)
//! - WIA / RVZ
//! - WBFS
//! - NFS (Wii U VC files, e.g. `hif_000000.nfs`)
//!
//! # Examples
//!
//! Opening a disc image and reading a file:
//! ```no_run
//! use std::io::Read;
//!
//! use nod::{Disc, PartitionKind};
//!
//! fn main() -> nod::Result<()> {
//!     let disc = Disc::new("path/to/file.iso")?;
//!     let mut partition = disc.open_partition_kind(PartitionKind::Data)?;
//!     let meta = partition.meta()?;
//!     let fst = meta.fst()?;
//!     if let Some((_, node)) = fst.find("/MP3/Worlds.txt") {
//!         let mut s = String::new();
//!         partition
//!             .open_file(node)
//!             .expect("Failed to open file stream")
//!             .read_to_string(&mut s)
//!             .expect("Failed to read file");
//!         println!("{}", s);
//!     }
//!     Ok(())
//! }
//! ```

use std::path::Path;

pub use disc::{
    AppLoaderHeader, DiscHeader, DolHeader, PartitionBase, PartitionHeader, PartitionInfo,
    PartitionKind, PartitionMeta, BI2_SIZE, BOOT_SIZE, SECTOR_SIZE,
};
pub use fst::{Fst, Node, NodeKind};
pub use io::DiscMeta;
use io::{block, block::BPartitionInfo};
pub use streams::ReadStream;

use crate::disc::reader::{DiscReader, EncryptionMode};

mod disc;
mod fst;
pub mod io;
mod streams;
mod util;

/// Error types for nod.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// An error for disc format related issues.
    #[error("disc format error: {0}")]
    DiscFormat(String),
    /// A general I/O error.
    #[error("I/O error: {0}")]
    Io(String, #[source] std::io::Error),
    /// An unknown error.
    #[error("error: {0}")]
    Other(String),
}

impl From<&str> for Error {
    fn from(s: &str) -> Error { Error::Other(s.to_string()) }
}

impl From<String> for Error {
    fn from(s: String) -> Error { Error::Other(s) }
}

/// Helper result type for [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

pub trait ErrorContext {
    fn context(self, context: impl Into<String>) -> Error;
}

impl ErrorContext for std::io::Error {
    fn context(self, context: impl Into<String>) -> Error { Error::Io(context.into(), self) }
}

pub trait ResultContext<T> {
    fn context(self, context: impl Into<String>) -> Result<T>;

    fn with_context<F>(self, f: F) -> Result<T>
    where F: FnOnce() -> String;
}

impl<T, E> ResultContext<T> for Result<T, E>
where E: ErrorContext
{
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|e| e.context(context))
    }

    fn with_context<F>(self, f: F) -> Result<T>
    where F: FnOnce() -> String {
        self.map_err(|e| e.context(f()))
    }
}

#[derive(Default, Debug, Clone)]
pub struct OpenOptions {
    /// Wii: Validate partition data hashes while reading the disc image if present.
    pub validate_hashes: bool,
    /// Wii: Rebuild partition data hashes for the disc image if the underlying format
    /// does not store them. (e.g. WIA/RVZ)
    pub rebuild_hashes: bool,
    /// Wii: Rebuild partition data encryption if the underlying format stores data decrypted.
    /// (e.g. WIA/RVZ, NFS)
    ///
    /// Unnecessary if only opening a disc partition stream, which will already provide a decrypted
    /// stream. In this case, this will cause unnecessary processing.
    ///
    /// Only valid in combination with `rebuild_hashes`, as the data encryption is derived from the
    /// partition data hashes.
    pub rebuild_encryption: bool,
}

pub struct Disc {
    pub reader: DiscReader,
    options: OpenOptions,
}

impl Disc {
    /// Opens a disc image from a file path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Disc> {
        Disc::new_with_options(path, &OpenOptions::default())
    }

    /// Opens a disc image from a file path with custom options.
    pub fn new_with_options<P: AsRef<Path>>(path: P, options: &OpenOptions) -> Result<Disc> {
        let io = block::open(path.as_ref(), options)?;
        let reader = DiscReader::new(io, EncryptionMode::Encrypted)?;
        Ok(Disc { reader, options: options.clone() })
    }

    /// The disc's header.
    pub fn header(&self) -> &DiscHeader { self.reader.header() }

    /// Returns extra metadata included in the disc file format, if any.
    pub fn meta(&self) -> Result<DiscMeta> { self.reader.io.meta() }

    /// The disc's size in bytes or an estimate if not stored by the format.
    pub fn disc_size(&self) -> u64 { self.reader.disc_size() }

    /// A list of partitions on the disc.
    ///
    /// For GameCube discs, this will return a single data partition spanning the entire disc.
    pub fn partitions(&self) -> &[BPartitionInfo] { self.reader.partitions() }

    // /// Opens a new read stream for the base disc image.
    // ///
    // /// Generally does _not_ need to be used directly. Opening a partition will provide a
    // /// decrypted stream instead.
    // pub fn open(&self) -> Result<Box<dyn ReadStream + '_>> { self.io.open() }
    //
    // /// Opens a new, decrypted partition read stream for the specified partition index.
    // pub fn open_partition(&self, index: usize) -> Result<Box<dyn PartitionBase + '_>> {
    //     self.base.open_partition(self.io.as_ref(), index, &self.options)
    // }
    //
    // /// Opens a new partition read stream for the first partition matching
    // /// the specified type.
    // pub fn open_partition_kind(&self, kind: PartitionKind) -> Result<Box<dyn PartitionBase + '_>> {
    //     self.base.open_partition_kind(self.io.as_ref(), kind, &self.options)
    // }
}
