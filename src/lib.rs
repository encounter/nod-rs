#![warn(missing_docs, rustdoc::missing_doc_code_examples)]
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
//! use nod::{
//!     disc::{new_disc_base, PartHeader},
//!     fst::NodeType,
//!     io::{new_disc_io, DiscIOOptions},
//! };
//!
//! fn main() -> nod::Result<()> {
//!     let options = DiscIOOptions::default();
//!     let mut disc_io = new_disc_io("path/to/file.iso".as_ref(), &options)?;
//!     let disc_base = new_disc_base(disc_io.as_mut())?;
//!     let mut partition = disc_base.get_data_partition(disc_io.as_mut(), false)?;
//!     let header = partition.read_header()?;
//!     if let Some(NodeType::File(node)) = header.find_node("/MP3/Worlds.txt") {
//!         let mut s = String::new();
//!         partition.begin_file_stream(node)?.read_to_string(&mut s).expect("Failed to read file");
//!         println!("{}", s);
//!     }
//!     Ok(())
//! }
//! ```
pub mod disc;
pub mod fst;
pub mod io;
pub mod streams;
pub mod util;

/// Error types for nod.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// An error for disc format related issues.
    #[error("disc format error: {0}")]
    DiscFormat(String),
    /// A general I/O error.
    #[error("I/O error: {0}")]
    Io(String, #[source] std::io::Error),
}

/// Helper result type for [`Error`].
pub type Result<T, E = Error> = core::result::Result<T, E>;

impl From<aes::cipher::block_padding::UnpadError> for Error {
    fn from(_: aes::cipher::block_padding::UnpadError) -> Self { unreachable!() }
}

impl From<base16ct::Error> for Error {
    fn from(_: base16ct::Error) -> Self { unreachable!() }
}

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
