//! Disc file format related logic (ISO, NFS, etc)

use std::{fs, io, path::Path};

use crate::{
    io::{
        iso::{DiscIOISO, DiscIOISOStream},
        nfs::DiscIONFS,
        wia::DiscIOWIA,
    },
    streams::{ByteReadStream, ReadStream},
    Error, Result,
};

pub(crate) mod iso;
pub(crate) mod nfs;
pub(crate) mod wia;

#[derive(Default, Debug, Clone)]
pub struct DiscIOOptions {
    /// Rebuild hashes for the disc image.
    pub rebuild_hashes: bool,
}

/// Abstraction over supported disc file types.
pub trait DiscIO: Send + Sync {
    /// Opens a new read stream for the disc file(s).
    /// Generally does _not_ need to be used directly.
    fn begin_read_stream(&mut self, offset: u64) -> io::Result<Box<dyn ReadStream + '_>>;

    /// If false, the file format does not use standard Wii partition encryption. (e.g. NFS)
    fn has_wii_crypto(&self) -> bool { true }
}

/// Creates a new [`DiscIO`] instance.
///
/// # Examples
///
/// Basic usage:
/// ```no_run
/// use nod::io::{new_disc_io, DiscIOOptions};
///
/// # fn main() -> nod::Result<()> {
/// let options = DiscIOOptions::default();
/// let mut disc_io = new_disc_io("path/to/file.iso".as_ref(), &options)?;
/// # Ok(())
/// # }
/// ```
pub fn new_disc_io(filename: &Path, options: &DiscIOOptions) -> Result<Box<dyn DiscIO>> {
    let path_result = fs::canonicalize(filename);
    if let Err(err) = path_result {
        return Err(Error::Io(format!("Failed to open {}", filename.display()), err));
    }
    let path = path_result.as_ref().unwrap();
    let meta = fs::metadata(path);
    if let Err(err) = meta {
        return Err(Error::Io(format!("Failed to open {}", filename.display()), err));
    }
    if !meta.unwrap().is_file() {
        return Err(Error::DiscFormat(format!("Input is not a file: {}", filename.display())));
    }
    if has_extension(path, "iso") {
        Ok(Box::from(DiscIOISO::new(path)?))
    } else if has_extension(path, "nfs") {
        match path.parent() {
            Some(parent) if parent.is_dir() => {
                Ok(Box::from(DiscIONFS::new(path.parent().unwrap())?))
            }
            _ => Err(Error::DiscFormat("Failed to locate NFS parent directory".to_string())),
        }
    } else if has_extension(path, "wia") || has_extension(path, "rvz") {
        Ok(Box::from(DiscIOWIA::new(path, options)?))
    } else {
        Err(Error::DiscFormat("Unknown file type".to_string()))
    }
}

/// Creates a new [`DiscIO`] instance from a byte slice.
///
/// # Examples
///
/// Basic usage:
/// ```no_run
/// use nod::io::new_disc_io_from_buf;
///
/// # fn main() -> nod::Result<()> {
/// # #[allow(non_upper_case_globals)] const buf: &[u8] = &[0u8; 0];
/// let mut disc_io = new_disc_io_from_buf(buf)?;
/// # Ok(())
/// # }
/// ```
pub fn new_disc_io_from_buf(buf: &[u8]) -> Result<Box<dyn DiscIO + '_>> {
    new_disc_io_from_stream(ByteReadStream { bytes: buf, position: 0 })
}

/// Creates a new [`DiscIO`] instance from an existing [`ReadStream`].
///
/// # Examples
///
/// Basic usage:
/// ```no_run
/// use nod::io::new_disc_io_from_stream;
/// use nod::streams::ByteReadStream;
///
/// # fn main() -> nod::Result<()> {
/// # #[allow(non_upper_case_globals)] const buf: &[u8] = &[0u8; 0];
/// let stream = ByteReadStream { bytes: buf, position: 0 };
/// let mut disc_io = new_disc_io_from_stream(stream)?;
/// # Ok(())
/// # }
/// ```
pub fn new_disc_io_from_stream<'a, T: 'a + ReadStream + Sized + Send + Sync>(
    stream: T,
) -> Result<Box<dyn DiscIO + 'a>> {
    Ok(Box::from(DiscIOISOStream::new(stream)?))
}

/// Helper function for checking a file extension.
#[inline(always)]
pub fn has_extension(filename: &Path, extension: &str) -> bool {
    match filename.extension() {
        Some(ext) => ext.eq_ignore_ascii_case(extension),
        None => false,
    }
}
