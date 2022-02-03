//! Disc file format related logic (ISO, NFS, etc)

use std::{fs, io, path::Path};

use crate::{
    io::{
        iso::{DiscIOISO, DiscIOISOStream},
        nfs::DiscIONFS,
    },
    streams::{ByteReadStream, ReadStream},
    Error, Result,
};

pub(crate) mod iso;
pub(crate) mod nfs;

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
/// use nod::io::new_disc_io;
///
/// let mut disc_io = new_disc_io("path/to/file".as_ref())?;
/// # Ok::<(), nod::Error>(())
/// ```
pub fn new_disc_io(filename: &Path) -> Result<Box<dyn DiscIO>> {
    let path_result = fs::canonicalize(filename);
    if let Err(err) = path_result {
        return Result::Err(Error::Io(
            format!("Failed to open {}", filename.to_string_lossy()),
            err,
        ));
    }
    let path = path_result.as_ref().unwrap();
    let meta = fs::metadata(path);
    if let Err(err) = meta {
        return Result::Err(Error::Io(
            format!("Failed to open {}", filename.to_string_lossy()),
            err,
        ));
    }
    if !meta.unwrap().is_file() {
        return Result::Err(Error::DiscFormat(format!(
            "Input is not a file: {}",
            filename.to_string_lossy()
        )));
    }
    if has_extension(path, "iso") {
        Result::Ok(Box::from(DiscIOISO::new(path)?))
    } else if has_extension(path, "nfs") {
        if matches!(path.parent(), Some(parent) if parent.is_dir()) {
            Result::Ok(Box::from(DiscIONFS::new(path.parent().unwrap())?))
        } else {
            Result::Err(Error::DiscFormat("Failed to locate NFS parent directory".to_string()))
        }
    } else {
        Result::Err(Error::DiscFormat("Unknown file type".to_string()))
    }
}

pub fn new_disc_io_from_buf(buf: &[u8]) -> Result<Box<dyn DiscIO + '_>> {
    Ok(Box::from(DiscIOISOStream::new(ByteReadStream { bytes: buf, position: 0 })?))
}

pub fn new_disc_io_from_stream<'a, T: 'a + ReadStream + Sized + Send + Sync>(
    stream: T,
) -> Result<Box<dyn DiscIO + 'a>> {
    Ok(Box::from(DiscIOISOStream::new(stream)?))
}

/// Helper function for checking a file extension.
#[inline(always)]
pub fn has_extension(filename: &Path, extension: &str) -> bool {
    if let Some(ext) = filename.extension() {
        // TODO use with Rust 1.53+
        // ext.eq_ignore_ascii_case(extension)
        ext.to_str().unwrap_or("").eq_ignore_ascii_case(extension)
    } else {
        false
    }
}
