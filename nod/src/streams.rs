//! Common stream types

use std::{
    io,
    io::{Read, Seek, SeekFrom},
};

/// A helper trait for seekable read streams.
pub trait ReadStream: Read + Seek {
    /// Creates a windowed read sub-stream with offset and size.
    ///
    /// Seeks underlying stream immediately.
    #[inline]
    fn new_window(&mut self, offset: u64, size: u64) -> io::Result<SharedWindowedReadStream> {
        self.seek(SeekFrom::Start(offset))?;
        Ok(SharedWindowedReadStream { base: self.as_dyn(), begin: offset, end: offset + size })
    }

    /// Retrieves a type-erased reference to the stream.
    fn as_dyn(&mut self) -> &mut dyn ReadStream;
}

impl<T> ReadStream for T
where T: Read + Seek
{
    #[inline]
    fn as_dyn(&mut self) -> &mut dyn ReadStream { self }
}

/// A non-owning window into an existing [`ReadStream`].
pub struct SharedWindowedReadStream<'a> {
    /// A reference to the base stream.
    pub base: &'a mut dyn ReadStream,
    /// The beginning of the window in bytes.
    pub begin: u64,
    /// The end of the window in bytes.
    pub end: u64,
}

impl<'a> SharedWindowedReadStream<'a> {
    /// Modifies the current window & seeks to the beginning of the window.
    pub fn set_window(&mut self, begin: u64, end: u64) -> io::Result<()> {
        self.base.seek(SeekFrom::Start(begin))?;
        self.begin = begin;
        self.end = end;
        Ok(())
    }
}

impl<'a> Read for SharedWindowedReadStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let pos = self.stream_position()?;
        let size = self.end - self.begin;
        if pos == size {
            return Ok(0);
        }
        self.base.read(if pos + buf.len() as u64 > size {
            &mut buf[..(size - pos) as usize]
        } else {
            buf
        })
    }
}

impl<'a> Seek for SharedWindowedReadStream<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let result = self.base.seek(match pos {
            SeekFrom::Start(p) => SeekFrom::Start(self.begin + p),
            SeekFrom::End(p) => SeekFrom::End(self.end as i64 + p),
            SeekFrom::Current(_) => pos,
        })?;
        if result < self.begin || result > self.end {
            Err(io::Error::from(io::ErrorKind::UnexpectedEof))
        } else {
            Ok(result - self.begin)
        }
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.base.stream_position()? - self.begin)
    }
}
