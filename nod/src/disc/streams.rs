//! Partition file read stream.

use std::{
    io,
    io::{BufRead, Read, Seek, SeekFrom},
};

use super::PartitionBase;

/// A file read stream for a [`PartitionBase`].
pub struct FileStream<'a> {
    base: &'a mut dyn PartitionBase,
    pos: u64,
    begin: u64,
    end: u64,
}

impl FileStream<'_> {
    /// Creates a new file stream with offset and size.
    ///
    /// Seeks underlying stream immediately.
    #[inline]
    pub(crate) fn new(
        base: &mut dyn PartitionBase,
        offset: u64,
        size: u64,
    ) -> io::Result<FileStream> {
        base.seek(SeekFrom::Start(offset))?;
        Ok(FileStream { base, pos: offset, begin: offset, end: offset + size })
    }
}

impl<'a> Read for FileStream<'a> {
    #[inline]
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let buf = self.fill_buf()?;
        let len = buf.len().min(out.len());
        out[..len].copy_from_slice(&buf[..len]);
        self.consume(len);
        Ok(len)
    }
}

impl<'a> BufRead for FileStream<'a> {
    #[inline]
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let limit = self.end.saturating_sub(self.pos);
        if limit == 0 {
            return Ok(&[]);
        }
        let buf = self.base.fill_buf()?;
        let max = (buf.len() as u64).min(limit) as usize;
        Ok(&buf[..max])
    }

    #[inline]
    fn consume(&mut self, amt: usize) {
        self.base.consume(amt);
        self.pos += amt as u64;
    }
}

impl<'a> Seek for FileStream<'a> {
    #[inline]
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let mut pos = match pos {
            SeekFrom::Start(p) => self.begin + p,
            SeekFrom::End(p) => self.end.saturating_add_signed(p),
            SeekFrom::Current(p) => self.pos.saturating_add_signed(p),
        };
        if pos < self.begin {
            pos = self.begin;
        } else if pos > self.end {
            pos = self.end;
        }
        let result = self.base.seek(SeekFrom::Start(pos))?;
        self.pos = result;
        Ok(result - self.begin)
    }

    #[inline]
    fn stream_position(&mut self) -> io::Result<u64> { Ok(self.pos) }
}
