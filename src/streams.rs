//! Common stream types

use std::{fs::File, io, io::{Read, Seek, SeekFrom}};
use std::ops::DerefMut;

/// Creates a fixed-size array from a slice.
#[macro_export]
macro_rules! array_ref {
    ($slice:expr, $offset:expr, $size:expr) => {{
        #[inline]
        fn to_array<T>(slice: &[T]) -> &[T; $size] {
            unsafe { &*(slice.as_ptr() as *const [_; $size]) }
        }
        to_array(&$slice[$offset..$offset + $size])
    }}
}

pub trait ReadStream: Read + Seek {}

impl ReadStream for File {}

trait WindowedReadStream: ReadStream {
    fn base_stream(&mut self) -> &mut dyn ReadStream;
    fn window(&self) -> (u64, u64);
}

pub struct OwningWindowedReadStream<'a> {
    pub(crate) base: Box<dyn ReadStream + 'a>,
    pub(crate) begin: u64,
    pub(crate) end: u64,
}

pub struct SharedWindowedReadStream<'a> {
    pub(crate) base: &'a mut dyn ReadStream,
    pub(crate) begin: u64,
    pub(crate) end: u64,
}

#[inline(always)]
fn windowed_read(stream: &mut dyn WindowedReadStream, buf: &mut [u8]) -> io::Result<usize> {
    let pos = stream.stream_position()?;
    let size = stream.stream_len()?;
    stream.base_stream().read(if pos + buf.len() as u64 > size {
        &mut buf[..(size - pos) as usize]
    } else {
        buf
    })
}

#[inline(always)]
fn windowed_seek(stream: &mut dyn WindowedReadStream, pos: SeekFrom) -> io::Result<u64> {
    let (begin, end) = stream.window();
    let result = stream.base_stream().seek(match pos {
        SeekFrom::Start(p) => SeekFrom::Start(begin + p),
        SeekFrom::End(p) => SeekFrom::End(end as i64 + p),
        SeekFrom::Current(_) => pos,
    })?;
    if result < begin || result > end {
        io::Result::Err(io::Error::from(io::ErrorKind::UnexpectedEof))
    } else {
        io::Result::Ok(result - begin)
    }
}

impl<'a> Read for OwningWindowedReadStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        windowed_read(self, buf)
    }
}

impl<'a> Seek for OwningWindowedReadStream<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        windowed_seek(self, pos)
    }

    fn stream_len(&mut self) -> io::Result<u64> {
        Result::Ok(self.end - self.begin)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Result::Ok(self.base.stream_position()? - self.begin)
    }
}

impl<'a> ReadStream for OwningWindowedReadStream<'a> {}

impl<'a> WindowedReadStream for OwningWindowedReadStream<'a> {
    fn base_stream(&mut self) -> &mut dyn ReadStream {
        self.base.deref_mut()
    }

    fn window(&self) -> (u64, u64) {
        (self.begin, self.end)
    }
}

impl<'a> Read for SharedWindowedReadStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        windowed_read(self, buf)
    }
}

impl<'a> Seek for SharedWindowedReadStream<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        windowed_seek(self, pos)
    }

    fn stream_len(&mut self) -> io::Result<u64> {
        Result::Ok(self.end - self.begin)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Result::Ok(self.base.stream_position()? - self.begin)
    }
}

impl<'a> ReadStream for SharedWindowedReadStream<'a> {}

impl<'a> WindowedReadStream for SharedWindowedReadStream<'a> {
    fn base_stream(&mut self) -> &mut dyn ReadStream {
        self.base
    }

    fn window(&self) -> (u64, u64) {
        (self.begin, self.end)
    }
}
