//! Common stream types

use std::{
    fs::File,
    io,
    io::{Read, Seek, SeekFrom},
    ops::DerefMut,
};

/// Creates a fixed-size array reference from a slice.
#[macro_export]
macro_rules! array_ref {
    ($slice:expr, $offset:expr, $size:expr) => {{
        #[inline]
        fn to_array<T>(slice: &[T]) -> &[T; $size] {
            unsafe { &*(slice.as_ptr() as *const [_; $size]) }
        }
        to_array(&$slice[$offset..$offset + $size])
    }};
}

/// Creates a mutable fixed-size array reference from a slice.
#[macro_export]
macro_rules! array_ref_mut {
    ($slice:expr, $offset:expr, $size:expr) => {{
        #[inline]
        fn to_array<T>(slice: &mut [T]) -> &mut [T; $size] {
            unsafe { &mut *(slice.as_ptr() as *mut [_; $size]) }
        }
        to_array(&mut $slice[$offset..$offset + $size])
    }};
}

pub trait ReadStream: Read + Seek {
    /// Replace with [`Read.stream_len`] when stabilized.
    ///
    /// <https://github.com/rust-lang/rust/issues/59359>
    fn stable_stream_len(&mut self) -> io::Result<u64>;

    /// Creates a windowed read sub-stream with offset and size.
    ///
    /// Seeks underlying stream immediately.
    fn new_window(&mut self, offset: u64, size: u64) -> io::Result<SharedWindowedReadStream> {
        self.seek(SeekFrom::Start(offset))?;
        io::Result::Ok(SharedWindowedReadStream {
            base: self.as_dyn(),
            begin: offset,
            end: offset + size,
        })
    }

    fn as_dyn(&mut self) -> &mut dyn ReadStream;
}

impl ReadStream for File {
    fn stable_stream_len(&mut self) -> io::Result<u64> {
        let before = self.stream_position()?;
        let result = self.seek(SeekFrom::End(0));
        // Try to restore position even if the above failed
        let seek_result = self.seek(SeekFrom::Start(before));
        if seek_result.is_err() {
            return if result.is_err() { result } else { seek_result };
        }
        result
    }

    fn as_dyn(&mut self) -> &mut dyn ReadStream { self }
}

trait WindowedReadStream: ReadStream {
    fn base_stream(&mut self) -> &mut dyn ReadStream;
    fn window(&self) -> (u64, u64);
}

pub struct OwningWindowedReadStream<'a> {
    pub base: Box<dyn ReadStream + 'a>,
    pub begin: u64,
    pub end: u64,
}

/// Takes ownership of & wraps a read stream into a windowed read stream.
pub fn wrap_windowed<'a>(
    mut base: Box<dyn ReadStream + 'a>,
    offset: u64,
    size: u64,
) -> io::Result<OwningWindowedReadStream<'a>> {
    base.seek(SeekFrom::Start(offset))?;
    io::Result::Ok(OwningWindowedReadStream { base, begin: offset, end: offset + size })
}

pub struct SharedWindowedReadStream<'a> {
    pub base: &'a mut dyn ReadStream,
    pub begin: u64,
    pub end: u64,
}

impl<'a> SharedWindowedReadStream<'a> {
    pub fn set_window(&mut self, begin: u64, end: u64) -> io::Result<()> {
        self.base.seek(SeekFrom::Start(begin))?;
        self.begin = begin;
        self.end = end;
        io::Result::Ok(())
    }
}

#[inline(always)]
fn windowed_read(stream: &mut dyn WindowedReadStream, buf: &mut [u8]) -> io::Result<usize> {
    let pos = stream.stream_position()?;
    let size = stream.stable_stream_len()?;
    if pos == size {
        return Ok(0);
    }
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
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { windowed_read(self, buf) }
}

impl<'a> Seek for OwningWindowedReadStream<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> { windowed_seek(self, pos) }

    fn stream_position(&mut self) -> io::Result<u64> {
        Result::Ok(self.base.stream_position()? - self.begin)
    }
}

impl<'a> ReadStream for OwningWindowedReadStream<'a> {
    fn stable_stream_len(&mut self) -> io::Result<u64> { Result::Ok(self.end - self.begin) }

    fn as_dyn(&mut self) -> &mut dyn ReadStream { self }
}

impl<'a> WindowedReadStream for OwningWindowedReadStream<'a> {
    fn base_stream(&mut self) -> &mut dyn ReadStream { self.base.deref_mut() }

    fn window(&self) -> (u64, u64) { (self.begin, self.end) }
}

impl<'a> Read for SharedWindowedReadStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { windowed_read(self, buf) }
}

impl<'a> Seek for SharedWindowedReadStream<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> { windowed_seek(self, pos) }

    fn stream_position(&mut self) -> io::Result<u64> {
        Result::Ok(self.base.stream_position()? - self.begin)
    }
}

impl<'a> ReadStream for SharedWindowedReadStream<'a> {
    fn stable_stream_len(&mut self) -> io::Result<u64> { Result::Ok(self.end - self.begin) }

    fn as_dyn(&mut self) -> &mut dyn ReadStream { self }
}

impl<'a> WindowedReadStream for SharedWindowedReadStream<'a> {
    fn base_stream(&mut self) -> &mut dyn ReadStream { self.base }

    fn window(&self) -> (u64, u64) { (self.begin, self.end) }
}

pub struct ByteReadStream<'a> {
    pub bytes: &'a [u8],
    pub position: u64,
}

impl Read for ByteReadStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut len = buf.len();
        let total = self.bytes.len();
        let pos = self.position as usize;
        if len + pos > total {
            #[allow(clippy::comparison_chain)]
            if pos > total {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            } else if pos == total {
                return Ok(0);
            }
            len = total - pos;
        }
        buf.copy_from_slice(&self.bytes[pos..pos + len]);
        self.position += len as u64;
        Ok(len)
    }
}

impl Seek for ByteReadStream<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(v) => (self.bytes.len() as i64 + v) as u64,
            SeekFrom::Current(v) => (self.position as i64 + v) as u64,
        };
        if new_pos > self.bytes.len() as u64 {
            Err(io::Error::from(io::ErrorKind::UnexpectedEof))
        } else {
            self.position = new_pos;
            Ok(new_pos)
        }
    }

    // fn stream_len(&mut self) -> io::Result<u64> { Ok(self.bytes.len() as u64) }

    fn stream_position(&mut self) -> io::Result<u64> { Ok(self.position) }
}

impl ReadStream for ByteReadStream<'_> {
    fn stable_stream_len(&mut self) -> io::Result<u64> { Ok(self.bytes.len() as u64) }

    fn as_dyn(&mut self) -> &mut dyn ReadStream { self }
}

impl<'a> AsMut<dyn ReadStream + 'a> for ByteReadStream<'a> {
    fn as_mut(&mut self) -> &mut (dyn ReadStream + 'a) { self as &mut (dyn ReadStream + 'a) }
}
