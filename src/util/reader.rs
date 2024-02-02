use std::{ffi::CString, io, io::Read};

use io::Write;

pub(crate) const DYNAMIC_SIZE: usize = 0;

pub(crate) const fn struct_size<const N: usize>(fields: [usize; N]) -> usize {
    let mut result = 0;
    let mut i = 0;
    while i < N {
        let size = fields[i];
        if size == DYNAMIC_SIZE {
            // Dynamically sized
            return DYNAMIC_SIZE;
        }
        result += size;
        i += 1;
    }
    result
}

pub(crate) fn skip_bytes<const N: usize, R>(reader: &mut R) -> io::Result<()>
where R: Read + ?Sized {
    let mut buf = [0u8; N];
    reader.read_exact(&mut buf)?;
    Ok(())
}

pub(crate) trait FromReader: Sized {
    type Args<'a>;

    const STATIC_SIZE: usize;

    fn from_reader_args<R>(reader: &mut R, args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized;

    fn from_reader<'a, R>(reader: &mut R) -> io::Result<Self>
    where
        R: Read + ?Sized,
        Self::Args<'a>: Default,
    {
        Self::from_reader_args(reader, Default::default())
    }
}

macro_rules! impl_from_reader {
    ($($t:ty),*) => {
        $(
            impl FromReader for $t {
                type Args<'a> = ();

                const STATIC_SIZE: usize = std::mem::size_of::<Self>();

                fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self> where R: Read + ?Sized{
                    let mut buf = [0u8; Self::STATIC_SIZE];
                    reader.read_exact(&mut buf)?;
                    Ok(Self::from_be_bytes(buf))
                }
            }
        )*
    };
}

impl_from_reader!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

#[repr(transparent)]
pub struct U24(pub u32);

impl FromReader for U24 {
    type Args<'a> = ();

    const STATIC_SIZE: usize = 3;

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf[1..])?;
        Ok(U24(u32::from_be_bytes(buf)))
    }
}

impl<const N: usize> FromReader for [u8; N] {
    type Args<'a> = ();

    const STATIC_SIZE: usize = N;

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        let mut buf = [0u8; N];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl<const N: usize> FromReader for [u32; N] {
    type Args<'a> = ();

    const STATIC_SIZE: usize = N * u32::STATIC_SIZE;

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        let mut buf = [0u32; N];
        reader.read_exact(unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, Self::STATIC_SIZE)
        })?;
        for x in buf.iter_mut() {
            *x = u32::from_be(*x);
        }
        Ok(buf)
    }
}

impl FromReader for CString {
    type Args<'a> = ();

    const STATIC_SIZE: usize = DYNAMIC_SIZE;

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        let mut buf = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte)?;
            buf.push(byte[0]);
            if byte[0] == 0 {
                break;
            }
        }
        Ok(unsafe { CString::from_vec_with_nul_unchecked(buf) })
    }
}

pub(crate) fn read_bytes<R>(reader: &mut R, count: usize) -> io::Result<Vec<u8>>
where R: Read + ?Sized {
    let mut buf = vec![0u8; count];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

pub(crate) fn read_vec<'a, T, R>(reader: &mut R, count: usize) -> io::Result<Vec<T>>
where
    T: FromReader,
    R: Read + ?Sized,
    <T as FromReader>::Args<'a>: Default,
{
    let mut vec = Vec::with_capacity(count);
    if T::STATIC_SIZE != DYNAMIC_SIZE {
        // Read the entire buffer at once
        let buf = read_bytes(reader, T::STATIC_SIZE * count)?;
        let mut slice = buf.as_slice();
        for _ in 0..count {
            vec.push(T::from_reader(&mut slice)?);
        }
    } else {
        for _ in 0..count {
            vec.push(T::from_reader(reader)?);
        }
    }
    Ok(vec)
}

pub(crate) trait ToWriter: Sized {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized;

    fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.write_size()];
        self.to_writer(&mut buf.as_mut_slice())?;
        Ok(buf)
    }

    fn write_size(&self) -> usize;
}

macro_rules! impl_to_writer {
    ($($t:ty),*) => {
        $(
            impl ToWriter for $t {
                fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
                where W: Write + ?Sized {
                    writer.write_all(&self.to_be_bytes())
                }

                fn to_bytes(&self) -> io::Result<Vec<u8>> {
                    Ok(self.to_be_bytes().to_vec())
                }

                fn write_size(&self) -> usize {
                    std::mem::size_of::<Self>()
                }
            }
        )*
    };
}

impl_to_writer!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

impl ToWriter for U24 {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        writer.write_all(&self.0.to_be_bytes()[1..])
    }

    fn write_size(&self) -> usize { 3 }
}

impl<const N: usize> ToWriter for [u8; N] {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        writer.write_all(self)
    }

    fn write_size(&self) -> usize { N }
}

impl ToWriter for &[u8] {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        writer.write_all(self)
    }

    fn write_size(&self) -> usize { self.len() }
}

impl ToWriter for Vec<u8> {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        writer.write_all(self)
    }

    fn write_size(&self) -> usize { self.len() }
}

pub(crate) fn write_vec<T, W>(writer: &mut W, vec: &[T]) -> io::Result<()>
where
    T: ToWriter,
    W: Write + ?Sized,
{
    for item in vec {
        item.to_writer(writer)?;
    }
    Ok(())
}
