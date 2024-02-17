use std::{io, io::Read};

use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[inline(always)]
pub fn read_from<T, R>(reader: &mut R) -> io::Result<T>
where
    T: FromBytes + FromZeroes + AsBytes,
    R: Read + ?Sized,
{
    let mut ret = <T>::new_zeroed();
    reader.read_exact(ret.as_bytes_mut())?;
    Ok(ret)
}

#[inline(always)]
pub fn read_vec<T, R>(reader: &mut R, count: usize) -> io::Result<Vec<T>>
where
    T: FromBytes + FromZeroes + AsBytes,
    R: Read + ?Sized,
{
    let mut ret = <T>::new_vec_zeroed(count);
    reader.read_exact(ret.as_mut_slice().as_bytes_mut())?;
    Ok(ret)
}

#[inline(always)]
pub fn read_box_slice<T, R>(reader: &mut R, count: usize) -> io::Result<Box<[T]>>
where
    T: FromBytes + FromZeroes + AsBytes,
    R: Read + ?Sized,
{
    let mut ret = <T>::new_box_slice_zeroed(count);
    reader.read_exact(ret.as_mut().as_bytes_mut())?;
    Ok(ret)
}

#[inline(always)]
pub fn read_u16_be<R>(reader: &mut R) -> io::Result<u16>
where R: Read + ?Sized {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

#[inline(always)]
pub fn read_u32_be<R>(reader: &mut R) -> io::Result<u32>
where R: Read + ?Sized {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

#[inline(always)]
pub fn read_u64_be<R>(reader: &mut R) -> io::Result<u64>
where R: Read + ?Sized {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}
