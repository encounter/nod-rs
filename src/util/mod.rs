use std::ops::{Div, Rem};

pub(crate) mod lfg;
pub(crate) mod reader;
pub(crate) mod take_seek;

#[inline(always)]
pub(crate) fn div_rem<T>(x: T, y: T) -> (T, T)
where T: Div<Output = T> + Rem<Output = T> + Copy {
    let quot = x / y;
    let rem = x % y;
    (quot, rem)
}
