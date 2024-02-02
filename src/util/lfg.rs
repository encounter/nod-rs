use std::{cmp::min, io, io::Read};

pub(crate) const LFG_K: usize = 521;
pub(crate) const LFG_J: usize = 32;
pub(crate) const SEED_SIZE: usize = 17;

/// Lagged Fibonacci generator for Wii partition junk data.
/// https://github.com/dolphin-emu/dolphin/blob/master/docs/WiaAndRvz.md#prng-algorithm
pub(crate) struct LaggedFibonacci {
    buffer: [u32; LFG_K],
    position: usize,
}

impl Default for LaggedFibonacci {
    fn default() -> Self { Self { buffer: [0u32; LFG_K], position: 0 } }
}

impl LaggedFibonacci {
    fn init(&mut self) {
        for i in SEED_SIZE..LFG_K {
            self.buffer[i] =
                (self.buffer[i - 17] << 23) ^ (self.buffer[i - 16] >> 9) ^ self.buffer[i - 1];
        }
        for x in self.buffer.iter_mut() {
            *x = ((*x & 0xFF00FFFF) | (*x >> 2 & 0x00FF0000)).swap_bytes();
        }
        for _ in 0..4 {
            self.forward();
        }
    }

    pub(crate) fn init_with_reader<R>(&mut self, reader: &mut R) -> io::Result<()>
    where R: Read + ?Sized {
        reader.read_exact(bytemuck::cast_slice_mut(&mut self.buffer[..SEED_SIZE]))?;
        for x in self.buffer[..SEED_SIZE].iter_mut() {
            *x = u32::from_be(*x);
        }
        self.position = 0;
        self.init();
        Ok(())
    }

    pub(crate) fn forward(&mut self) {
        for i in 0..LFG_J {
            self.buffer[i] ^= self.buffer[i + LFG_K - LFG_J];
        }
        for i in LFG_J..LFG_K {
            self.buffer[i] ^= self.buffer[i - LFG_J];
        }
    }

    pub(crate) fn skip(&mut self, n: usize) {
        self.position += n;
        while self.position >= LFG_K * 4 {
            self.forward();
            self.position -= LFG_K * 4;
        }
    }

    #[inline]
    fn bytes(&self) -> &[u8; LFG_K * 4] {
        unsafe { &*(self.buffer.as_ptr() as *const [u8; LFG_K * 4]) }
    }

    pub(crate) fn fill(&mut self, mut buf: &mut [u8]) {
        while !buf.is_empty() {
            let len = min(buf.len(), LFG_K * 4 - self.position);
            buf[..len].copy_from_slice(&self.bytes()[self.position..self.position + len]);
            self.position += len;
            buf = &mut buf[len..];
            if self.position == LFG_K * 4 {
                self.forward();
                self.position = 0;
            }
        }
    }
}
