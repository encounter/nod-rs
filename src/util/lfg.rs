use std::{cmp::min, io, io::Read};

use zerocopy::{transmute_ref, AsBytes};

use crate::disc::SECTOR_SIZE;

pub const LFG_K: usize = 521;
pub const LFG_J: usize = 32;
pub const SEED_SIZE: usize = 17;

/// Lagged Fibonacci generator for Wii partition junk data.
///
/// References (license CC0-1.0):
/// https://github.com/dolphin-emu/dolphin/blob/a0f555648c27ec0c928f6b1e1fcad5e2d7c4d0c4/docs/WiaAndRvz.md
/// https://github.com/dolphin-emu/dolphin/blob/a0f555648c27ec0c928f6b1e1fcad5e2d7c4d0c4/Source/Core/DiscIO/LaggedFibonacciGenerator.cpp
pub struct LaggedFibonacci {
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
        // Instead of doing the "shift by 18 instead of 16" oddity when actually outputting the data,
        // we can do the shifting (and byteswapping) at this point to make the output code simpler.
        for x in self.buffer.iter_mut() {
            *x = ((*x & 0xFF00FFFF) | (*x >> 2 & 0x00FF0000)).swap_bytes();
        }
        for _ in 0..4 {
            self.forward();
        }
    }

    pub fn init_with_seed(&mut self, init: [u8; 4], disc_num: u8, partition_offset: u64) {
        let seed = u32::from_be_bytes([
            init[2],
            init[1],
            init[3].wrapping_add(init[2]),
            init[0].wrapping_add(init[1]),
        ]) ^ disc_num as u32;
        let sector = (partition_offset / SECTOR_SIZE as u64) as u32;
        let mut n = seed.wrapping_mul(0x260BCD5) ^ sector.wrapping_mul(0x1EF29123);
        for i in 0..SEED_SIZE {
            let mut v = 0u32;
            for _ in 0..LFG_J {
                n = n.wrapping_mul(0x5D588B65).wrapping_add(1);
                v = (v >> 1) | (n & 0x80000000);
            }
            self.buffer[i] = v;
        }
        self.buffer[16] ^= self.buffer[0] >> 9 ^ self.buffer[16] << 23;
        self.position = 0;
        self.init();
        self.skip((partition_offset % SECTOR_SIZE as u64) as usize);
    }

    pub fn init_with_reader<R>(&mut self, reader: &mut R) -> io::Result<()>
    where R: Read + ?Sized {
        reader.read_exact(self.buffer[..SEED_SIZE].as_bytes_mut())?;
        for x in self.buffer[..SEED_SIZE].iter_mut() {
            *x = u32::from_be(*x);
        }
        self.position = 0;
        self.init();
        Ok(())
    }

    pub fn forward(&mut self) {
        for i in 0..LFG_J {
            self.buffer[i] ^= self.buffer[i + LFG_K - LFG_J];
        }
        for i in LFG_J..LFG_K {
            self.buffer[i] ^= self.buffer[i - LFG_J];
        }
    }

    pub fn skip(&mut self, n: usize) {
        self.position += n;
        while self.position >= LFG_K * 4 {
            self.forward();
            self.position -= LFG_K * 4;
        }
    }

    pub fn fill(&mut self, mut buf: &mut [u8]) {
        while !buf.is_empty() {
            let len = min(buf.len(), LFG_K * 4 - self.position);
            let bytes: &[u8; LFG_K * 4] = transmute_ref!(&self.buffer);
            buf[..len].copy_from_slice(&bytes[self.position..self.position + len]);
            self.position += len;
            buf = &mut buf[len..];
            if self.position == LFG_K * 4 {
                self.forward();
                self.position = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_with_seed_1() {
        let mut lfg = LaggedFibonacci::default();
        lfg.init_with_seed([0x47, 0x41, 0x4c, 0x45], 0, 0x600000);
        let mut buf = [0u8; 16];
        lfg.fill(&mut buf);
        assert_eq!(buf, [
            0xE9, 0x47, 0x67, 0xBD, 0x41, 0x50, 0x4D, 0x5D, 0x61, 0x48, 0xB1, 0x99, 0xA0, 0x12,
            0x0C, 0xBA
        ]);
    }

    #[test]
    fn test_init_with_seed_2() {
        let mut lfg = LaggedFibonacci::default();
        lfg.init_with_seed([0x47, 0x41, 0x4c, 0x45], 0, 0x608000);
        let mut buf = [0u8; 16];
        lfg.fill(&mut buf);
        assert_eq!(buf, [
            0xE2, 0xBB, 0xBD, 0x77, 0xDA, 0xB2, 0x22, 0x42, 0x1C, 0x0C, 0x0B, 0xFC, 0xAC, 0x06,
            0xEA, 0xD0
        ]);
    }
}
