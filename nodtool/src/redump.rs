use std::{mem::size_of, str};

use nod::{array_ref, SECTOR_SIZE};
use zerocopy::{FromBytes, FromZeroes};

#[derive(Clone, Debug)]
pub struct GameResult {
    pub name: &'static str,
    pub crc32: u32,
    pub md5: [u8; 16],
    pub sha1: [u8; 20],
    pub size: u64,
}

pub fn find_by_hashes(crc32: u32, sha1: [u8; 20]) -> Option<GameResult> {
    let header: &Header = Header::ref_from_prefix(&DATA.0).unwrap();
    assert_eq!(header.entry_size as usize, size_of::<GameEntry>());

    let entries_size = header.entry_count as usize * size_of::<GameEntry>();
    let entries: &[GameEntry] =
        GameEntry::slice_from(&DATA.0[size_of::<Header>()..size_of::<Header>() + entries_size])
            .unwrap();
    let string_table: &[u8] = &DATA.0[size_of::<Header>() + entries_size..];

    // Binary search by CRC32
    let index = entries.binary_search_by_key(&crc32, |entry| entry.crc32).ok()?;

    // Verify SHA-1
    let entry = &entries[index];
    if entry.sha1 != sha1 {
        return None;
    }

    // Parse the entry
    let offset = entry.string_table_offset as usize;
    let name_size = u32::from_ne_bytes(*array_ref![string_table, offset, 4]) as usize;
    let name = str::from_utf8(&string_table[offset + 4..offset + 4 + name_size]).unwrap();
    Some(GameResult {
        name,
        crc32: entry.crc32,
        md5: entry.md5,
        sha1: entry.sha1,
        size: entry.sectors as u64 * SECTOR_SIZE as u64,
    })
}

#[repr(C, align(4))]
struct Aligned<T: ?Sized>(T);

const DATA: &'static Aligned<[u8]> =
    &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/parsed-dats.bin")));

// Keep in sync with build.rs
#[derive(Clone, Debug, FromBytes, FromZeroes)]
#[repr(C, align(4))]
struct Header {
    entry_count: u32,
    entry_size: u32,
}

// Keep in sync with build.rs
#[derive(Clone, Debug, FromBytes, FromZeroes)]
#[repr(C, align(4))]
struct GameEntry {
    crc32: u32,
    string_table_offset: u32,
    sectors: u32,
    md5: [u8; 16],
    sha1: [u8; 20],
}
