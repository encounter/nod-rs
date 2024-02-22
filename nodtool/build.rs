use std::{
    env,
    fs::File,
    io::{BufReader, BufWriter, Write},
    mem::size_of,
    path::Path,
};

use hex::deserialize as deserialize_hex;
use serde::Deserialize;
use zerocopy::AsBytes;

// Keep in sync with build.rs
#[derive(Clone, Debug, AsBytes)]
#[repr(C, align(4))]
struct Header {
    entry_count: u32,
    entry_size: u32,
}

// Keep in sync with redump.rs
#[derive(Clone, Debug, AsBytes)]
#[repr(C, align(4))]
struct GameEntry {
    crc32: u32,
    string_table_offset: u32,
    sectors: u32,
    md5: [u8; 16],
    sha1: [u8; 20],
}

fn main() {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("Failed to execute git");
    let rev = String::from_utf8(output.stdout).expect("Failed to parse git output");
    println!("cargo:rustc-env=GIT_COMMIT_SHA={rev}");
    println!("cargo:rustc-rerun-if-changed=.git/HEAD");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("parsed-dats.bin");
    let mut f = BufWriter::new(File::create(&dest_path).unwrap());

    // Parse dat files
    let mut entries = Vec::<(GameEntry, String)>::new();
    for path in ["assets/redump-gc.dat", "assets/redump-wii.dat"] {
        let file = BufReader::new(File::open(path).expect("Failed to open dat file"));
        let dat: DatFile = quick_xml::de::from_reader(file).expect("Failed to parse dat file");
        entries.extend(dat.games.into_iter().map(|game| {
            (
                GameEntry {
                    string_table_offset: 0,
                    crc32: u32::from_be_bytes(game.rom.crc32),
                    md5: game.rom.md5,
                    sha1: game.rom.sha1,
                    sectors: game.rom.size.div_ceil(0x8000) as u32,
                },
                game.name,
            )
        }));
    }

    // Sort by CRC32
    entries.sort_by_key(|(entry, _)| entry.crc32);

    // Write game entries
    let header =
        Header { entry_count: entries.len() as u32, entry_size: size_of::<GameEntry>() as u32 };
    f.write_all(header.as_bytes()).unwrap();
    let mut string_table_offset = 0u32;
    for (entry, name) in &mut entries {
        entry.string_table_offset = string_table_offset;
        f.write_all(entry.as_bytes()).unwrap();
        string_table_offset += name.as_bytes().len() as u32 + 4;
    }

    // Write string table
    for (_, name) in &entries {
        f.write_all(&(name.len() as u32).to_le_bytes()).unwrap();
        f.write_all(name.as_bytes()).unwrap();
    }
    f.flush().unwrap();
}

#[derive(Clone, Debug, Deserialize)]
struct DatFile {
    #[serde(rename = "game")]
    games: Vec<DatGame>,
}

#[derive(Clone, Debug, Deserialize)]
struct DatGame {
    #[serde(rename = "@name")]
    name: String,
    rom: DatGameRom,
}

#[derive(Clone, Debug, Deserialize)]
struct DatGameRom {
    #[serde(rename = "@size")]
    size: u64,
    #[serde(rename = "@crc", deserialize_with = "deserialize_hex")]
    crc32: [u8; 4],
    #[serde(rename = "@md5", deserialize_with = "deserialize_hex")]
    md5: [u8; 16],
    #[serde(rename = "@sha1", deserialize_with = "deserialize_hex")]
    sha1: [u8; 20],
}
