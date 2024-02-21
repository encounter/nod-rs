use std::{cmp::min, fs, fs::File, io, path::Path};

use dyn_clone::DynClone;
use zerocopy::transmute_ref;

use crate::{
    array_ref,
    disc::{
        hashes::HashTable,
        wii::{WiiPartitionHeader, HASHES_SIZE, SECTOR_DATA_SIZE},
        SECTOR_SIZE,
    },
    io::{aes_decrypt, aes_encrypt, ciso, iso, nfs, wbfs, wia, KeyBytes, MagicBytes},
    util::{lfg::LaggedFibonacci, read::read_from},
    DiscHeader, DiscMeta, Error, OpenOptions, PartitionHeader, PartitionKind, Result,
    ResultContext,
};

/// Block I/O trait for reading disc images.
pub trait BlockIO: DynClone + Send + Sync {
    /// Reads a block from the disc image.
    fn read_block(
        &mut self,
        out: &mut [u8],
        block: u32,
        partition: Option<&BPartitionInfo>,
    ) -> io::Result<Option<Block>>;

    /// The format's block size in bytes. Must be a multiple of the sector size (0x8000).
    fn block_size(&self) -> u32;

    /// Returns extra metadata included in the disc file format, if any.
    fn meta(&self) -> Result<DiscMeta>;
}

dyn_clone::clone_trait_object!(BlockIO);

/// Creates a new [`BlockIO`] instance.
pub fn open(filename: &Path, options: &OpenOptions) -> Result<Box<dyn BlockIO>> {
    let path_result = fs::canonicalize(filename);
    if let Err(err) = path_result {
        return Err(Error::Io(format!("Failed to open {}", filename.display()), err));
    }
    let path = path_result.as_ref().unwrap();
    let meta = fs::metadata(path);
    if let Err(err) = meta {
        return Err(Error::Io(format!("Failed to open {}", filename.display()), err));
    }
    if !meta.unwrap().is_file() {
        return Err(Error::DiscFormat(format!("Input is not a file: {}", filename.display())));
    }
    let magic: MagicBytes = {
        let mut file =
            File::open(path).with_context(|| format!("Opening file {}", filename.display()))?;
        read_from(&mut file)
            .with_context(|| format!("Reading magic bytes from {}", filename.display()))?
    };
    match magic {
        ciso::CISO_MAGIC => Ok(ciso::DiscIOCISO::new(path)?),
        nfs::NFS_MAGIC => match path.parent() {
            Some(parent) if parent.is_dir() => {
                Ok(nfs::DiscIONFS::new(path.parent().unwrap(), options)?)
            }
            _ => Err(Error::DiscFormat("Failed to locate NFS parent directory".to_string())),
        },
        wbfs::WBFS_MAGIC => Ok(wbfs::DiscIOWBFS::new(path)?),
        wia::WIA_MAGIC | wia::RVZ_MAGIC => Ok(wia::DiscIOWIA::new(path, options)?),
        _ => Ok(iso::DiscIOISO::new(path)?),
    }
}

#[derive(Debug, Clone)]
pub struct BPartitionInfo {
    pub index: u32,
    pub kind: PartitionKind,
    pub start_sector: u32,
    pub data_start_sector: u32,
    pub data_end_sector: u32,
    pub key: KeyBytes,
    pub header: Box<WiiPartitionHeader>,
    pub disc_header: Box<DiscHeader>,
    pub partition_header: Box<PartitionHeader>,
    pub hash_table: Option<HashTable>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Block {
    /// Raw data or encrypted Wii partition data
    Raw,
    /// Decrypted Wii partition data
    PartDecrypted {
        /// Whether the sector has its hash block intact
        has_hashes: bool,
    },
    /// Wii partition junk data
    Junk,
    /// All zeroes
    Zero,
}

impl Block {
    pub(crate) fn decrypt(
        self,
        out: &mut [u8; SECTOR_SIZE],
        data: &[u8],
        block_idx: u32,
        abs_sector: u32,
        partition: &BPartitionInfo,
    ) -> io::Result<()> {
        let rel_sector = abs_sector - self.start_sector(block_idx, data.len());
        match self {
            Block::Raw => {
                out.copy_from_slice(block_sector::<SECTOR_SIZE>(data, rel_sector)?);
                decrypt_sector(out, partition);
            }
            Block::PartDecrypted { has_hashes } => {
                out.copy_from_slice(block_sector::<SECTOR_SIZE>(data, rel_sector)?);
                if !has_hashes {
                    rebuild_hash_block(out, abs_sector, partition);
                }
            }
            Block::Junk => {
                generate_junk(out, abs_sector, Some(partition), &partition.disc_header);
                rebuild_hash_block(out, abs_sector, partition);
            }
            Block::Zero => {
                out.fill(0);
                rebuild_hash_block(out, abs_sector, partition);
            }
        }
        Ok(())
    }

    pub(crate) fn encrypt(
        self,
        out: &mut [u8; SECTOR_SIZE],
        data: &[u8],
        block_idx: u32,
        abs_sector: u32,
        partition: &BPartitionInfo,
    ) -> io::Result<()> {
        let rel_sector = abs_sector - self.start_sector(block_idx, data.len());
        match self {
            Block::Raw => {
                out.copy_from_slice(block_sector::<SECTOR_SIZE>(data, rel_sector)?);
            }
            Block::PartDecrypted { has_hashes } => {
                out.copy_from_slice(block_sector::<SECTOR_SIZE>(data, rel_sector)?);
                if !has_hashes {
                    rebuild_hash_block(out, abs_sector, partition);
                }
                encrypt_sector(out, partition);
            }
            Block::Junk => {
                generate_junk(out, abs_sector, Some(partition), &partition.disc_header);
                rebuild_hash_block(out, abs_sector, partition);
                encrypt_sector(out, partition);
            }
            Block::Zero => {
                out.fill(0);
                rebuild_hash_block(out, abs_sector, partition);
                encrypt_sector(out, partition);
            }
        }
        Ok(())
    }

    pub(crate) fn copy_raw(
        self,
        out: &mut [u8; SECTOR_SIZE],
        data: &[u8],
        block_idx: u32,
        abs_sector: u32,
        disc_header: &DiscHeader,
    ) -> io::Result<()> {
        match self {
            Block::Raw => {
                out.copy_from_slice(block_sector::<SECTOR_SIZE>(
                    data,
                    abs_sector - self.start_sector(block_idx, data.len()),
                )?);
            }
            Block::PartDecrypted { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Cannot copy decrypted data as raw",
                ));
            }
            Block::Junk => generate_junk(out, abs_sector, None, disc_header),
            Block::Zero => out.fill(0),
        }
        Ok(())
    }

    /// Returns the start sector of the block.
    fn start_sector(&self, index: u32, block_size: usize) -> u32 {
        (index as u64 * block_size as u64 / SECTOR_SIZE as u64) as u32
    }
}

#[inline(always)]
fn block_sector<const N: usize>(data: &[u8], sector_idx: u32) -> io::Result<&[u8; N]> {
    if data.len() % N != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Expected block size {} to be a multiple of {}", data.len(), N),
        ));
    }
    let offset = sector_idx as usize * N;
    data.get(offset..offset + N)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Sector {} out of range (block size {}, sector size {})",
                    sector_idx,
                    data.len(),
                    N
                ),
            )
        })
        .map(|v| unsafe { &*(v as *const [u8] as *const [u8; N]) })
}

fn generate_junk(
    out: &mut [u8; SECTOR_SIZE],
    sector: u32,
    partition: Option<&BPartitionInfo>,
    disc_header: &DiscHeader,
) {
    let mut pos = if let Some(partition) = partition {
        (sector - partition.data_start_sector) as u64 * SECTOR_DATA_SIZE as u64
    } else {
        sector as u64 * SECTOR_SIZE as u64
    };
    let mut offset = if partition.is_some() { HASHES_SIZE } else { 0 };
    out[..offset].fill(0);
    while offset < SECTOR_SIZE {
        // The LFG spans a single sector of the decrypted data,
        // so we may need to initialize it multiple times
        let mut lfg = LaggedFibonacci::default();
        lfg.init_with_seed(*array_ref![disc_header.game_id, 0, 4], disc_header.disc_num, pos);
        let sector_end = (pos + SECTOR_SIZE as u64) & !(SECTOR_SIZE as u64 - 1);
        let len = min(SECTOR_SIZE - offset, (sector_end - pos) as usize);
        lfg.fill(&mut out[offset..offset + len]);
        pos += len as u64;
        offset += len;
    }
}

fn rebuild_hash_block(out: &mut [u8; SECTOR_SIZE], sector: u32, partition: &BPartitionInfo) {
    let Some(hash_table) = partition.hash_table.as_ref() else {
        return;
    };
    let sector_idx = (sector - partition.data_start_sector) as usize;
    let h0_hashes: &[u8; 0x26C] =
        transmute_ref!(array_ref![hash_table.h0_hashes, sector_idx * 31, 31]);
    out[0..0x26C].copy_from_slice(h0_hashes);
    let h1_hashes: &[u8; 0xA0] =
        transmute_ref!(array_ref![hash_table.h1_hashes, sector_idx & !7, 8]);
    out[0x280..0x320].copy_from_slice(h1_hashes);
    let h2_hashes: &[u8; 0xA0] =
        transmute_ref!(array_ref![hash_table.h2_hashes, (sector_idx / 8) & !7, 8]);
    out[0x340..0x3E0].copy_from_slice(h2_hashes);
}

fn encrypt_sector(out: &mut [u8; SECTOR_SIZE], partition: &BPartitionInfo) {
    aes_encrypt(&partition.key, [0u8; 16], &mut out[..HASHES_SIZE]);
    // Data IV from encrypted hash block
    let iv = *array_ref![out, 0x3D0, 16];
    aes_encrypt(&partition.key, iv, &mut out[HASHES_SIZE..]);
}

fn decrypt_sector(out: &mut [u8; SECTOR_SIZE], partition: &BPartitionInfo) {
    // Data IV from encrypted hash block
    let iv = *array_ref![out, 0x3D0, 16];
    aes_decrypt(&partition.key, [0u8; 16], &mut out[..HASHES_SIZE]);
    aes_decrypt(&partition.key, iv, &mut out[HASHES_SIZE..]);
}
