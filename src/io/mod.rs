//! Disc file format related logic (CISO, NFS, WBFS, WIA, etc.)

use std::{fs, fs::File, path::Path};

use crate::{
    streams::ReadStream, util::reader::read_from, Error, OpenOptions, Result, ResultContext,
};

pub(crate) mod ciso;
pub(crate) mod iso;
pub(crate) mod nfs;
pub(crate) mod nkit;
pub(crate) mod split;
pub(crate) mod wbfs;
pub(crate) mod wia;

/// SHA-1 hash bytes
pub(crate) type HashBytes = [u8; 20];

/// AES key bytes
pub(crate) type KeyBytes = [u8; 16];

/// Magic bytes
pub(crate) type MagicBytes = [u8; 4];

/// Abstraction over supported disc file formats.
pub trait DiscIO: Send + Sync {
    /// Opens a new read stream for the disc file(s).
    /// Generally does _not_ need to be used directly.
    fn open(&self) -> Result<Box<dyn ReadStream + '_>>;

    /// Returns extra metadata included in the disc file format, if any.
    fn meta(&self) -> Result<DiscMeta> { Ok(DiscMeta::default()) }

    /// If None, the file format does not store the original disc size. (e.g. WBFS, NFS)
    fn disc_size(&self) -> Option<u64>;
}

/// Extra metadata included in some disc file formats.
#[derive(Debug, Clone, Default)]
pub struct DiscMeta {
    pub crc32: Option<u32>,
    pub md5: Option<[u8; 16]>,
    pub sha1: Option<[u8; 20]>,
    pub xxhash64: Option<u64>,
}

/// Creates a new [`DiscIO`] instance.
pub fn open(filename: &Path, options: &OpenOptions) -> Result<Box<dyn DiscIO>> {
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
        ciso::CISO_MAGIC => Ok(Box::new(ciso::DiscIOCISO::new(path)?)),
        nfs::NFS_MAGIC => match path.parent() {
            Some(parent) if parent.is_dir() => {
                Ok(Box::new(nfs::DiscIONFS::new(path.parent().unwrap(), options)?))
            }
            _ => Err(Error::DiscFormat("Failed to locate NFS parent directory".to_string())),
        },
        wbfs::WBFS_MAGIC => Ok(Box::new(wbfs::DiscIOWBFS::new(path)?)),
        wia::WIA_MAGIC | wia::RVZ_MAGIC => Ok(Box::new(wia::DiscIOWIA::new(path, options)?)),
        _ => Ok(Box::new(iso::DiscIOISO::new(path)?)),
    }
}

/// Encrypts data in-place using AES-128-CBC with the given key and IV.
pub(crate) fn aes_encrypt(key: &KeyBytes, iv: KeyBytes, data: &mut [u8]) {
    use aes::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
    <cbc::Encryptor<aes::Aes128>>::new(key.into(), &aes::Block::from(iv))
        .encrypt_padded_mut::<NoPadding>(data, data.len())
        .unwrap(); // Safe: using NoPadding
}

/// Decrypts data in-place using AES-128-CBC with the given key and IV.
pub(crate) fn aes_decrypt(key: &KeyBytes, iv: KeyBytes, data: &mut [u8]) {
    use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
    <cbc::Decryptor<aes::Aes128>>::new(key.into(), &aes::Block::from(iv))
        .decrypt_padded_mut::<NoPadding>(data)
        .unwrap(); // Safe: using NoPadding
}
