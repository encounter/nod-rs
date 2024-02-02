use std::{
    cmp::min,
    fs::File,
    io,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use aes::{
    cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit},
    Aes128, Block,
};
use sha1::{Digest, Sha1};

use crate::{
    array_ref, array_ref_mut,
    disc::{
        wii::{BLOCK_SIZE, HASHES_SIZE},
        SECTOR_SIZE,
    },
    io::{DiscIO, DiscIOOptions},
    streams::ReadStream,
    util::{
        lfg::LaggedFibonacci,
        reader::{
            read_bytes, read_vec, struct_size, write_vec, FromReader, ToWriter, DYNAMIC_SIZE,
        },
        take_seek::TakeSeekExt,
    },
    Error, Result, ResultContext,
};

/// SHA-1 hash bytes
type HashBytes = [u8; 20];

/// AES key bytes
type KeyBytes = [u8; 16];

/// Magic bytes
type MagicBytes = [u8; 4];

/// AES-128-CBC encryptor
type Aes128Cbc = cbc::Encryptor<Aes128>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WIARVZMagic {
    Wia,
    Rvz,
}

impl FromReader for WIARVZMagic {
    type Args<'a> = ();

    const STATIC_SIZE: usize = MagicBytes::STATIC_SIZE;

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        match &MagicBytes::from_reader(reader)? {
            b"WIA\x01" => Ok(Self::Wia),
            b"RVZ\x01" => Ok(Self::Rvz),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid WIA/RVZ magic")),
        }
    }
}

impl ToWriter for WIARVZMagic {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        match self {
            Self::Wia => b"WIA\x01".to_writer(writer),
            Self::Rvz => b"RVZ\x01".to_writer(writer),
        }
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

/// This struct is stored at offset 0x0 and is 0x48 bytes long. The wit source code says its format
/// will never be changed.
#[derive(Clone, Debug)]
pub(crate) struct WIAFileHeader {
    pub(crate) magic: WIARVZMagic,
    /// The WIA format version.
    ///
    /// A short note from the wit source code about how version numbers are encoded:
    ///
    /// ```c
    /// //-----------------------------------------------------
    /// // Format of version number: AABBCCDD = A.BB | A.BB.CC
    /// // If D != 0x00 && D != 0xff => append: 'beta' D
    /// //-----------------------------------------------------
    /// ```
    pub(crate) version: u32,
    /// If the reading program supports the version of WIA indicated here, it can read the file.
    ///
    /// [version](Self::version) can be higher than `version_compatible`.
    pub(crate) version_compatible: u32,
    /// The size of the [WIADisc] struct.
    pub(crate) disc_size: u32,
    /// The SHA-1 hash of the [WIADisc] struct.
    ///
    /// The number of bytes to hash is determined by [disc_size](Self::disc_size).
    pub(crate) disc_hash: HashBytes,
    /// The original size of the ISO.
    pub(crate) iso_file_size: u64,
    /// The size of this file.
    pub(crate) wia_file_size: u64,
    /// The SHA-1 hash of this struct, up to but not including `file_head_hash` itself.
    pub(crate) file_head_hash: HashBytes,
}

impl FromReader for WIAFileHeader {
    type Args<'a> = ();

    const STATIC_SIZE: usize = struct_size([
        WIARVZMagic::STATIC_SIZE, // magic
        u32::STATIC_SIZE,         // version
        u32::STATIC_SIZE,         // version_compatible
        u32::STATIC_SIZE,         // disc_size
        HashBytes::STATIC_SIZE,   // disc_hash
        u64::STATIC_SIZE,         // iso_file_size
        u64::STATIC_SIZE,         // wia_file_size
        HashBytes::STATIC_SIZE,   // file_head_hash
    ]);

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        Ok(Self {
            magic: <_>::from_reader(reader)?,
            version: <_>::from_reader(reader)?,
            version_compatible: <_>::from_reader(reader)?,
            disc_size: <_>::from_reader(reader)?,
            disc_hash: <_>::from_reader(reader)?,
            iso_file_size: <_>::from_reader(reader)?,
            wia_file_size: <_>::from_reader(reader)?,
            file_head_hash: <_>::from_reader(reader)?,
        })
    }
}

impl ToWriter for WIAFileHeader {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        let mut buf = [0u8; Self::STATIC_SIZE - HashBytes::STATIC_SIZE];
        let mut out = buf.as_mut();
        self.magic.to_writer(&mut out)?;
        self.version.to_writer(&mut out)?;
        self.version_compatible.to_writer(&mut out)?;
        self.disc_size.to_writer(&mut out)?;
        self.disc_hash.to_writer(&mut out)?;
        self.iso_file_size.to_writer(&mut out)?;
        self.wia_file_size.to_writer(&mut out)?;
        buf.to_writer(writer)?;
        // Calculate and write the hash
        hash_bytes(&buf).to_writer(writer)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

/// Disc type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DiscType {
    /// GameCube disc
    GameCube = 1,
    /// Wii disc
    Wii = 2,
}

impl FromReader for DiscType {
    type Args<'a> = ();

    const STATIC_SIZE: usize = u32::STATIC_SIZE;

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        match u32::from_reader(reader)? {
            1 => Ok(Self::GameCube),
            2 => Ok(Self::Wii),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid disc type")),
        }
    }
}

impl ToWriter for DiscType {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        match self {
            Self::GameCube => 1u32.to_writer(writer),
            Self::Wii => 2u32.to_writer(writer),
        }
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

/// Compression type
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Compression {
    /// No compression.
    None = 0,
    /// (WIA only) See [WIASegment]
    Purge = 1,
    /// BZIP2 compression
    Bzip2 = 2,
    /// LZMA compression
    Lzma = 3,
    /// LZMA2 compression
    Lzma2 = 4,
    /// (RVZ only) Zstandard compression
    Zstandard = 5,
}

impl FromReader for Compression {
    type Args<'a> = ();

    const STATIC_SIZE: usize = u32::STATIC_SIZE;

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        match u32::from_reader(reader)? {
            0 => Ok(Self::None),
            1 => Ok(Self::Purge),
            2 => Ok(Self::Bzip2),
            3 => Ok(Self::Lzma),
            4 => Ok(Self::Lzma2),
            5 => Ok(Self::Zstandard),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid compression type")),
        }
    }
}

impl ToWriter for Compression {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        match self {
            Self::None => 0u32.to_writer(writer),
            Self::Purge => 1u32.to_writer(writer),
            Self::Bzip2 => 2u32.to_writer(writer),
            Self::Lzma => 3u32.to_writer(writer),
            Self::Lzma2 => 4u32.to_writer(writer),
            Self::Zstandard => 5u32.to_writer(writer),
        }
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

const DISC_HEAD_SIZE: usize = 0x80;

/// This struct is stored at offset 0x48, immediately after [WIAFileHeader].
#[derive(Clone, Debug)]
pub(crate) struct WIADisc {
    /// The disc type.
    pub(crate) disc_type: DiscType,
    /// The compression type.
    pub(crate) compression: Compression,
    /// The compression level used by the compressor.
    ///
    /// The possible values are compressor-specific.
    ///
    /// RVZ only:
    /// > This is signed (instead of unsigned) to support negative compression levels in
    ///   [Zstandard](Compression::Zstandard) (RVZ only).
    pub(crate) compression_level: i32,
    /// The size of the chunks that data is divided into.
    ///
    /// WIA only:
    /// > Must be a multiple of 2 MiB.
    ///
    /// RVZ only:
    /// > Chunk sizes smaller than 2 MiB are supported. The following applies when using a chunk size
    ///   smaller than 2 MiB:
    /// > - The chunk size must be at least 32 KiB and must be a power of two. (Just like with WIA,
    ///     sizes larger than 2 MiB do not have to be a power of two, they just have to be an integer
    ///     multiple of 2 MiB.)
    /// > - For Wii partition data, each chunk contains one [WIAExceptionList] which contains
    ///     exceptions for that chunk (and no other chunks). Offset 0 refers to the first hash of the
    ///     current chunk, not the first hash of the full 2 MiB of data.
    pub(crate) chunk_size: u32,
    /// The first 0x80 bytes of the disc image.
    pub(crate) disc_head: [u8; DISC_HEAD_SIZE],
    /// The number of [WIAPartition] structs.
    pub(crate) num_partitions: u32,
    /// The size of one [WIAPartition] struct.
    ///
    /// If this is smaller than the size of [WIAPartition], fill the missing bytes with 0x00.
    pub(crate) partition_type_size: u32,
    /// The offset in the file where the [WIAPartition] structs are stored (uncompressed).
    pub(crate) partition_offset: u64,
    /// The SHA-1 hash of the [WIAPartition] structs.
    ///
    /// The number of bytes to hash is determined by `num_partitions * partition_type_size`.
    pub(crate) partition_hash: HashBytes,
    /// The number of [WIARawData] structs.
    pub(crate) num_raw_data: u32,
    /// The offset in the file where the [WIARawData] structs are stored (compressed).
    pub(crate) raw_data_offset: u64,
    /// The total compressed size of the [WIARawData] structs.
    pub(crate) raw_data_size: u32,
    /// The number of [WIAGroup] structs.
    pub(crate) num_groups: u32,
    /// The offset in the file where the [WIAGroup] structs are stored (compressed).
    pub(crate) group_offset: u64,
    /// The total compressed size of the [WIAGroup] structs.
    pub(crate) group_size: u32,
    /// The number of used bytes in the [compr_data](Self::compr_data) array.
    pub(crate) compr_data_len: u8,
    /// Compressor specific data.
    ///
    /// If the compression method is [None](Compression::None), [Purge](Compression::Purge),
    /// [Bzip2](Compression::Bzip2), or [Zstandard](Compression::Zstandard) (RVZ only),
    /// [compr_data_len](Self::compr_data_len) is 0. If the compression method is
    /// [Lzma](Compression::Lzma) or [Lzma2](Compression::Lzma2), the compressor specific data is
    /// stored in the format used by the 7-Zip SDK. It needs to be converted if you are using e.g.
    /// liblzma.
    ///
    /// For [Lzma](Compression::Lzma), the data is 5 bytes long. The first byte encodes the `lc`,
    /// `pb`, and `lp` parameters, and the four other bytes encode the dictionary size in little
    /// endian.
    pub(crate) compr_data: [u8; 7],
}

impl FromReader for WIADisc {
    type Args<'a> = ();

    const STATIC_SIZE: usize = struct_size([
        DiscType::STATIC_SIZE,    // disc_type
        Compression::STATIC_SIZE, // compression
        i32::STATIC_SIZE,         // compression_level
        u32::STATIC_SIZE,         // chunk_size
        DISC_HEAD_SIZE,           // disc_head
        u32::STATIC_SIZE,         // num_partitions
        u32::STATIC_SIZE,         // partition_type_size
        u64::STATIC_SIZE,         // partition_offset
        HashBytes::STATIC_SIZE,   // partition_hash
        u32::STATIC_SIZE,         // num_raw_data
        u64::STATIC_SIZE,         // raw_data_offset
        u32::STATIC_SIZE,         // raw_data_size
        u32::STATIC_SIZE,         // num_groups
        u64::STATIC_SIZE,         // group_offset
        u32::STATIC_SIZE,         // group_size
        u8::STATIC_SIZE,          // compr_data_len
        <[u8; 7]>::STATIC_SIZE,   // compr_data
    ]);

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        Ok(Self {
            disc_type: <_>::from_reader(reader)?,
            compression: <_>::from_reader(reader)?,
            compression_level: <_>::from_reader(reader)?,
            chunk_size: <_>::from_reader(reader)?,
            disc_head: <_>::from_reader(reader)?,
            num_partitions: <_>::from_reader(reader)?,
            partition_type_size: <_>::from_reader(reader)?,
            partition_offset: <_>::from_reader(reader)?,
            partition_hash: <_>::from_reader(reader)?,
            num_raw_data: <_>::from_reader(reader)?,
            raw_data_offset: <_>::from_reader(reader)?,
            raw_data_size: <_>::from_reader(reader)?,
            num_groups: <_>::from_reader(reader)?,
            group_offset: <_>::from_reader(reader)?,
            group_size: <_>::from_reader(reader)?,
            compr_data_len: <_>::from_reader(reader)?,
            compr_data: <_>::from_reader(reader)?,
        })
    }
}

impl ToWriter for WIADisc {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        self.disc_type.to_writer(writer)?;
        self.compression.to_writer(writer)?;
        self.compression_level.to_writer(writer)?;
        self.chunk_size.to_writer(writer)?;
        self.disc_head.to_writer(writer)?;
        self.num_partitions.to_writer(writer)?;
        self.partition_type_size.to_writer(writer)?;
        self.partition_offset.to_writer(writer)?;
        self.partition_hash.to_writer(writer)?;
        self.num_raw_data.to_writer(writer)?;
        self.raw_data_offset.to_writer(writer)?;
        self.raw_data_size.to_writer(writer)?;
        self.num_groups.to_writer(writer)?;
        self.group_offset.to_writer(writer)?;
        self.group_size.to_writer(writer)?;
        self.compr_data_len.to_writer(writer)?;
        self.compr_data.to_writer(writer)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

#[derive(Clone, Debug)]
pub(crate) struct WIAPartitionData {
    /// The sector on the disc at which this data starts.
    /// One sector is 32 KiB (or 31 KiB excluding hashes).
    pub(crate) first_sector: u32,
    /// The number of sectors on the disc covered by this struct.
    /// One sector is 32 KiB (or 31 KiB excluding hashes).
    pub(crate) num_sectors: u32,
    /// The index of the first [WIAGroup] struct that points to the data covered by this struct.
    /// The other [WIAGroup] indices follow sequentially.
    pub(crate) group_index: u32,
    /// The number of [WIAGroup] structs used for this data.
    pub(crate) num_groups: u32,
}

impl FromReader for WIAPartitionData {
    type Args<'a> = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // first_sector
        u32::STATIC_SIZE, // num_sectors
        u32::STATIC_SIZE, // group_index
        u32::STATIC_SIZE, // num_groups
    ]);

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        Ok(Self {
            first_sector: <_>::from_reader(reader)?,
            num_sectors: <_>::from_reader(reader)?,
            group_index: <_>::from_reader(reader)?,
            num_groups: <_>::from_reader(reader)?,
        })
    }
}

impl ToWriter for WIAPartitionData {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        self.first_sector.to_writer(writer)?;
        self.num_sectors.to_writer(writer)?;
        self.group_index.to_writer(writer)?;
        self.num_groups.to_writer(writer)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

/// This struct is used for keeping track of Wii partition data that on the actual disc is encrypted
/// and hashed. This does not include the unencrypted area at the beginning of partitions that
/// contains the ticket, TMD, certificate chain, and H3 table. So for a typical game partition,
/// `pd[0].first_sector * 0x8000` would be 0x0F820000, not 0x0F800000.
///
/// Wii partition data is stored decrypted and with hashes removed. For each 0x8000 bytes on the
/// disc, 0x7C00 bytes are stored in the WIA file (prior to compression). If the hashes are desired,
/// the reading program must first recalculate the hashes as done when creating a Wii disc image
/// from scratch (see <https://wiibrew.org/wiki/Wii_Disc>), and must then apply the hash exceptions
/// which are stored along with the data (see the [WIAExceptionList] section).
#[derive(Clone, Debug)]
pub(crate) struct WIAPartition {
    /// The title key for this partition (128-bit AES), which can be used for re-encrypting the
    /// partition data.
    ///
    /// This key can be used directly, without decrypting it using the Wii common key.
    pub(crate) partition_key: KeyBytes,
    /// To quote the wit source code: `segment 0 is small and defined for management data (boot ..
    /// fst). segment 1 takes the remaining data.`
    ///
    /// The point at which wit splits the two segments is the FST end offset rounded up to the next
    /// 2 MiB. Giving the first segment a size which is not a multiple of 2 MiB is likely a bad idea
    /// (unless the second segment has a size of 0).
    pub(crate) partition_data: [WIAPartitionData; 2],
}

impl FromReader for WIAPartition {
    type Args<'a> = ();

    const STATIC_SIZE: usize = struct_size([
        KeyBytes::STATIC_SIZE,             // partition_key
        WIAPartitionData::STATIC_SIZE * 2, // partition_data
    ]);

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        Ok(Self {
            partition_key: <_>::from_reader(reader)?,
            partition_data: [<_>::from_reader(reader)?, <_>::from_reader(reader)?],
        })
    }
}

impl ToWriter for WIAPartition {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        self.partition_key.to_writer(writer)?;
        self.partition_data[0].to_writer(writer)?;
        self.partition_data[1].to_writer(writer)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

/// This struct is used for keeping track of disc data that is not stored as [WIAPartition].
/// The data is stored as is (other than compression being applied).
///
/// The first [WIARawData] has `raw_data_offset` set to 0x80 and `raw_data_size` set to 0x4FF80,
/// but despite this, it actually contains 0x50000 bytes of data. (However, the first 0x80 bytes
/// should be read from [WIADisc] instead.) This should be handled by rounding the offset down to
/// the previous multiple of 0x8000 (and adding the equivalent amount to the size so that the end
/// offset stays the same), not by special casing the first [WIARawData].
#[derive(Clone, Debug)]
pub(crate) struct WIARawData {
    /// The offset on the disc at which this data starts.
    pub(crate) raw_data_offset: u64,
    /// The number of bytes on the disc covered by this struct.
    pub(crate) raw_data_size: u64,
    /// The index of the first [WIAGroup] struct that points to the data covered by this struct.
    /// The other [WIAGroup] indices follow sequentially.
    pub(crate) group_index: u32,
    /// The number of [WIAGroup] structs used for this data.
    pub(crate) num_groups: u32,
}

impl FromReader for WIARawData {
    type Args<'a> = ();

    const STATIC_SIZE: usize = struct_size([
        u64::STATIC_SIZE, // raw_data_offset
        u64::STATIC_SIZE, // raw_data_size
        u32::STATIC_SIZE, // group_index
        u32::STATIC_SIZE, // num_groups
    ]);

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        Ok(Self {
            raw_data_offset: <_>::from_reader(reader)?,
            raw_data_size: <_>::from_reader(reader)?,
            group_index: <_>::from_reader(reader)?,
            num_groups: <_>::from_reader(reader)?,
        })
    }
}

impl ToWriter for WIARawData {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        self.raw_data_offset.to_writer(writer)?;
        self.raw_data_size.to_writer(writer)?;
        self.group_index.to_writer(writer)?;
        self.num_groups.to_writer(writer)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

/// This struct points directly to the actual disc data, stored compressed.
///
/// The data is interpreted differently depending on whether the [WIAGroup] is referenced by a
/// [WIAPartitionData] or a [WIARawData] (see the [WIAPartition] section for details).
///
/// A [WIAGroup] normally contains chunk_size bytes of decompressed data
/// (or `chunk_size / 0x8000 * 0x7C00` for Wii partition data when not counting hashes), not
/// counting any [WIAExceptionList] structs. However, the last [WIAGroup] of a [WIAPartitionData]
/// or [WIARawData] contains less data than that if `num_sectors * 0x8000` (for [WIAPartitionData])
/// or `raw_data_size` (for [WIARawData]) is not evenly divisible by `chunk_size`.
#[derive(Clone, Debug)]
pub(crate) struct WIAGroup {
    /// The offset in the file where the compressed data is stored.
    ///
    /// Stored as a `u32`, divided by 4.
    pub(crate) data_offset: u32,
    /// The size of the compressed data, including any [WIAExceptionList] structs. 0 is a special
    /// case meaning that every byte of the decompressed data is 0x00 and the [WIAExceptionList]
    /// structs (if there are supposed to be any) contain 0 exceptions.
    pub(crate) data_size: u32,
}

impl FromReader for WIAGroup {
    type Args<'a> = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // data_offset
        u32::STATIC_SIZE, // data_size
    ]);

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        Ok(Self { data_offset: <_>::from_reader(reader)?, data_size: <_>::from_reader(reader)? })
    }
}

impl ToWriter for WIAGroup {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        self.data_offset.to_writer(writer)?;
        self.data_size.to_writer(writer)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

/// Compared to [WIAGroup], [RVZGroup] changes the meaning of the most significant bit of
/// [data_size](Self::data_size) and adds one additional attribute.
#[derive(Clone, Debug)]
pub(crate) struct RVZGroup {
    /// The offset in the file where the compressed data is stored, divided by 4.
    pub(crate) data_offset: u32,
    /// The most significant bit is 1 if the data is compressed using the compression method
    /// indicated in [WIADisc], and 0 if it is not compressed. The lower 31 bits are the size of
    /// the compressed data, including any [WIAExceptionList] structs. The lower 31 bits being 0 is
    /// a special case meaning that every byte of the decompressed and unpacked data is 0x00 and
    /// the [WIAExceptionList] structs (if there are supposed to be any) contain 0 exceptions.
    pub(crate) data_size: u32,
    /// The size after decompressing but before decoding the RVZ packing.
    /// If this is 0, RVZ packing is not used for this group.
    pub(crate) rvz_packed_size: u32,
    /// Extracted from the most significant bit of [data_size](Self::data_size).
    pub(crate) is_compressed: bool,
}

impl FromReader for RVZGroup {
    type Args<'a> = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // data_offset
        u32::STATIC_SIZE, // data_size
        u32::STATIC_SIZE, // rvz_packed_size
    ]);

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        let data_offset = u32::from_reader(reader)?;
        let size_and_flag = u32::from_reader(reader)?;
        let rvz_packed_size = u32::from_reader(reader)?;
        Ok(Self {
            data_offset,
            data_size: size_and_flag & 0x7FFFFFFF,
            rvz_packed_size,
            is_compressed: size_and_flag & 0x80000000 != 0,
        })
    }
}

impl ToWriter for RVZGroup {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        self.data_offset.to_writer(writer)?;
        (self.data_size | (self.is_compressed as u32) << 31).to_writer(writer)?;
        self.rvz_packed_size.to_writer(writer)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

impl From<WIAGroup> for RVZGroup {
    fn from(value: WIAGroup) -> Self {
        Self {
            data_offset: value.data_offset,
            data_size: value.data_size,
            rvz_packed_size: 0,
            is_compressed: true,
        }
    }
}

/// This struct represents a 20-byte difference between the recalculated hash data and the original
/// hash data. (See also [WIAExceptionList])
///
/// When recalculating hashes for a [WIAGroup] with a size which is not evenly divisible by 2 MiB
/// (with the size of the hashes included), the missing bytes should be treated as zeroes for the
/// purpose of hashing. (wit's writing code seems to act as if the reading code does not assume that
/// these missing bytes are zero, but both wit's and Dolphin's reading code treat them as zero.
/// Dolphin's writing code assumes that the reading code treats them as zero.)
///
/// wit's writing code only outputs [WIAException] structs for mismatches in the actual hash
/// data, not in the padding data (which normally only contains zeroes). Dolphin's writing code
/// outputs [WIAException] structs for both hash data and padding data. When Dolphin needs to
/// write [WIAException] structs for a padding area which is 32 bytes long, it writes one which
/// covers the first 20 bytes of the padding area and one which covers the last 20 bytes of the
/// padding area, generating 12 bytes of overlap between the [WIAException] structs.
#[derive(Clone, Debug)]
pub(crate) struct WIAException {
    /// The offset among the hashes. The offsets 0x0000-0x0400 here map to the offsets 0x0000-0x0400
    /// in the full 2 MiB of data, the offsets 0x0400-0x0800 here map to the offsets 0x8000-0x8400
    /// in the full 2 MiB of data, and so on.
    ///
    /// The offsets start over at 0 for each new [WIAExceptionList].
    pub(crate) offset: u16,
    /// The hash that the automatically generated hash at the given offset needs to be replaced
    /// with.
    ///
    /// The replacement should happen after calculating all hashes for the current 2 MiB of data
    /// but before encrypting the hashes.
    pub(crate) hash: HashBytes,
}

impl FromReader for WIAException {
    type Args<'a> = ();

    const STATIC_SIZE: usize = struct_size([
        u16::STATIC_SIZE,       // offset
        HashBytes::STATIC_SIZE, // hash
    ]);

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        Ok(Self { offset: <_>::from_reader(reader)?, hash: <_>::from_reader(reader)? })
    }
}

impl ToWriter for WIAException {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        self.offset.to_writer(writer)?;
        self.hash.to_writer(writer)?;
        Ok(())
    }

    fn write_size(&self) -> usize { Self::STATIC_SIZE }
}

/// Each [WIAGroup] of Wii partition data contains one or more [WIAExceptionList] structs before
/// the actual data, one for each 2 MiB of data in the [WIAGroup]. The number of [WIAExceptionList]
/// structs per [WIAGroup] is always `chunk_size / 0x200000`, even for a [WIAGroup] which contains
/// less data than normal due to it being at the end of a partition.
///
/// For memory management reasons, programs which read WIA files might place a limit on how many
/// exceptions there can be in a [WIAExceptionList]. Dolphin's reading code has a limit of
/// `52 × 64 = 3328` (unless the compression method is [None](Compression::None) or
/// [Purge](Compression::Purge), in which case there is no limit), which is enough to cover all
/// hashes and all padding. wit's reading code seems to be written as if `47 × 64 = 3008` is the
/// maximum it needs to be able to handle, which is enough to cover all hashes but not any padding.
/// However, because wit allocates more memory than needed, it seems to be possible to exceed 3008
/// by some amount without problems. It should be safe for writing code to assume that reading code
/// can handle at least 3328 exceptions per [WIAExceptionList].
///
/// Somewhat ironically, there are exceptions to how [WIAExceptionList] structs are handled:
///
/// For the compression method [Purge](Compression::Purge), the [WIAExceptionList] structs are
/// stored uncompressed (in other words, before the first [WIASegment]). For
/// [Bzip2](Compression::Bzip2), [Lzma](Compression::Lzma) and [Lzma2](Compression::Lzma2), they are
/// compressed along with the rest of the data.
///
/// For the compression methods [None](Compression::None) and [Purge](Compression::Purge), if the
/// end offset of the last [WIAExceptionList] is not evenly divisible by 4, padding is inserted
/// after it so that the data afterwards will start at a 4 byte boundary. This padding is not
/// inserted for the other compression methods.
#[derive(Clone, Debug)]
pub(crate) struct WIAExceptionList {
    /// Each [WIAException] describes one difference between the hashes obtained by hashing the
    /// partition data and the original hashes.
    pub(crate) exceptions: Vec<WIAException>,
}

impl FromReader for WIAExceptionList {
    type Args<'a> = ();

    const STATIC_SIZE: usize = DYNAMIC_SIZE;

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        let num_exceptions = u16::from_reader(reader)?;
        let exceptions = read_vec(reader, num_exceptions as usize)?;
        Ok(Self { exceptions })
    }
}

impl ToWriter for WIAExceptionList {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        (self.exceptions.len() as u16).to_writer(writer)?;
        write_vec(writer, &self.exceptions)?;
        Ok(())
    }

    fn write_size(&self) -> usize {
        u16::STATIC_SIZE + self.exceptions.len() * WIAException::STATIC_SIZE
    }
}

/// This struct is used by the simple compression method [Purge](Compression::Purge), which stores
/// runs of zeroes efficiently and stores other data as is.
///
/// Each [Purge](Compression::Purge) chunk contains zero or more [WIASegment] structs stored in
/// order of ascending offset, followed by a SHA-1 hash (0x14 bytes) of the [WIAExceptionList]
/// structs (if any) and the [WIASegment] structs. Bytes in the decompressed data that are not
/// covered by any [WIASegment] struct are set to 0x00.
#[derive(Clone, Debug)]
pub(crate) struct WIASegment {
    /// The offset of data within the decompressed data.
    ///
    /// Any [WIAExceptionList] structs are not counted as part of the decompressed data.
    pub(crate) offset: u32,
    /// The data.
    pub(crate) data: Vec<u8>,
}

impl FromReader for WIASegment {
    type Args<'a> = ();

    const STATIC_SIZE: usize = DYNAMIC_SIZE;

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        let offset = u32::from_reader(reader)?;
        let size = u32::from_reader(reader)?;
        let data = read_bytes(reader, size as usize)?;
        Ok(Self { offset, data })
    }
}

impl ToWriter for WIASegment {
    fn to_writer<W>(&self, writer: &mut W) -> io::Result<()>
    where W: Write + ?Sized {
        self.offset.to_writer(writer)?;
        (self.data.len() as u32).to_writer(writer)?;
        self.data.to_writer(writer)?;
        Ok(())
    }

    fn write_size(&self) -> usize { u32::STATIC_SIZE * 2 + self.data.len() }
}

pub(crate) enum Decompressor {
    None,
    // Purge,
    #[cfg(feature = "compress-bzip2")]
    Bzip2,
    // Lzma,
    // Lzma2,
    #[cfg(feature = "compress-zstd")]
    Zstandard,
}

impl Decompressor {
    pub(crate) fn new(disc: &WIADisc) -> Result<Self> {
        match disc.compression {
            Compression::None => Ok(Self::None),
            // Compression::Purge => Ok(Self::Purge),
            #[cfg(feature = "compress-bzip2")]
            Compression::Bzip2 => Ok(Self::Bzip2),
            // Compression::Lzma => Ok(Self::Lzma),
            // Compression::Lzma2 => Ok(Self::Lzma2),
            #[cfg(feature = "compress-zstd")]
            Compression::Zstandard => Ok(Self::Zstandard),
            comp => Err(Error::DiscFormat(format!("Unsupported WIA/RVZ compression: {:?}", comp))),
        }
    }

    pub(crate) fn wrap<'a, R>(&mut self, reader: R) -> Result<Box<dyn Read + 'a>>
    where R: Read + 'a {
        Ok(match self {
            Decompressor::None => Box::new(reader),
            #[cfg(feature = "compress-bzip2")]
            Decompressor::Bzip2 => Box::new(bzip2::read::BzDecoder::new(reader)),
            #[cfg(feature = "compress-zstd")]
            Decompressor::Zstandard => {
                Box::new(zstd::stream::Decoder::new(reader).context("Creating zstd decoder")?)
            }
        })
    }
}

/// In a sector, following the 0x400 byte block of hashes, each 0x400 bytes of decrypted data is
/// hashed, yielding 31 H0 hashes.
/// Then, 8 sectors are aggregated into a subgroup, and the 31 H0 hashes for each sector are hashed,
/// yielding 8 H1 hashes.
/// Then, 8 subgroups are aggregated into a group, and the 8 H1 hashes for each subgroup are hashed,
/// yielding 8 H2 hashes.
/// Finally, the 8 H2 hashes for each group are hashed, yielding 1 H3 hash.
/// The H3 hashes for each group are stored in the partition's H3 table.
pub(crate) struct HashTable {
    /// SHA-1 hash of the 31 H0 hashes for each sector.
    pub(crate) h1_hashes: Vec<HashBytes>,
    /// SHA-1 hash of the 8 H1 hashes for each subgroup.
    pub(crate) h2_hashes: Vec<HashBytes>,
    /// SHA-1 hash of the 8 H2 hashes for each group.
    pub(crate) h3_hashes: Vec<HashBytes>,
}

pub(crate) struct DiscIOWIA {
    pub(crate) header: WIAFileHeader,
    pub(crate) disc: WIADisc,
    pub(crate) partitions: Vec<WIAPartition>,
    pub(crate) raw_data: Vec<WIARawData>,
    pub(crate) groups: Vec<RVZGroup>,
    pub(crate) filename: PathBuf,
    pub(crate) encrypt: bool,
    pub(crate) hash_tables: Vec<HashTable>,
}

/// Wraps a buffer, reading zeros for any extra bytes.
struct SizedRead<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SizedRead<'a> {
    fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }
}

impl Read for SizedRead<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let written = if self.pos < self.buf.len() {
            let to_read = min(buf.len(), self.buf.len() - self.pos);
            buf[..to_read].copy_from_slice(&self.buf[self.pos..self.pos + to_read]);
            to_read
        } else {
            0
        };
        buf[written..].fill(0);
        self.pos += buf.len();
        Ok(buf.len())
    }
}

impl Seek for SizedRead<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(pos) => self.pos = pos as usize,
            SeekFrom::Current(pos) => self.pos = (self.pos as i64 + pos) as usize,
            SeekFrom::End(_) => unimplemented!(),
        }
        Ok(self.pos as u64)
    }

    fn stream_position(&mut self) -> io::Result<u64> { Ok(self.pos as u64) }
}

#[derive(Debug)]
struct GroupResult {
    /// Offset of the group in the raw disc image.
    disc_offset: u64,
    /// Data offset of the group within a partition, excluding hashes.
    /// Same as `disc_offset` for raw data or GameCube discs.
    partition_offset: u64,
    /// The group.
    group: RVZGroup,
    /// The index of the Wii partition that this group belongs to.
    partition_index: Option<usize>,
    /// Chunk size, differs between Wii and raw data.
    chunk_size: u32,
    /// End offset for the partition or raw data.
    partition_end: u64,
}

#[inline]
fn hash_bytes(buf: &[u8]) -> HashBytes {
    let mut hasher = Sha1::new();
    hasher.update(buf);
    hasher.finalize().into()
}

fn verify_hash(buf: &[u8], expected: &HashBytes) -> Result<()> {
    let out = hash_bytes(buf);
    if out != *expected {
        let mut got_bytes = [0u8; 40];
        let got = base16ct::lower::encode_str(&out, &mut got_bytes)?;
        let mut expected_bytes = [0u8; 40];
        let expected = base16ct::lower::encode_str(expected, &mut expected_bytes)?;
        return Err(Error::DiscFormat(format!(
            "WIA hash mismatch: {}, expected {}",
            got, expected
        )));
    }
    Ok(())
}

impl DiscIOWIA {
    pub(crate) fn new(filename: &Path, options: &DiscIOOptions) -> Result<Self> {
        let mut file = BufReader::new(
            File::open(filename).with_context(|| format!("Opening file {}", filename.display()))?,
        );

        // Load & verify file header
        let header_buf = <[u8; WIAFileHeader::STATIC_SIZE]>::from_reader(&mut file)
            .context("Reading WIA/RVZ file header")?;
        let header = WIAFileHeader::from_reader(&mut header_buf.as_slice())
            .context("Parsing WIA/RVZ file header")?;
        verify_hash(
            &header_buf[..WIAFileHeader::STATIC_SIZE - HashBytes::STATIC_SIZE],
            &header.file_head_hash,
        )?;
        if header.version_compatible < 0x30000 {
            return Err(Error::DiscFormat(format!(
                "WIA/RVZ version {:#X} is not supported",
                header.version_compatible
            )));
        }
        let is_rvz = header.magic == WIARVZMagic::Rvz;
        // println!("Header: {:?}", header);

        // Load & verify disc header
        let disc_buf = read_bytes(&mut file, header.disc_size as usize)
            .context("Reading WIA/RVZ disc header")?;
        verify_hash(&disc_buf, &header.disc_hash)?;
        let disc = WIADisc::from_reader(&mut SizedRead::new(&disc_buf))
            .context("Parsing WIA/RVZ disc header")?;
        // println!("Disc: {:?}", disc);
        if disc.partition_type_size != WIAPartition::STATIC_SIZE as u32 {
            return Err(Error::DiscFormat(format!(
                "WIA partition type size is {}, expected {}",
                disc.partition_type_size,
                WIAPartition::STATIC_SIZE
            )));
        }

        // Load & verify partition headers
        file.seek(SeekFrom::Start(disc.partition_offset))
            .context("Seeking to WIA/RVZ partition headers")?;
        let partition_buf =
            read_bytes(&mut file, disc.partition_type_size as usize * disc.num_partitions as usize)
                .context("Reading WIA/RVZ partition headers")?;
        verify_hash(&partition_buf, &disc.partition_hash)?;
        let partitions = read_vec(&mut partition_buf.as_slice(), disc.num_partitions as usize)
            .context("Parsing WIA/RVZ partition headers")?;
        // println!("Partitions: {:?}", partitions);

        // Create decompressor
        let mut decompressor = Decompressor::new(&disc)?;

        // Load raw data headers
        let raw_data = {
            file.seek(SeekFrom::Start(disc.raw_data_offset))
                .context("Seeking to WIA/RVZ raw data headers")?;
            let mut reader = decompressor.wrap((&mut file).take(disc.raw_data_size as u64))?;
            read_vec(&mut reader, disc.num_raw_data as usize)
                .context("Reading WIA/RVZ raw data headers")?
            // println!("Raw data: {:?}", raw_data);
        };

        // Load group headers
        let mut groups = Vec::with_capacity(disc.num_groups as usize);
        {
            file.seek(SeekFrom::Start(disc.group_offset))
                .context("Seeking to WIA/RVZ group headers")?;
            let mut reader = decompressor.wrap((&mut file).take(disc.group_size as u64))?;
            let bytes = read_bytes(
                &mut reader,
                disc.num_groups as usize
                    * if is_rvz { RVZGroup::STATIC_SIZE } else { WIAGroup::STATIC_SIZE },
            )
            .context("Reading WIA/RVZ group headers")?;
            let mut slice = bytes.as_slice();
            for i in 0..disc.num_groups {
                if is_rvz {
                    groups.push(
                        RVZGroup::from_reader(&mut slice)
                            .with_context(|| format!("Parsing RVZ group header {}", i))?,
                    );
                } else {
                    groups.push(
                        WIAGroup::from_reader(&mut slice)
                            .with_context(|| format!("Parsing WIA group header {}", i))?
                            .into(),
                    );
                }
            }
            // println!("Groups: {:?}", groups);
        }

        let mut disc_io = Self {
            header,
            disc,
            partitions,
            raw_data,
            groups,
            filename: filename.to_owned(),
            encrypt: options.rebuild_hashes,
            hash_tables: vec![],
        };
        if options.rebuild_hashes {
            disc_io.rebuild_hashes()?;
        }
        Ok(disc_io)
    }

    fn group_for_offset(&self, offset: u64) -> Option<GroupResult> {
        if let Some((p_idx, pd)) = self.partitions.iter().enumerate().find_map(|(p_idx, p)| {
            p.partition_data
                .iter()
                .find(|pd| {
                    let start = pd.first_sector as u64 * SECTOR_SIZE as u64;
                    let end = start + pd.num_sectors as u64 * SECTOR_SIZE as u64;
                    offset >= start && offset < end
                })
                .map(|pd| (p_idx, pd))
        }) {
            let start = pd.first_sector as u64 * SECTOR_SIZE as u64;
            let group_index = (offset - start) / self.disc.chunk_size as u64;
            if group_index >= pd.num_groups as u64 {
                return None;
            }
            let disc_offset = start + group_index * self.disc.chunk_size as u64;
            let chunk_size = (self.disc.chunk_size as u64 * BLOCK_SIZE as u64) / SECTOR_SIZE as u64;
            let partition_offset = group_index * chunk_size;
            let partition_end = pd.num_sectors as u64 * BLOCK_SIZE as u64;
            self.groups.get(pd.group_index as usize + group_index as usize).map(|g| GroupResult {
                disc_offset,
                partition_offset,
                group: g.clone(),
                partition_index: Some(p_idx),
                chunk_size: chunk_size as u32,
                partition_end,
            })
        } else if let Some(d) = self.raw_data.iter().find(|d| {
            let start = d.raw_data_offset & !0x7FFF;
            let end = d.raw_data_offset + d.raw_data_size;
            offset >= start && offset < end
        }) {
            let start = d.raw_data_offset & !0x7FFF;
            let end = d.raw_data_offset + d.raw_data_size;
            let group_index = (offset - start) / self.disc.chunk_size as u64;
            if group_index >= d.num_groups as u64 {
                return None;
            }
            let disc_offset = start + group_index * self.disc.chunk_size as u64;
            self.groups.get(d.group_index as usize + group_index as usize).map(|g| GroupResult {
                disc_offset,
                partition_offset: disc_offset,
                group: g.clone(),
                partition_index: None,
                chunk_size: self.disc.chunk_size,
                partition_end: end,
            })
        } else {
            None
        }
    }

    pub(crate) fn rebuild_hashes(&mut self) -> Result<()> {
        const NUM_H0_HASHES: usize = BLOCK_SIZE / HASHES_SIZE;
        const H0_HASHES_SIZE: usize = HashBytes::STATIC_SIZE * NUM_H0_HASHES;

        // Precompute hashes for zeroed sectors.
        let zero_h0_hash = hash_bytes(&[0u8; HASHES_SIZE]);
        let mut zero_h1_hash = Sha1::new();
        for _ in 0..NUM_H0_HASHES {
            zero_h1_hash.update(zero_h0_hash);
        }
        let zero_h1_hash: HashBytes = zero_h1_hash.finalize().into();

        let mut hash_tables = Vec::with_capacity(self.partitions.len());
        let mut stream =
            WIAReadStream::new(self, 0, false).context("Creating WIA/RVZ read stream")?;
        for part in &self.partitions {
            let first_sector = part.partition_data[0].first_sector;
            if first_sector + part.partition_data[0].num_sectors
                != part.partition_data[1].first_sector
            {
                return Err(Error::DiscFormat(format!(
                    "Partition data is not contiguous: {}..{} != {}",
                    first_sector,
                    first_sector + part.partition_data[0].num_sectors,
                    part.partition_data[1].first_sector
                )));
            }
            let part_sectors =
                part.partition_data[0].num_sectors + part.partition_data[1].num_sectors;

            let num_sectors = part_sectors.next_multiple_of(64) as usize;
            let num_subgroups = num_sectors / 8;
            let num_groups = num_subgroups / 8;
            println!(
                "Rebuilding hashes: {} sectors, {} subgroups, {} groups",
                num_sectors, num_subgroups, num_groups
            );

            let mut hash_table = HashTable {
                h1_hashes: vec![HashBytes::default(); num_sectors],
                h2_hashes: vec![HashBytes::default(); num_subgroups],
                h3_hashes: vec![HashBytes::default(); num_groups],
            };
            let mut h0_buf = [0u8; H0_HASHES_SIZE];
            for h3_index in 0..num_groups {
                let mut h3_hasher = Sha1::new();
                for h2_index in h3_index * 8..h3_index * 8 + 8 {
                    let mut h2_hasher = Sha1::new();
                    for h1_index in h2_index * 8..h2_index * 8 + 8 {
                        let h1_hash = if h1_index >= part_sectors as usize {
                            zero_h1_hash
                        } else {
                            let sector = first_sector + h1_index as u32;
                            stream
                                .seek(SeekFrom::Start(sector as u64 * SECTOR_SIZE as u64))
                                .with_context(|| format!("Seeking to sector {}", sector))?;
                            stream
                                .read_exact(&mut h0_buf)
                                .with_context(|| format!("Reading sector {}", sector))?;
                            hash_bytes(&h0_buf)
                        };
                        hash_table.h1_hashes[h1_index] = h1_hash;
                        h2_hasher.update(h1_hash);
                    }
                    let h2_hash = h2_hasher.finalize().into();
                    hash_table.h2_hashes[h2_index] = h2_hash;
                    h3_hasher.update(h2_hash);
                }
                hash_table.h3_hashes[h3_index] = h3_hasher.finalize().into();
            }

            hash_tables.push(hash_table);
        }
        self.hash_tables = hash_tables;
        Ok(())
    }
}

impl DiscIO for DiscIOWIA {
    fn begin_read_stream(&mut self, offset: u64) -> io::Result<Box<dyn ReadStream + '_>> {
        Ok(Box::new(WIAReadStream::new(self, offset, self.encrypt)?))
    }

    fn has_wii_crypto(&self) -> bool { self.encrypt && self.disc.disc_type == DiscType::Wii }
}

pub(crate) struct WIAReadStream<'a> {
    /// The disc IO.
    disc_io: &'a DiscIOWIA,
    /// The currently open file handle.
    file: BufReader<File>,
    /// The data read offset.
    offset: u64,
    /// The data offset of the current group.
    group_offset: u64,
    /// The current group data.
    group_data: Vec<u8>,
    /// Exception lists for the current group.
    exception_lists: Vec<WIAExceptionList>,
    /// The decompressor data.
    decompressor: Decompressor,
    /// Whether to re-encrypt Wii partition data.
    encrypt: bool,
}

fn read_exception_lists<R>(
    reader: &mut R,
    partition_index: Option<usize>,
    chunk_size: u32,
) -> io::Result<Vec<WIAExceptionList>>
where
    R: Read + ?Sized,
{
    if partition_index.is_none() {
        return Ok(vec![]);
    }

    let num_exception_list = (chunk_size as usize).div_ceil(0x200000);
    // println!("Num exception list: {:?}", num_exception_list);
    let exception_lists = read_vec::<WIAExceptionList, _>(reader, num_exception_list)?;
    for list in &exception_lists {
        if !list.exceptions.is_empty() {
            println!("Exception list: {:?}", list);
        }
    }
    Ok(exception_lists)
}

impl<'a> WIAReadStream<'a> {
    pub(crate) fn new(disc_io: &'a DiscIOWIA, offset: u64, encrypt: bool) -> io::Result<Self> {
        let result = match disc_io.group_for_offset(offset) {
            Some(v) => v,
            None => return Err(io::Error::from(io::ErrorKind::InvalidInput)),
        };
        let file = BufReader::new(File::open(&disc_io.filename)?);
        let decompressor = Decompressor::new(&disc_io.disc)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut stream = Self {
            disc_io,
            file,
            offset,
            group_offset: result.disc_offset,
            group_data: Vec::new(),
            exception_lists: vec![],
            decompressor,
            encrypt,
        };
        stream.read_group(result)?; // Initialize group data
        Ok(stream)
    }

    /// If the current group does not contain the current offset, load the new group.
    /// Returns false if the offset is not in the disc.
    fn check_group(&mut self) -> io::Result<bool> {
        if self.offset < self.group_offset
            || self.offset >= self.group_offset + self.group_data.len() as u64
        {
            let Some(result) = self.disc_io.group_for_offset(self.offset) else {
                return Ok(false);
            };
            if result.disc_offset == self.group_offset {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Group offset did not change",
                ));
            }
            self.group_offset = result.disc_offset;
            self.read_group(result)?;
        }
        Ok(true)
    }

    /// Reads new group data into the buffer, handling decompression and RVZ packing.
    fn read_group(&mut self, result: GroupResult) -> io::Result<()> {
        // Special case for all-zero data
        if result.group.data_size == 0 {
            self.exception_lists.clear();
            let size = min(result.chunk_size as u64, result.partition_end - result.partition_offset)
                as usize;
            self.group_data = vec![0u8; size];
            self.recalculate_hashes(result)?;
            return Ok(());
        }

        self.group_data = Vec::with_capacity(result.chunk_size as usize);
        let group_data_start = result.group.data_offset as u64 * 4;
        self.file.seek(SeekFrom::Start(group_data_start))?;

        let mut reader = (&mut self.file).take_seek(result.group.data_size as u64);
        let uncompressed_exception_lists =
            matches!(self.disc_io.disc.compression, Compression::None | Compression::Purge)
                || !result.group.is_compressed;
        if uncompressed_exception_lists {
            self.exception_lists = read_exception_lists(
                &mut reader,
                result.partition_index,
                self.disc_io.disc.chunk_size, // result.chunk_size?
            )?;
            // Align to 4
            let rem = reader.stream_position()? % 4;
            if rem != 0 {
                reader.seek(SeekFrom::Current((4 - rem) as i64))?;
            }
        }
        let mut reader: Box<dyn Read> =
            if result.group.is_compressed && self.disc_io.disc.compression != Compression::None {
                self.decompressor
                    .wrap(reader)
                    .map_err(|v| io::Error::new(io::ErrorKind::InvalidData, v))?
            } else {
                Box::new(reader)
            };
        if !uncompressed_exception_lists {
            self.exception_lists = read_exception_lists(
                reader.as_mut(),
                result.partition_index,
                self.disc_io.disc.chunk_size, // result.chunk_size?
            )?;
        }

        if result.group.rvz_packed_size > 0 {
            // Decode RVZ packed data
            let mut lfg = LaggedFibonacci::default();
            loop {
                let mut size_bytes = [0u8; 4];
                let read = reader.read(&mut size_bytes)?;
                if read == 0 {
                    break;
                } else if read < 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Failed to read RVZ packed size",
                    ));
                }
                let size = u32::from_be_bytes(size_bytes);
                let cur_data_len = self.group_data.len();
                if size & 0x80000000 != 0 {
                    // Junk data
                    let size = size & 0x7FFFFFFF;
                    lfg.init_with_reader(reader.as_mut())?;
                    lfg.skip(
                        ((result.partition_offset + cur_data_len as u64) % SECTOR_SIZE as u64)
                            as usize,
                    );
                    self.group_data.resize(cur_data_len + size as usize, 0);
                    lfg.fill(&mut self.group_data[cur_data_len..]);
                } else {
                    // Real data
                    self.group_data.resize(cur_data_len + size as usize, 0);
                    reader.read_exact(&mut self.group_data[cur_data_len..])?;
                }
            }
        } else {
            // Read and decompress data
            reader.read_to_end(&mut self.group_data)?;
        }

        drop(reader);
        self.recalculate_hashes(result)?;
        Ok(())
    }

    fn recalculate_hashes(&mut self, result: GroupResult) -> io::Result<()> {
        let Some(partition_index) = result.partition_index else {
            // Data not inside of a Wii partition
            return Ok(());
        };
        let hash_table = self.disc_io.hash_tables.get(partition_index);

        if self.group_data.len() % BLOCK_SIZE != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid group data size: {:#X}", self.group_data.len()),
            ));
        }

        // WIA/RVZ excludes the hash data for each sector, instead storing all data contiguously.
        // We need to add space for the hash data, and then recalculate the hashes.
        let num_sectors = self.group_data.len() / BLOCK_SIZE;
        let mut out = vec![0u8; num_sectors * SECTOR_SIZE];
        for i in 0..num_sectors {
            let data = array_ref![self.group_data, i * BLOCK_SIZE, BLOCK_SIZE];
            let out = array_ref_mut![out, i * SECTOR_SIZE, SECTOR_SIZE];

            // Rebuild H0 hashes
            for n in 0..31 {
                let hash = hash_bytes(array_ref![data, n * 0x400, 0x400]);
                array_ref_mut![out, n * 20, 20].copy_from_slice(&hash);
            }

            // Rebuild H1 and H2 hashes if available
            let mut data_copied = false;
            if let Some(hash_table) = hash_table {
                let partition = &self.disc_io.partitions[partition_index];
                let part_sector = (result.disc_offset / SECTOR_SIZE as u64) as usize + i
                    - partition.partition_data[0].first_sector as usize;
                let h1_start = part_sector & !7;
                for i in 0..8 {
                    array_ref_mut![out, 0x280 + i * 20, 20]
                        .copy_from_slice(&hash_table.h1_hashes[h1_start + i]);
                }
                let h2_start = (h1_start / 8) & !7;
                for i in 0..8 {
                    array_ref_mut![out, 0x340 + i * 20, 20]
                        .copy_from_slice(&hash_table.h2_hashes[h2_start + i]);
                }

                // if result.disc_offset == 0x9150000 {
                //     println!("Validating hashes for sector {}: {:X?}", part_sector, result);
                //     // Print H0 hashes
                //     for i in 0..31 {
                //         println!("H0 hash {} {:x}", i, as_digest(array_ref![out, i * 20, 20]));
                //     }
                //     // Print H1 hashes
                //     for i in 0..8 {
                //         println!(
                //             "H1 hash {} {:x}",
                //             i,
                //             as_digest(array_ref![out, 0x280 + i * 20, 20])
                //         );
                //     }
                //     // Print H2 hashes
                //     for i in 0..8 {
                //         println!(
                //             "H2 hash {} {:x}",
                //             i,
                //             as_digest(array_ref![out, 0x340 + i * 20, 20])
                //         );
                //     }
                // }

                if self.encrypt {
                    // Re-encrypt hashes and data
                    let key = (&partition.partition_key).into();
                    Aes128Cbc::new(key, &Block::from([0u8; 16]))
                        .encrypt_padded_mut::<NoPadding>(&mut out[..HASHES_SIZE], HASHES_SIZE)
                        .expect("Failed to encrypt hashes");
                    Aes128Cbc::new(key, &Block::from(*array_ref![out, 0x3d0, 16]))
                        .encrypt_padded_b2b_mut::<NoPadding>(data, &mut out[HASHES_SIZE..])
                        .expect("Failed to encrypt data");
                    data_copied = true;
                }
            }

            if !data_copied {
                // Copy decrypted data
                array_ref_mut![out, 0x400, BLOCK_SIZE].copy_from_slice(data);
            }
        }

        self.group_data = out;
        Ok(())
    }
}

impl<'a> Read for WIAReadStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rem = buf.len();
        let mut read: usize = 0;

        // Special case: First 0x80 bytes are stored in the disc header
        if self.offset < DISC_HEAD_SIZE as u64 {
            let to_read = min(rem, DISC_HEAD_SIZE);
            buf[read..read + to_read].copy_from_slice(
                &self.disc_io.disc.disc_head[self.offset as usize..self.offset as usize + to_read],
            );
            rem -= to_read;
            read += to_read;
            self.offset += to_read as u64;
        }

        // Decompress groups and read data
        while rem > 0 {
            if !self.check_group()? {
                break;
            }
            let group_offset = (self.offset - self.group_offset) as usize;
            let to_read = min(rem, self.group_data.len() - group_offset);
            buf[read..read + to_read]
                .copy_from_slice(&self.group_data[group_offset..group_offset + to_read]);
            rem -= to_read;
            read += to_read;
            self.offset += to_read as u64;
        }
        Ok(read)
    }
}

impl<'a> Seek for WIAReadStream<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.offset = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(v) => (self.stable_stream_len()? as i64 + v) as u64,
            SeekFrom::Current(v) => (self.offset as i64 + v) as u64,
        };
        self.check_group()?;
        Ok(self.offset)
    }

    fn stream_position(&mut self) -> io::Result<u64> { Ok(self.offset) }
}

impl<'a> ReadStream for WIAReadStream<'a> {
    fn stable_stream_len(&mut self) -> io::Result<u64> { Ok(self.disc_io.header.iso_file_size) }

    fn as_dyn(&mut self) -> &mut dyn ReadStream { self }
}
