use std::{
    cmp::min,
    ffi::CStr,
    io,
    io::{Read, Seek, SeekFrom},
    mem::size_of,
};

use sha1::{digest, Digest, Sha1};
use zerocopy::{big_endian::*, AsBytes, FromBytes, FromZeroes};

use crate::{
    array_ref,
    disc::{
        gcn::read_part_header, DiscBase, DiscHeader, DiscIO, PartitionBase, PartitionInfo,
        PartitionKind, PartitionMeta, DL_DVD_SIZE, MINI_DVD_SIZE, SECTOR_SIZE, SL_DVD_SIZE,
    },
    fst::{Node, NodeKind},
    io::{aes_decrypt, KeyBytes},
    static_assert,
    streams::{ReadStream, SharedWindowedReadStream},
    util::{
        div_rem,
        read::{read_from, read_vec},
    },
    Error, OpenOptions, PartitionHeader, Result, ResultContext,
};

pub(crate) const HASHES_SIZE: usize = 0x400;
pub(crate) const SECTOR_DATA_SIZE: usize = SECTOR_SIZE - HASHES_SIZE; // 0x7C00

// ppki (Retail)
const RVL_CERT_ISSUER_PPKI_TICKET: &str = "Root-CA00000001-XS00000003";
#[rustfmt::skip]
const RETAIL_COMMON_KEYS: [KeyBytes; 3] = [
    /* RVL_KEY_RETAIL */
    [0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7],
    /* RVL_KEY_KOREAN */
    [0x63, 0xb8, 0x2b, 0xb4, 0xf4, 0x61, 0x4e, 0x2e, 0x13, 0xf2, 0xfe, 0xfb, 0xba, 0x4c, 0x9b, 0x7e],
    /* vWii_KEY_RETAIL */
    [0x30, 0xbf, 0xc7, 0x6e, 0x7c, 0x19, 0xaf, 0xbb, 0x23, 0x16, 0x33, 0x30, 0xce, 0xd7, 0xc2, 0x8d],
];

// dpki (Debug)
const RVL_CERT_ISSUER_DPKI_TICKET: &str = "Root-CA00000002-XS00000006";
#[rustfmt::skip]
const DEBUG_COMMON_KEYS: [KeyBytes; 3] = [
    /* RVL_KEY_DEBUG */
    [0xa1, 0x60, 0x4a, 0x6a, 0x71, 0x23, 0xb5, 0x29, 0xae, 0x8b, 0xec, 0x32, 0xc8, 0x16, 0xfc, 0xaa],
    /* RVL_KEY_KOREAN_DEBUG */
    [0x67, 0x45, 0x8b, 0x6b, 0xc6, 0x23, 0x7b, 0x32, 0x69, 0x98, 0x3c, 0x64, 0x73, 0x48, 0x33, 0x66],
    /* vWii_KEY_DEBUG */
    [0x2f, 0x5c, 0x1b, 0x29, 0x44, 0xe7, 0xfd, 0x6f, 0xc3, 0x97, 0x96, 0x4b, 0x05, 0x76, 0x91, 0xfa],
];

#[derive(Debug, PartialEq, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub(crate) struct WiiPartEntry {
    pub(crate) offset: U32,
    pub(crate) kind: U32,
}

static_assert!(size_of::<WiiPartEntry>() == 8);

impl WiiPartEntry {
    pub(crate) fn offset(&self) -> u64 { (self.offset.get() as u64) << 2 }
}

#[derive(Debug, PartialEq)]
pub(crate) struct WiiPartInfo {
    pub(crate) group_idx: u32,
    pub(crate) part_idx: u32,
    pub(crate) offset: u64,
    pub(crate) kind: PartitionKind,
    pub(crate) header: WiiPartitionHeader,
    pub(crate) junk_id: [u8; 4],
    pub(crate) junk_start: u64,
    pub(crate) title_key: KeyBytes,
}

pub(crate) const WII_PART_GROUP_OFF: u64 = 0x40000;

#[derive(Debug, PartialEq, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub(crate) struct WiiPartGroup {
    pub(crate) part_count: U32,
    pub(crate) part_entry_off: U32,
}

static_assert!(size_of::<WiiPartGroup>() == 8);

impl WiiPartGroup {
    pub(crate) fn part_entry_off(&self) -> u64 { (self.part_entry_off.get() as u64) << 2 }
}

#[derive(Debug, Clone, PartialEq, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub struct SignedHeader {
    /// Signature type, always 0x00010001 (RSA-2048)
    pub sig_type: U32,
    /// RSA-2048 signature
    pub sig: [u8; 256],
    _pad: [u8; 60],
}

static_assert!(size_of::<SignedHeader>() == 0x140);

#[derive(Debug, Clone, PartialEq, Default, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub struct TicketTimeLimit {
    pub enable_time_limit: U32,
    pub time_limit: U32,
}

static_assert!(size_of::<TicketTimeLimit>() == 8);

#[derive(Debug, Clone, PartialEq, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub struct Ticket {
    pub header: SignedHeader,
    pub sig_issuer: [u8; 64],
    pub ecdh: [u8; 60],
    pub version: u8,
    _pad1: U16,
    pub title_key: KeyBytes,
    _pad2: u8,
    pub ticket_id: [u8; 8],
    pub console_id: [u8; 4],
    pub title_id: [u8; 8],
    _pad3: U16,
    pub ticket_title_version: U16,
    pub permitted_titles_mask: U32,
    pub permit_mask: U32,
    pub title_export_allowed: u8,
    pub common_key_idx: u8,
    _pad4: [u8; 48],
    pub content_access_permissions: [u8; 64],
    _pad5: [u8; 2],
    pub time_limits: [TicketTimeLimit; 8],
}

static_assert!(size_of::<Ticket>() == 0x2A4);

impl Ticket {
    pub fn decrypt_title_key(&self) -> Result<KeyBytes> {
        let mut iv: KeyBytes = [0; 16];
        iv[..8].copy_from_slice(&self.title_id);
        let cert_issuer_ticket =
            CStr::from_bytes_until_nul(&self.sig_issuer).ok().and_then(|c| c.to_str().ok());
        let common_keys = match cert_issuer_ticket {
            Some(RVL_CERT_ISSUER_PPKI_TICKET) => &RETAIL_COMMON_KEYS,
            Some(RVL_CERT_ISSUER_DPKI_TICKET) => &DEBUG_COMMON_KEYS,
            Some(v) => {
                return Err(Error::DiscFormat(format!("unknown certificate issuer {:?}", v)));
            }
            None => {
                return Err(Error::DiscFormat("failed to parse certificate issuer".to_string()));
            }
        };
        let common_key = common_keys.get(self.common_key_idx as usize).ok_or(Error::DiscFormat(
            format!("unknown common key index {}", self.common_key_idx),
        ))?;
        let mut title_key = self.title_key;
        aes_decrypt(common_key, iv, &mut title_key);
        Ok(title_key)
    }
}

#[derive(Debug, Clone, PartialEq, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub struct TmdHeader {
    pub header: SignedHeader,
    pub sig_issuer: [u8; 64],
    pub version: u8,
    pub ca_crl_version: u8,
    pub signer_crl_version: u8,
    pub is_vwii: u8,
    pub ios_id: [u8; 8],
    pub title_id: [u8; 8],
    pub title_type: u32,
    pub group_id: U16,
    _pad1: [u8; 2],
    pub region: U16,
    pub ratings: KeyBytes,
    _pad2: [u8; 12],
    pub ipc_mask: [u8; 12],
    _pad3: [u8; 18],
    pub access_flags: U32,
    pub title_version: U16,
    pub num_contents: U16,
    pub boot_idx: U16,
    pub minor_version: U16,
}

static_assert!(size_of::<TmdHeader>() == 0x1E4);

pub const H3_TABLE_SIZE: usize = 0x18000;

#[derive(Debug, Clone, PartialEq, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(4))]
pub struct WiiPartitionHeader {
    pub ticket: Ticket,
    tmd_size: U32,
    tmd_off: U32,
    cert_chain_size: U32,
    cert_chain_off: U32,
    h3_table_off: U32,
    data_off: U32,
    data_size: U32,
}

static_assert!(size_of::<WiiPartitionHeader>() == 0x2C0);

impl WiiPartitionHeader {
    pub fn tmd_size(&self) -> u64 { self.tmd_size.get() as u64 }

    pub fn tmd_off(&self) -> u64 { (self.tmd_off.get() as u64) << 2 }

    pub fn cert_chain_size(&self) -> u64 { self.cert_chain_size.get() as u64 }

    pub fn cert_chain_off(&self) -> u64 { (self.cert_chain_off.get() as u64) << 2 }

    pub fn h3_table_off(&self) -> u64 { (self.h3_table_off.get() as u64) << 2 }

    pub fn h3_table_size(&self) -> u64 { H3_TABLE_SIZE as u64 }

    pub fn data_off(&self) -> u64 { (self.data_off.get() as u64) << 2 }

    pub fn data_size(&self) -> u64 { (self.data_size.get() as u64) << 2 }
}

pub(crate) struct DiscWii {
    header: DiscHeader,
    part_info: Vec<WiiPartInfo>,
    disc_size: u64,
}

impl DiscWii {
    pub(crate) fn new(
        stream: &mut dyn ReadStream,
        header: DiscHeader,
        disc_size: Option<u64>,
    ) -> Result<Self> {
        let part_info = read_partition_info(stream, &header)?;
        // Guess disc size if not provided
        let disc_size = disc_size.unwrap_or_else(|| guess_disc_size(&part_info));
        Ok(Self { header, part_info, disc_size })
    }
}

pub(crate) fn read_partition_info(
    stream: &mut dyn ReadStream,
    disc_header: &DiscHeader,
) -> Result<Vec<WiiPartInfo>> {
    stream.seek(SeekFrom::Start(WII_PART_GROUP_OFF)).context("Seeking to partition groups")?;
    let part_groups: [WiiPartGroup; 4] = read_from(stream).context("Reading partition groups")?;
    let mut part_info = Vec::new();
    for (group_idx, group) in part_groups.iter().enumerate() {
        let part_count = group.part_count.get();
        if part_count == 0 {
            continue;
        }
        stream
            .seek(SeekFrom::Start(group.part_entry_off()))
            .with_context(|| format!("Seeking to partition group {group_idx}"))?;
        let entries: Vec<WiiPartEntry> = read_vec(stream, part_count as usize)
            .with_context(|| format!("Reading partition group {group_idx}"))?;
        for (part_idx, entry) in entries.iter().enumerate() {
            let offset = entry.offset();
            stream
                .seek(SeekFrom::Start(offset))
                .with_context(|| format!("Seeking to partition data {group_idx}:{part_idx}"))?;
            let header: WiiPartitionHeader = read_from(stream)
                .with_context(|| format!("Reading partition header {group_idx}:{part_idx}"))?;

            // Open partition stream and read junk data seed
            // let inner = stream
            //     .new_window(offset + header.data_off(), DL_DVD_SIZE) // header.data_size()
            //     .context("Wrapping partition stream")?;
            let title_key = header.ticket.decrypt_title_key()?;
            let part_offset = entry.offset() + header.data_off();
            if part_offset % SECTOR_SIZE as u64 != 0 {
                return Err(Error::DiscFormat(format!(
                    "Partition {group_idx}:{part_idx} offset is not sector aligned",
                )));
            }
            let start_sector = (part_offset / SECTOR_SIZE as u64) as u32;
            let mut stream = PartitionWii {
                start_sector,
                header: header.clone(),
                tmd: vec![],
                cert_chain: vec![],
                h3_table: vec![],
                stream: Box::new(stream.as_dyn()),
                key: Some(title_key),
                offset: 0,
                cur_block: u32::MAX,
                buf: [0; SECTOR_SIZE],
                has_hashes: disc_header.no_partition_hashes == 0,
                validate_hashes: false,
            };
            let junk_id: [u8; 4] = read_from(&mut stream).context("Reading junk seed bytes")?;
            stream
                .seek(SeekFrom::Start(size_of::<DiscHeader>() as u64))
                .context("Seeking to partition header")?;
            let part_header: PartitionHeader =
                read_from(&mut stream).context("Reading partition header")?;
            let junk_start = part_header.fst_off(true) + part_header.fst_sz(true);

            log::debug!("Header: {:?}", header);
            log::debug!(
                "Partition: {:?} - {:?}: {:?}",
                offset + header.data_off(),
                header.data_size(),
                header.ticket.title_key
            );

            part_info.push(WiiPartInfo {
                group_idx: group_idx as u32,
                part_idx: part_idx as u32,
                offset,
                kind: entry.kind.get().into(),
                header,
                junk_id,
                junk_start,
                title_key,
            });
        }
    }
    Ok(part_info)
}

pub(crate) fn guess_disc_size(part_info: &[WiiPartInfo]) -> u64 {
    let max_offset = part_info
        .iter()
        .flat_map(|v| {
            [
                v.offset + v.header.tmd_off() + v.header.tmd_size(),
                v.offset + v.header.cert_chain_off() + v.header.cert_chain_size(),
                v.offset + v.header.h3_table_off() + v.header.h3_table_size(),
                v.offset + v.header.data_off() + v.header.data_size(),
            ]
        })
        .max()
        .unwrap_or(0x50000);
    if max_offset <= MINI_DVD_SIZE && !part_info.iter().any(|v| v.kind == PartitionKind::Data) {
        // Datel disc
        MINI_DVD_SIZE
    } else if max_offset < SL_DVD_SIZE {
        SL_DVD_SIZE
    } else {
        DL_DVD_SIZE
    }
}

fn open_partition<'a>(
    part: &WiiPartInfo,
    disc_io: &'a dyn DiscIO,
    options: &OpenOptions,
    header: &DiscHeader,
) -> Result<Box<dyn PartitionBase + 'a>> {
    let mut base = disc_io.open()?;

    base.seek(SeekFrom::Start(part.offset + part.header.tmd_off()))
        .context("Seeking to TMD offset")?;
    let tmd: Vec<u8> =
        read_vec(&mut base, part.header.tmd_size() as usize).context("Reading TMD")?;

    base.seek(SeekFrom::Start(part.offset + part.header.cert_chain_off()))
        .context("Seeking to cert chain offset")?;
    let cert_chain: Vec<u8> = read_vec(&mut base, part.header.cert_chain_size() as usize)
        .context("Reading cert chain")?;

    base.seek(SeekFrom::Start(part.offset + part.header.h3_table_off()))
        .context("Seeking to H3 table offset")?;
    let h3_table: Vec<u8> = read_vec(&mut base, H3_TABLE_SIZE).context("Reading H3 table")?;

    let key = if header.no_partition_encryption == 0 {
        Some(part.header.ticket.decrypt_title_key()?)
    } else {
        None
    };
    let data_off = part.offset + part.header.data_off();
    if data_off % SECTOR_SIZE as u64 != 0 {
        return Err(Error::DiscFormat(format!(
            "Partition {}:{} offset is not sector aligned",
            part.group_idx, part.part_idx
        )));
    }
    let start_sector = (data_off / SECTOR_SIZE as u64) as u32;
    Ok(Box::new(PartitionWii {
        start_sector,
        header: part.header.clone(),
        tmd,
        cert_chain,
        h3_table,
        stream: base,
        key,
        offset: 0,
        cur_block: u32::MAX,
        buf: [0; SECTOR_SIZE],
        has_hashes: header.no_partition_hashes == 0,
        validate_hashes: options.validate_hashes && header.no_partition_hashes == 0,
    }))
}

impl DiscBase for DiscWii {
    fn header(&self) -> &DiscHeader { &self.header }

    fn partitions(&self) -> Vec<PartitionInfo> {
        self.part_info
            .iter()
            .map(|v| PartitionInfo {
                group_index: v.group_idx,
                part_index: v.part_idx,
                part_offset: v.offset,
                kind: v.kind,
                data_offset: v.header.data_off(),
                data_size: v.header.data_size(),
                header: Some(v.header.clone()),
                lfg_seed: v.junk_id,
                // junk_start: v.junk_start,
            })
            .collect()
    }

    fn open_partition<'a>(
        &self,
        disc_io: &'a dyn DiscIO,
        index: usize,
        options: &OpenOptions,
    ) -> Result<Box<dyn PartitionBase + 'a>> {
        let part = self.part_info.get(index).ok_or_else(|| {
            Error::DiscFormat(format!("Failed to locate partition index {}", index))
        })?;
        open_partition(part, disc_io, options, &self.header)
    }

    fn open_partition_kind<'a>(
        &self,
        disc_io: &'a dyn DiscIO,
        part_type: PartitionKind,
        options: &OpenOptions,
    ) -> Result<Box<dyn PartitionBase + 'a>> {
        let part = self.part_info.iter().find(|&v| v.kind == part_type).ok_or_else(|| {
            Error::DiscFormat(format!("Failed to locate {:?} partition", part_type))
        })?;
        open_partition(part, disc_io, options, &self.header)
    }

    fn disc_size(&self) -> u64 { self.disc_size }
}

struct PartitionWii<'a> {
    start_sector: u32,
    header: WiiPartitionHeader,
    tmd: Vec<u8>,
    cert_chain: Vec<u8>,
    h3_table: Vec<u8>,

    stream: Box<dyn ReadStream + 'a>,
    key: Option<KeyBytes>,
    offset: u64,
    cur_block: u32,
    buf: [u8; SECTOR_SIZE],
    has_hashes: bool,
    validate_hashes: bool,
}

impl<'a> PartitionBase for PartitionWii<'a> {
    fn meta(&mut self) -> Result<Box<PartitionMeta>> {
        self.seek(SeekFrom::Start(0)).context("Seeking to partition header")?;
        let mut meta = read_part_header(self, true)?;
        meta.raw_ticket = Some(Box::from(self.header.ticket.as_bytes()));
        meta.raw_tmd = Some(Box::from(self.tmd.as_slice()));
        meta.raw_cert_chain = Some(Box::from(self.cert_chain.as_slice()));
        meta.raw_h3_table = Some(Box::from(self.h3_table.as_slice()));
        Ok(meta)
    }

    fn open_file(&mut self, node: &Node) -> io::Result<SharedWindowedReadStream> {
        assert_eq!(node.kind(), NodeKind::File);
        self.new_window(node.offset(true), node.length(true))
    }

    fn ideal_buffer_size(&self) -> usize {
        if self.has_hashes {
            SECTOR_DATA_SIZE
        } else {
            SECTOR_SIZE
        }
    }
}

#[inline(always)]
pub(crate) fn as_digest(slice: &[u8; 20]) -> digest::Output<Sha1> { (*slice).into() }

fn decrypt_block(part: &mut PartitionWii, cluster: u32) -> io::Result<()> {
    part.stream.read_exact(&mut part.buf)?;
    if let Some(key) = &part.key {
        // Fetch IV before decrypting header
        let iv = *array_ref![part.buf, 0x3d0, 16];
        // Don't need to decrypt header if we're not validating hashes
        if part.validate_hashes {
            aes_decrypt(key, [0; 16], &mut part.buf[..HASHES_SIZE]);
        }
        aes_decrypt(key, iv, &mut part.buf[HASHES_SIZE..]);
    }
    if part.validate_hashes {
        let (mut group, sub_group) = div_rem(cluster as usize, 8);
        group %= 8;
        // H0 hashes
        for i in 0..31 {
            let mut hash = Sha1::new();
            hash.update(array_ref![part.buf, (i + 1) * 0x400, 0x400]);
            let expected = as_digest(array_ref![part.buf, i * 20, 20]);
            let output = hash.finalize();
            if output != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Invalid H0 hash! (block {:?}) {:x}\n\texpected {:x}",
                        i, output, expected
                    ),
                ));
            }
        }
        // H1 hash
        {
            let mut hash = Sha1::new();
            hash.update(array_ref![part.buf, 0, 0x26C]);
            let expected = as_digest(array_ref![part.buf, 0x280 + sub_group * 20, 20]);
            let output = hash.finalize();
            if output != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Invalid H1 hash! (subgroup {:?}) {:x}\n\texpected {:x}",
                        sub_group, output, expected
                    ),
                ));
            }
        }
        // H2 hash
        {
            let mut hash = Sha1::new();
            hash.update(array_ref![part.buf, 0x280, 0xA0]);
            let expected = as_digest(array_ref![part.buf, 0x340 + group * 20, 20]);
            let output = hash.finalize();
            if output != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Invalid H2 hash! (group {:?}) {:x}\n\texpected {:x}",
                        group, output, expected
                    ),
                ));
            }
        }
    }
    Ok(())
}

impl<'a> Read for PartitionWii<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let block_size = self.ideal_buffer_size() as u64;
        let (block, block_offset) = div_rem(self.offset, block_size);
        let block = block as u32;
        if block != self.cur_block {
            self.stream
                .seek(SeekFrom::Start((self.start_sector + block) as u64 * SECTOR_SIZE as u64))?;
            decrypt_block(self, block)?;
            self.cur_block = block;
        }

        let offset = (SECTOR_SIZE - block_size as usize) + block_offset as usize;
        let read = min(buf.len(), block_size as usize - block_offset as usize);
        buf[..read].copy_from_slice(&self.buf[offset..offset + read]);
        self.offset += read as u64;
        Ok(read)

        // let mut block = block as u32;
        //
        // let mut rem = buf.len();
        // let mut read: usize = 0;
        //
        // while rem > 0 {
        //     if block != self.cur_block {
        //         decrypt_block(self, block)?;
        //         self.cur_block = block;
        //     }
        //
        //     let mut cache_size = rem;
        //     if cache_size as u64 + block_offset > block_size {
        //         cache_size = (block_size - block_offset) as usize;
        //     }
        //
        //     let hashes_size = SECTOR_SIZE - block_size as usize;
        //     let start = hashes_size + block_offset as usize;
        //     buf[read..read + cache_size].copy_from_slice(&self.buf[start..start + cache_size]);
        //     read += cache_size;
        //     rem -= cache_size;
        //     block_offset = 0;
        //     block += 1;
        // }
        //
        // self.offset += buf.len() as u64;
        // Ok(buf.len())
    }
}

#[inline(always)]
fn to_block_size(v: u64) -> u64 {
    (v / SECTOR_SIZE as u64) * SECTOR_DATA_SIZE as u64 + (v % SECTOR_SIZE as u64)
}

impl<'a> Seek for PartitionWii<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.offset = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "PartitionWii: SeekFrom::End is not supported",
                ));
            }
            SeekFrom::Current(v) => self.offset.saturating_add_signed(v),
        };
        // let block = self.offset / self.ideal_buffer_size() as u64;
        // if block as u32 != self.cur_block {
        //     self.stream.seek(SeekFrom::Start((self.start_sector + block) * SECTOR_SIZE as u64))?;
        //     self.cur_block = u32::MAX;
        // }
        Ok(self.offset)
    }

    fn stream_position(&mut self) -> io::Result<u64> { Ok(self.offset) }
}
