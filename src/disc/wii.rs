use std::{
    io,
    io::{Read, Seek, SeekFrom},
};

use aes::{
    cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit},
    Aes128, Block,
};
use sha1::{digest, Digest, Sha1};

use crate::{
    array_ref,
    disc::{
        AppLoaderHeader, DiscBase, DiscIO, DolHeader, Header, PartHeader, PartReadStream,
        PartitionHeader, PartitionType, SECTOR_SIZE,
    },
    fst::{find_node, Node, NodeKind, NodeType},
    streams::{wrap_windowed, OwningWindowedReadStream, ReadStream, SharedWindowedReadStream},
    util::{
        div_rem,
        reader::{skip_bytes, struct_size, FromReader},
    },
    Error, Result, ResultContext,
};

pub(crate) const HASHES_SIZE: usize = 0x400;
pub(crate) const BLOCK_SIZE: usize = SECTOR_SIZE - HASHES_SIZE; // 0x7C00

/// AES-128-CBC decryptor
type Aes128Cbc = cbc::Decryptor<Aes128>;

#[rustfmt::skip]
const COMMON_KEYS: [[u8; 16]; 2] = [
    /* Normal */
    [0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7],
    /* Korean */
    [0x63, 0xb8, 0x2b, 0xb4, 0xf4, 0x61, 0x4e, 0x2e, 0x13, 0xf2, 0xfe, 0xfb, 0xba, 0x4c, 0x9b, 0x7e],
];

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum SigType {
    Rsa4096,
    Rsa2048,
    EllipticalCurve,
}

impl FromReader for SigType {
    type Args<'a> = ();

    const STATIC_SIZE: usize = u32::STATIC_SIZE;

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        match u32::from_reader(reader)? {
            0x00010000 => Ok(SigType::Rsa4096),
            0x00010001 => Ok(SigType::Rsa2048),
            0x00010002 => Ok(SigType::EllipticalCurve),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid signature type")),
        }
    }
}

impl SigType {
    fn size(self) -> usize {
        match self {
            SigType::Rsa4096 => 512,
            SigType::Rsa2048 => 256,
            SigType::EllipticalCurve => 64,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum KeyType {
    Rsa4096,
    Rsa2048,
}

impl FromReader for KeyType {
    type Args<'a> = ();

    const STATIC_SIZE: usize = u32::STATIC_SIZE;

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        match u32::from_reader(reader)? {
            0x00000000 => Ok(KeyType::Rsa4096),
            0x00000001 => Ok(KeyType::Rsa2048),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid key type")),
        }
    }
}

impl KeyType {
    fn size(self) -> usize {
        match self {
            KeyType::Rsa4096 => 512,
            KeyType::Rsa2048 => 256,
        }
    }
}

#[derive(Debug, PartialEq)]
struct WiiPart {
    // #[br(map = |x: u32| (x as u64) << 2)]
    part_data_off: u64,
    part_type: PartitionType,
    // #[br(restore_position, args(part_data_off))]
    part_header: WiiPartitionHeader,
}

#[derive(Debug, PartialEq)]
struct WiiPartInfo {
    // #[br(seek_before = SeekFrom::Start(0x40000))]
    part_count: u32,
    // #[br(map = |x: u32| (x as u64) << 2)]
    part_info_off: u64,
    // #[br(seek_before = SeekFrom::Start(part_info_off), count = part_count)]
    parts: Vec<WiiPart>,
}

#[derive(Debug, PartialEq, Default)]
struct TicketTimeLimit {
    enable_time_limit: u32,
    time_limit: u32,
}

impl FromReader for TicketTimeLimit {
    type Args<'a> = ();

    const STATIC_SIZE: usize = struct_size([
        u32::STATIC_SIZE, // enable_time_limit
        u32::STATIC_SIZE, // time_limit
    ]);

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        let enable_time_limit = u32::from_reader(reader)?;
        let time_limit = u32::from_reader(reader)?;
        Ok(TicketTimeLimit { enable_time_limit, time_limit })
    }
}

#[derive(Debug, PartialEq)]
struct Ticket {
    sig_type: SigType,
    sig: [u8; 256],
    sig_issuer: [u8; 64],
    ecdh: [u8; 60],
    enc_key: [u8; 16],
    ticket_id: [u8; 8],
    console_id: [u8; 4],
    title_id: [u8; 8],
    ticket_version: u16,
    permitted_titles_mask: u32,
    permit_mask: u32,
    title_export_allowed: u8,
    common_key_idx: u8,
    content_access_permissions: [u8; 64],
    time_limits: [TicketTimeLimit; 8],
}

impl FromReader for Ticket {
    type Args<'a> = ();

    const STATIC_SIZE: usize = 0x2A4;

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        let sig_type = SigType::from_reader(reader)?;
        let sig = <[u8; 256]>::from_reader(reader)?;
        skip_bytes::<0x3C, _>(reader)?;
        let sig_issuer = <[u8; 64]>::from_reader(reader)?;
        let ecdh = <[u8; 60]>::from_reader(reader)?;
        skip_bytes::<3, _>(reader)?;
        let enc_key = <[u8; 16]>::from_reader(reader)?;
        skip_bytes::<1, _>(reader)?;
        let ticket_id = <[u8; 8]>::from_reader(reader)?;
        let console_id = <[u8; 4]>::from_reader(reader)?;
        let title_id = <[u8; 8]>::from_reader(reader)?;
        skip_bytes::<2, _>(reader)?;
        let ticket_version = u16::from_reader(reader)?;
        let permitted_titles_mask = u32::from_reader(reader)?;
        let permit_mask = u32::from_reader(reader)?;
        let title_export_allowed = u8::from_reader(reader)?;
        let common_key_idx = u8::from_reader(reader)?;
        skip_bytes::<48, _>(reader)?;
        let content_access_permissions = <[u8; 64]>::from_reader(reader)?;
        let time_limits = [
            TicketTimeLimit::from_reader(reader)?,
            TicketTimeLimit::from_reader(reader)?,
            TicketTimeLimit::from_reader(reader)?,
            TicketTimeLimit::from_reader(reader)?,
            TicketTimeLimit::from_reader(reader)?,
            TicketTimeLimit::from_reader(reader)?,
            TicketTimeLimit::from_reader(reader)?,
            TicketTimeLimit::from_reader(reader)?,
        ];
        Ok(Ticket {
            sig_type,
            sig,
            sig_issuer,
            ecdh,
            enc_key,
            ticket_id,
            console_id,
            title_id,
            ticket_version,
            permitted_titles_mask,
            permit_mask,
            title_export_allowed,
            common_key_idx,
            content_access_permissions,
            time_limits,
        })
    }
}

#[derive(Debug, PartialEq)]
struct TmdContent {
    id: u32,
    index: u16,
    content_type: u16,
    size: u64,
    hash: [u8; 20],
}

#[derive(Debug, PartialEq)]
struct Tmd {
    sig_type: SigType,
    // #[br(count = 256)]
    sig: Vec<u8>,
    // #[br(pad_before = 60, count = 64)]
    sig_issuer: Vec<u8>,
    version: u8,
    ca_crl_version: u8,
    signer_crl_version: u8,
    // #[br(pad_before = 1)]
    ios_id_major: u32,
    ios_id_minor: u32,
    title_id_major: u32,
    title_id_minor: [u8; 4],
    title_type: u32,
    group_id: u16,
    // #[br(pad_before = 62)]
    access_flags: u32,
    title_version: u16,
    num_contents: u16,
    // #[br(pad_after = 2)]
    boot_idx: u16,
    // #[br(count = num_contents)]
    contents: Vec<TmdContent>,
}

#[derive(Debug, PartialEq)]
struct Certificate {
    sig_type: SigType,
    // #[br(count = sig_size(sig_type))]
    sig: Vec<u8>,
    // #[br(pad_before = 60, count = 64)]
    issuer: Vec<u8>,
    key_type: KeyType,
    // #[br(count = 64)]
    subject: Vec<u8>,
    // #[br(count = key_size(key_type))]
    key: Vec<u8>,
    modulus: u32,
    // #[br(pad_after = 52)]
    pub_exp: u32,
}

#[derive(Debug, PartialEq)]
// #[br(import(partition_off: u64))]
struct WiiPartitionHeader {
    // #[br(seek_before = SeekFrom::Start(partition_off))]
    ticket: Ticket,
    tmd_size: u32,
    // #[br(map = |x: u32| ((x as u64) << 2) + partition_off)]
    tmd_off: u64,
    cert_chain_size: u32,
    // #[br(map = |x: u32| ((x as u64) << 2) + partition_off)]
    cert_chain_off: u64,
    // #[br(map = |x: u32| ((x as u64) << 2) + partition_off)]
    global_hash_table_off: u64,
    // #[br(map = |x: u32| ((x as u64) << 2) + partition_off)]
    data_off: u64,
    // #[br(map = |x: u32| (x as u64) << 2)]
    data_size: u64,

    // #[br(seek_before = SeekFrom::Start(tmd_off))]
    tmd: Tmd,
    // #[br(seek_before = SeekFrom::Start(cert_chain_off))]
    ca_cert: Certificate,
    tmd_cert: Certificate,
    ticket_cert: Certificate,
    // #[br(seek_before = SeekFrom::Start(global_hash_table_off), count = 0x18000)]
    h3_data: Vec<u8>,
}

impl FromReader for WiiPartitionHeader {
    type Args<'a> = u64;

    const STATIC_SIZE: usize = Ticket::STATIC_SIZE;

    fn from_reader_args<R>(reader: &mut R, args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        todo!()
    }
}

pub(crate) struct DiscWii {
    header: Header,
    part_info: WiiPartInfo,
}

impl DiscWii {
    pub(crate) fn new(mut stream: &mut dyn ReadStream, header: Header) -> Result<DiscWii> {
        let mut disc = DiscWii { header, part_info: todo!() }; // stream.read_be()?
        disc.decrypt_partition_keys()?;
        Ok(disc)
    }
}

impl DiscWii {
    pub(crate) fn decrypt_partition_keys(&mut self) -> Result<()> {
        for part in self.part_info.parts.as_mut_slice() {
            let ticket = &mut part.part_header.ticket;
            let mut iv: [u8; 16] = [0; 16];
            iv[..8].copy_from_slice(&ticket.title_id);
            Aes128Cbc::new(&COMMON_KEYS[ticket.common_key_idx as usize].into(), &iv.into())
                .decrypt_padded_mut::<NoPadding>(&mut ticket.enc_key)?;
        }
        Ok(())
    }
}

impl DiscBase for DiscWii {
    fn get_header(&self) -> &Header { &self.header }

    fn get_data_partition<'a>(
        &self,
        disc_io: &'a mut dyn DiscIO,
        validate_hashes: bool,
    ) -> Result<Box<dyn PartReadStream + 'a>> {
        let part = self
            .part_info
            .parts
            .iter()
            .find(|v| v.part_type == PartitionType::Data)
            .ok_or_else(|| Error::DiscFormat("Failed to locate data partition".to_string()))?;
        let data_off = part.part_header.data_off;
        let has_crypto = disc_io.has_wii_crypto();
        let base = disc_io
            .begin_read_stream(data_off)
            .map_err(|e| Error::Io("Opening data partition stream".to_string(), e))?;
        let stream = wrap_windowed(base, data_off, part.part_header.data_size)
            .context("Wrapping data partition stream")?;
        let result = Box::new(WiiPartReadStream {
            stream,
            crypto: if has_crypto { Some(part.part_header.ticket.enc_key) } else { None },
            offset: 0,
            cur_block: u32::MAX,
            buf: [0; 0x8000],
            validate_hashes,
        });
        Ok(result)
    }

    fn get_partition<'a>(
        &self,
        disc_io: &'a mut dyn DiscIO,
        part_type: PartitionType,
        validate_hashes: bool,
    ) -> Result<Box<dyn PartReadStream + 'a>> {
        let part =
            self.part_info.parts.iter().find(|v| v.part_type == part_type).ok_or_else(|| {
                Error::DiscFormat(format!("Failed to locate {:?} partition", part_type))
            })?;
        let data_off = part.part_header.data_off;
        let has_crypto = disc_io.has_wii_crypto();
        let base = disc_io
            .begin_read_stream(data_off)
            .with_context(|| format!("Opening {:?} partition stream", part_type))?;
        let stream = wrap_windowed(base, data_off, part.part_header.data_size)
            .with_context(|| format!("Wrapping {:?} partition stream", part_type))?;
        let result = Box::new(WiiPartReadStream {
            stream,
            crypto: if has_crypto { Some(part.part_header.ticket.enc_key) } else { None },
            offset: 0,
            cur_block: u32::MAX,
            buf: [0; 0x8000],
            validate_hashes,
        });
        Ok(result)
    }
}

struct WiiPartReadStream<'a> {
    stream: OwningWindowedReadStream<'a>,
    crypto: Option<[u8; 16]>,
    offset: u64,
    cur_block: u32,
    buf: [u8; SECTOR_SIZE],
    validate_hashes: bool,
}

impl<'a> PartReadStream for WiiPartReadStream<'a> {
    fn begin_file_stream(&mut self, node: &Node) -> io::Result<SharedWindowedReadStream> {
        assert_eq!(node.kind, NodeKind::File);
        self.new_window((node.offset as u64) << 2, node.length as u64)
    }

    fn read_header(&mut self) -> Result<Box<dyn PartHeader>> {
        self.seek(SeekFrom::Start(0)).context("Seeking to partition header")?;
        todo!()
        // Ok(Box::from(self.read_be::<WiiPartition>()?))
    }

    fn ideal_buffer_size(&self) -> usize { BLOCK_SIZE }
}

#[inline(always)]
fn as_digest(slice: &[u8; 20]) -> digest::Output<Sha1> { (*slice).into() }

fn decrypt_block(part: &mut WiiPartReadStream, cluster: u32) -> io::Result<()> {
    part.stream.read_exact(&mut part.buf)?;
    if let Some(key) = &part.crypto {
        // Fetch IV before decrypting header
        let iv_bytes = array_ref![part.buf, 0x3d0, 16];
        let iv = Block::from(*iv_bytes);
        // Don't need to decrypt header if we're not validating hashes
        if part.validate_hashes {
            Aes128Cbc::new(key.into(), &Block::from([0; 16]))
                .decrypt_padded_mut::<NoPadding>(&mut part.buf[..HASHES_SIZE])
                .expect("Failed to decrypt header");
        }
        Aes128Cbc::new(key.into(), &iv)
            .decrypt_padded_mut::<NoPadding>(&mut part.buf[HASHES_SIZE..])
            .expect("Failed to decrypt block");
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
                panic!("Invalid H0 hash! (block {:?}) {:x}\n\texpected {:x}", i, output, expected);
            }
        }
        // H1 hash
        {
            let mut hash = Sha1::new();
            hash.update(array_ref![part.buf, 0, 0x26C]);
            let expected = as_digest(array_ref![part.buf, 0x280 + sub_group * 20, 20]);
            let output = hash.finalize();
            if output != expected {
                panic!(
                    "Invalid H1 hash! (subgroup {:?}) {:x}\n\texpected {:x}",
                    sub_group, output, expected
                );
            }
        }
        // H2 hash
        {
            let mut hash = Sha1::new();
            hash.update(array_ref![part.buf, 0x280, 0xA0]);
            let expected = as_digest(array_ref![part.buf, 0x340 + group * 20, 20]);
            let output = hash.finalize();
            if output != expected {
                panic!(
                    "Invalid H2 hash! (group {:?}) {:x}\n\texpected {:x}",
                    group, output, expected
                );
            }
        }
    }
    Ok(())
}

impl<'a> Read for WiiPartReadStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (block, block_offset) = div_rem(self.offset, BLOCK_SIZE as u64);
        let mut block = block as u32;
        let mut block_offset = block_offset as usize;

        let mut rem = buf.len();
        let mut read: usize = 0;

        while rem > 0 {
            if block != self.cur_block {
                decrypt_block(self, block)?;
                self.cur_block = block;
            }

            let mut cache_size = rem;
            if cache_size + block_offset > BLOCK_SIZE {
                cache_size = BLOCK_SIZE - block_offset;
            }

            buf[read..read + cache_size].copy_from_slice(
                &self.buf[HASHES_SIZE + block_offset..HASHES_SIZE + block_offset + cache_size],
            );
            read += cache_size;
            rem -= cache_size;
            block_offset = 0;
            block += 1;
        }

        self.offset += buf.len() as u64;
        Ok(buf.len())
    }
}

#[inline(always)]
fn to_block_size(v: u64) -> u64 {
    (v / SECTOR_SIZE as u64) * BLOCK_SIZE as u64 + (v % SECTOR_SIZE as u64)
}

impl<'a> Seek for WiiPartReadStream<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.offset = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(v) => (self.stable_stream_len()? as i64 + v) as u64,
            SeekFrom::Current(v) => (self.offset as i64 + v) as u64,
        };
        let block = (self.offset / BLOCK_SIZE as u64) as u32;
        if block != self.cur_block {
            self.stream.seek(SeekFrom::Start(block as u64 * SECTOR_SIZE as u64))?;
            self.cur_block = u32::MAX;
        }
        Ok(self.offset)
    }

    fn stream_position(&mut self) -> io::Result<u64> { Ok(self.offset) }
}

impl<'a> ReadStream for WiiPartReadStream<'a> {
    fn stable_stream_len(&mut self) -> io::Result<u64> {
        Ok(to_block_size(self.stream.stable_stream_len()?))
    }

    fn as_dyn(&mut self) -> &mut dyn ReadStream { self }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct WiiPartition {
    header: Header,
    // #[br(seek_before = SeekFrom::Start(0x400))]
    part_header: PartitionHeader,
    // bi2_header: BI2Header,
    // #[br(seek_before = SeekFrom::Start((part_header.fst_off as u64) << 2))]
    // #[br(parse_with = node_parser)]
    root_node: NodeType,
}

impl PartHeader for WiiPartition {
    fn root_node(&self) -> &NodeType { &self.root_node }

    fn find_node(&self, path: &str) -> Option<&NodeType> { find_node(&self.root_node, path) }

    fn boot_bytes(&self) -> &[u8] { todo!() }

    fn bi2_bytes(&self) -> &[u8] { todo!() }

    fn apploader_bytes(&self) -> &[u8] { todo!() }

    fn fst_bytes(&self) -> &[u8] { todo!() }

    fn dol_bytes(&self) -> &[u8] { todo!() }

    fn disc_header(&self) -> &Header { todo!() }

    fn partition_header(&self) -> &PartitionHeader { todo!() }

    fn apploader_header(&self) -> &AppLoaderHeader { todo!() }

    fn dol_header(&self) -> &DolHeader { todo!() }
}
