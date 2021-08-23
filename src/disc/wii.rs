use std::{io, io::{Read, Seek, SeekFrom}};

use aes::{Aes128, NewBlockCipher, Block};
use binread::prelude::*;
use block_modes::{block_padding::NoPadding, BlockMode, Cbc};
use sha1::{digest, Digest, Sha1};

use crate::disc::{BI2Header, BUFFER_SIZE, DiscBase, DiscIO, Header, PartHeader, PartReadStream};
use crate::{Error, div_rem, Result, array_ref};
use crate::fst::{find_node, Node, NodeKind, NodeType, node_parser};
use crate::streams::{OwningWindowedReadStream, ReadStream, SharedWindowedReadStream};

type Aes128Cbc = Cbc<Aes128, NoPadding>;

const BLOCK_SIZE: usize = 0x7c00;
const BUFFER_OFFSET: usize = BUFFER_SIZE - BLOCK_SIZE;
const COMMON_KEYS: [[u8; 16]; 2] = [
    /* Normal */
    [0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7],
    /* Korean */
    [0x63, 0xb8, 0x2b, 0xb4, 0xf4, 0x61, 0x4e, 0x2e, 0x13, 0xf2, 0xfe, 0xfb, 0xba, 0x4c, 0x9b, 0x7e],
];

#[derive(Debug, PartialEq, BinRead)]
#[br(repr = u32)]
enum WiiPartType {
    Data,
    Update,
    Channel,
}

#[derive(Debug, PartialEq, BinRead)]
#[br(repr = u32)]
enum SigType {
    Rsa4096 = 0x00010000,
    Rsa2048 = 0x00010001,
    EllipticalCurve = 0x00010002,
}

#[derive(Debug, PartialEq, BinRead)]
#[br(repr = u32)]
enum KeyType {
    Rsa4096 = 0x00000000,
    Rsa2048 = 0x00000001,
}

#[derive(Debug, PartialEq, BinRead)]
struct WiiPart {
    #[br(map = | x: u32 | (x as u64) << 2)]
    part_data_off: u64,
    part_type: WiiPartType,
    #[br(restore_position, args(part_data_off))]
    part_header: WiiPartitionHeader,
}

#[derive(Debug, PartialEq, BinRead)]
struct WiiPartInfo {
    #[br(seek_before = SeekFrom::Start(0x40000))]
    part_count: u32,
    #[br(map = | x: u32 | (x as u64) << 2)]
    part_info_off: u64,
    #[br(seek_before = SeekFrom::Start(part_info_off), count = part_count)]
    parts: Vec<WiiPart>,
}

#[derive(Debug, PartialEq, BinRead)]
struct TicketTimeLimit {
    enable_time_limit: u32,
    time_limit: u32,
}

#[derive(Debug, PartialEq, BinRead)]
struct Ticket {
    sig_type: SigType,
    #[br(count = 256)]
    sig: Vec<u8>,
    #[br(pad_before = 60, count = 64)]
    sig_issuer: Vec<u8>,
    #[br(count = 60)]
    ecdh: Vec<u8>,
    #[br(pad_before = 3)]
    enc_key: [u8; 16],
    #[br(pad_before = 1)]
    ticket_id: [u8; 8],
    console_id: [u8; 4],
    title_id: [u8; 8],
    #[br(pad_before = 2)]
    ticket_version: u16,
    permitted_titles_mask: u32,
    permit_mask: u32,
    title_export_allowed: u8,
    common_key_idx: u8,
    #[br(pad_before = 48, count = 64)]
    content_access_permissions: Vec<u8>,
    #[br(pad_before = 2, count = 8)]
    time_limits: Vec<TicketTimeLimit>,
}

#[derive(Debug, PartialEq, BinRead)]
struct TMDContent {
    id: u32,
    index: u16,
    content_type: u16,
    size: u64,
    hash: [u8; 20],
}

#[derive(Debug, PartialEq, BinRead)]
struct TMD {
    sig_type: SigType,
    #[br(count = 256)]
    sig: Vec<u8>,
    #[br(pad_before = 60, count = 64)]
    sig_issuer: Vec<u8>,
    version: u8,
    ca_crl_version: u8,
    signer_crl_version: u8,
    #[br(pad_before = 1)]
    ios_id_major: u32,
    ios_id_minor: u32,
    title_id_major: u32,
    title_id_minor: [char; 4],
    title_type: u32,
    group_id: u16,
    #[br(pad_before = 62)]
    access_flags: u32,
    title_version: u16,
    num_contents: u16,
    #[br(pad_after = 2)]
    boot_idx: u16,
    #[br(count = num_contents)]
    contents: Vec<TMDContent>,
}

#[derive(Debug, PartialEq, BinRead)]
struct Certificate {
    sig_type: SigType,
    #[br(count = if sig_type == SigType::Rsa4096 { 512 }
    else if sig_type == SigType::Rsa2048 { 256 }
    else if sig_type == SigType::EllipticalCurve { 64 } else { 0 })]
    sig: Vec<u8>,
    #[br(pad_before = 60, count = 64)]
    issuer: Vec<u8>,
    key_type: KeyType,
    #[br(count = 64)]
    subject: Vec<u8>,
    #[br(count = if key_type == KeyType::Rsa4096 { 512 } else if key_type == KeyType::Rsa2048 { 256 } else { 0 })]
    key: Vec<u8>,
    modulus: u32,
    #[br(pad_after = 52)]
    pub_exp: u32,
}

#[derive(Debug, PartialEq, BinRead)]
#[br(import(partition_off: u64))]
struct WiiPartitionHeader {
    #[br(seek_before = SeekFrom::Start(partition_off))]
    ticket: Ticket,
    tmd_size: u32,
    #[br(map = | x: u32 | ((x as u64) << 2) + partition_off)]
    tmd_off: u64,
    cert_chain_size: u32,
    #[br(map = | x: u32 | ((x as u64) << 2) + partition_off)]
    cert_chain_off: u64,
    #[br(map = | x: u32 | ((x as u64) << 2) + partition_off)]
    global_hash_table_off: u64,
    #[br(map = | x: u32 | ((x as u64) << 2) + partition_off)]
    data_off: u64,
    #[br(map = | x: u32 | (x as u64) << 2)]
    data_size: u64,

    #[br(seek_before = SeekFrom::Start(tmd_off))]
    tmd: TMD,
    #[br(seek_before = SeekFrom::Start(cert_chain_off))]
    ca_cert: Certificate,
    tmd_cert: Certificate,
    ticket_cert: Certificate,
    #[br(seek_before = SeekFrom::Start(global_hash_table_off), count = 0x18000)]
    h3_data: Vec<u8>,
}

pub(crate) struct DiscWii {
    header: Header,
    part_info: WiiPartInfo,
}

pub(crate) fn new_disc_wii(mut stream: &mut dyn ReadStream, header: Header) -> Result<DiscWii> {
    let mut disc = DiscWii {
        header,
        part_info: stream.read_be()?,
    };
    disc.decrypt_partition_keys()?;
    Result::Ok(disc)
}

impl DiscWii {
    pub(crate) fn decrypt_partition_keys(&mut self) -> Result<()> {
        for part in self.part_info.parts.as_mut_slice() {
            let ticket = &mut part.part_header.ticket;
            let mut iv: [u8; 16] = [0; 16];
            iv[..8].copy_from_slice(&ticket.title_id);
            Aes128Cbc::new(
                Aes128::new(&COMMON_KEYS[ticket.common_key_idx as usize].into()),
                &iv.into(),
            ).decrypt(&mut ticket.enc_key)?;
        }
        Result::Ok(())
    }
}

impl DiscBase for DiscWii {
    fn get_header(&self) -> &Header {
        &self.header
    }

    fn get_data_partition<'a>(&self, disc_io: &'a mut dyn DiscIO) -> Result<Box<dyn PartReadStream + 'a>> {
        let part = self.part_info.parts.iter().find(|v| v.part_type == WiiPartType::Data)
            .ok_or(Error::DiscFormat("Failed to locate data partition".to_string()))?;
        let data_off = part.part_header.data_off;
        let result = Box::new(WiiPartReadStream {
            stream: OwningWindowedReadStream {
                base: disc_io.begin_read_stream(data_off)?,
                begin: data_off,
                end: data_off + part.part_header.data_size,
            },
            crypto: if disc_io.has_wii_crypto() {
                Aes128::new(&part.part_header.ticket.enc_key.into()).into()
            } else { Option::None },
            offset: 0,
            cur_block: u64::MAX,
            buf: [0; 0x8000],
            validate_hashes: false,
        });
        Result::Ok(result)
    }
}

struct WiiPartReadStream<'a> {
    stream: OwningWindowedReadStream<'a>,
    crypto: Option<Aes128>,
    offset: u64,
    cur_block: u64,
    buf: [u8; BUFFER_SIZE],
    validate_hashes: bool,
}

impl<'a> PartReadStream for WiiPartReadStream<'a> {
    fn begin_file_stream(&mut self, node: &Node) -> io::Result<SharedWindowedReadStream> {
        assert_eq!(node.kind, NodeKind::File);
        let offset = (node.offset as u64) << 2;
        self.seek(SeekFrom::Start(offset))?;
        io::Result::Ok(SharedWindowedReadStream {
            base: self,
            begin: offset,
            end: offset + node.length as u64,
        })
    }

    fn read_header(&mut self) -> Result<Box<dyn PartHeader>> {
        self.seek(SeekFrom::Start(0))?;
        Result::Ok(Box::from(self.read_be::<WiiPartition>()?))
    }

    fn ideal_buffer_size(&self) -> usize {
        BLOCK_SIZE
    }
}

#[inline(always)]
fn as_digest(slice: &[u8; 20]) -> digest::Output<Sha1> { (*slice).into() }

fn decrypt_block(part: &mut WiiPartReadStream, cluster: usize) -> io::Result<()> {
    part.stream.read(&mut part.buf)?;
    if part.crypto.is_some() {
        // Fetch IV before decrypting header
        let iv = Block::from(*array_ref![part.buf, 0x3d0, 16]);
        // Don't need to decrypt header if we're not validating hashes
        if part.validate_hashes {
            Aes128Cbc::new(part.crypto.as_ref().unwrap().clone(), &Block::from([0; 16]))
                .decrypt(&mut part.buf[..BUFFER_OFFSET])
                .expect("Failed to decrypt header");
        }
        Aes128Cbc::new(part.crypto.as_ref().unwrap().clone(), &iv)
            .decrypt(&mut part.buf[BUFFER_OFFSET..])
            .expect("Failed to decrypt block");
    }
    if part.validate_hashes && part.crypto.is_some() /* FIXME NFS validation? */ {
        let (mut group, sub_group) = div_rem(cluster, 8);
        group %= 8;
        // H0 hashes
        for i in 0..31 {
            let mut hash = Sha1::new();
            hash.update(array_ref![part.buf, (i + 1) * 0x400, 0x400]);
            let expected = as_digest(array_ref![part.buf, i * 20, 20]);
            let output = hash.finalize();
            if output != expected {
                panic!("Invalid hash! (block {:?}) {:?}\n\texpected {:?}", i, output.as_slice(), expected);
            }
        }
        // H1 hash
        {
            let mut hash = Sha1::new();
            hash.update(array_ref![part.buf, 0, 0x26C]);
            let expected = as_digest(array_ref![part.buf, 0x280 + sub_group * 20, 20]);
            let output = hash.finalize();
            if output != expected {
                panic!("Invalid hash! (subgroup {:?}) {:?}\n\texpected {:?}", sub_group, output.as_slice(), expected);
            }
        }
        // H2 hash
        {
            let mut hash = Sha1::new();
            hash.update(array_ref![part.buf, 0x280, 0xA0]);
            let expected = as_digest(array_ref![part.buf, 0x340 + group * 20, 20]);
            let output = hash.finalize();
            if output != expected {
                panic!("Invalid hash! (group {:?}) {:?}\n\texpected {:?}", group, output.as_slice(), expected);
            }
        }
    }
    io::Result::Ok(())
}

impl<'a> Read for WiiPartReadStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (mut block, mut block_offset) = div_rem(self.offset as usize, BLOCK_SIZE);
        let mut rem = buf.len();
        let mut read: usize = 0;

        while rem > 0 {
            if block != self.cur_block as usize {
                decrypt_block(self, block)?;
                self.cur_block = block as u64;
            }

            let mut cache_size = rem;
            if cache_size + block_offset > BLOCK_SIZE {
                cache_size = BLOCK_SIZE - block_offset;
            }

            buf[read..read + cache_size]
                .copy_from_slice(&self.buf[BUFFER_OFFSET + block_offset..
                    BUFFER_OFFSET + block_offset + cache_size]);
            read += cache_size;
            rem -= cache_size;
            block_offset = 0;
            block += 1;
        }

        self.offset += buf.len() as u64;
        io::Result::Ok(buf.len())
    }
}

#[inline(always)]
fn to_block_size(v: u64) -> u64 {
    (v / BUFFER_SIZE as u64) * BLOCK_SIZE as u64 + (v % BUFFER_SIZE as u64)
}

impl<'a> Seek for WiiPartReadStream<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.offset = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(v) => (self.stable_stream_len()? as i64 + v) as u64,
            SeekFrom::Current(v) => (self.offset as i64 + v) as u64,
        };
        let block = self.offset / BLOCK_SIZE as u64;
        if block != self.cur_block {
            self.stream.seek(SeekFrom::Start(block * BUFFER_SIZE as u64))?;
            self.cur_block = u64::MAX;
        }
        io::Result::Ok(self.offset)
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        io::Result::Ok(self.offset)
    }
}

impl<'a> ReadStream for WiiPartReadStream<'a> {
    fn stable_stream_len(&mut self) -> io::Result<u64> {
        io::Result::Ok(to_block_size(self.stream.stable_stream_len()?))
    }
}

#[derive(Clone, Debug, PartialEq, BinRead)]
pub(crate) struct WiiPartition {
    header: Header,
    bi2_header: BI2Header,
    #[br(seek_before = SeekFrom::Start((header.fst_off as u64) << 2))]
    #[br(parse_with = node_parser)]
    root_node: NodeType,
}

impl PartHeader for WiiPartition {
    fn root_node(&self) -> &NodeType {
        &self.root_node
    }

    fn find_node(&self, path: &str) -> Option<&NodeType> {
        find_node(&self.root_node, path)
    }
}
