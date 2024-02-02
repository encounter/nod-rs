use std::{
    io,
    io::{Cursor, Read, Seek, SeekFrom},
};

use crate::{
    disc::{
        AppLoaderHeader, DiscBase, DiscIO, DolHeader, Header, PartHeader, PartReadStream,
        PartitionHeader, PartitionType, SECTOR_SIZE,
    },
    fst::{find_node, read_fst, Node, NodeKind, NodeType},
    streams::{ReadStream, SharedWindowedReadStream},
    util::{
        div_rem,
        reader::{read_bytes, FromReader},
    },
    Error, Result, ResultContext,
};

pub(crate) struct DiscGCN {
    pub(crate) header: Header,
}

impl DiscGCN {
    pub(crate) fn new(header: Header) -> Result<DiscGCN> { Ok(DiscGCN { header }) }
}

impl DiscBase for DiscGCN {
    fn get_header(&self) -> &Header { &self.header }

    fn get_data_partition<'a>(
        &self,
        disc_io: &'a mut dyn DiscIO,
        _validate_hashes: bool,
    ) -> Result<Box<dyn PartReadStream + 'a>> {
        let stream = disc_io.begin_read_stream(0).context("Opening data partition stream")?;
        Ok(Box::from(GCPartReadStream {
            stream,
            offset: 0,
            cur_block: u32::MAX,
            buf: [0; SECTOR_SIZE],
        }))
    }

    fn get_partition<'a>(
        &self,
        disc_io: &'a mut dyn DiscIO,
        part_type: PartitionType,
        _validate_hashes: bool,
    ) -> Result<Box<dyn PartReadStream + 'a>> {
        if part_type == PartitionType::Data {
            Ok(Box::from(GCPartReadStream {
                stream: disc_io.begin_read_stream(0).context("Opening partition read stream")?,
                offset: 0,
                cur_block: u32::MAX,
                buf: [0; SECTOR_SIZE],
            }))
        } else {
            Err(Error::DiscFormat(format!(
                "Invalid partition type {:?} for GameCube disc",
                part_type
            )))
        }
    }
}

struct GCPartReadStream<'a> {
    stream: Box<dyn ReadStream + 'a>,
    offset: u64,
    cur_block: u32,
    buf: [u8; SECTOR_SIZE],
}

impl<'a> Read for GCPartReadStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (block, block_offset) = div_rem(self.offset, SECTOR_SIZE as u64);
        let mut block = block as u32;
        let mut block_offset = block_offset as usize;

        let mut rem = buf.len();
        let mut read: usize = 0;

        while rem > 0 {
            if block != self.cur_block {
                self.stream.read_exact(&mut self.buf)?;
                self.cur_block = block;
            }

            let mut cache_size = rem;
            if cache_size + block_offset > SECTOR_SIZE {
                cache_size = SECTOR_SIZE - block_offset;
            }

            buf[read..read + cache_size]
                .copy_from_slice(&self.buf[block_offset..block_offset + cache_size]);
            read += cache_size;
            rem -= cache_size;
            block_offset = 0;
            block += 1;
        }

        self.offset += buf.len() as u64;
        Ok(buf.len())
    }
}

impl<'a> Seek for GCPartReadStream<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.offset = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(v) => (self.stable_stream_len()? as i64 + v) as u64,
            SeekFrom::Current(v) => (self.offset as i64 + v) as u64,
        };
        let block = self.offset / SECTOR_SIZE as u64;
        if block as u32 != self.cur_block {
            self.stream.seek(SeekFrom::Start(block * SECTOR_SIZE as u64))?;
            self.cur_block = u32::MAX;
        }
        Ok(self.offset)
    }

    fn stream_position(&mut self) -> io::Result<u64> { Ok(self.offset) }
}

impl<'a> ReadStream for GCPartReadStream<'a> {
    fn stable_stream_len(&mut self) -> io::Result<u64> { self.stream.stable_stream_len() }

    fn as_dyn(&mut self) -> &mut dyn ReadStream { self }
}

impl<'a> PartReadStream for GCPartReadStream<'a> {
    fn begin_file_stream(&mut self, node: &Node) -> io::Result<SharedWindowedReadStream> {
        assert_eq!(node.kind, NodeKind::File);
        self.new_window(node.offset as u64, node.length as u64)
    }

    fn read_header(&mut self) -> Result<Box<dyn PartHeader>> {
        self.seek(SeekFrom::Start(0)).context("Seeking to partition header")?;
        Ok(Box::from(read_part_header(self)?))
    }

    fn ideal_buffer_size(&self) -> usize { SECTOR_SIZE }
}

const BOOT_SIZE: usize = Header::STATIC_SIZE + PartitionHeader::STATIC_SIZE;
const BI2_SIZE: usize = 0x2000;

#[derive(Clone, Debug)]
pub(crate) struct GCPartition {
    raw_boot: [u8; BOOT_SIZE],
    raw_bi2: [u8; BI2_SIZE],
    raw_apploader: Vec<u8>,
    raw_fst: Vec<u8>,
    raw_dol: Vec<u8>,
    // Parsed
    header: Header,
    partition_header: PartitionHeader,
    apploader_header: AppLoaderHeader,
    root_node: NodeType,
    dol_header: DolHeader,
}

fn read_part_header<R>(reader: &mut R) -> Result<GCPartition>
where R: Read + Seek + ?Sized {
    // boot.bin
    let raw_boot = <[u8; BOOT_SIZE]>::from_reader(reader).context("Reading boot.bin")?;
    let mut boot_bytes = raw_boot.as_slice();
    let header = Header::from_reader(&mut boot_bytes).context("Parsing disc header")?;
    let partition_header =
        PartitionHeader::from_reader(&mut boot_bytes).context("Parsing partition header")?;
    debug_assert_eq!(boot_bytes.len(), 0, "failed to consume boot.bin");

    // bi2.bin
    let raw_bi2 = <[u8; BI2_SIZE]>::from_reader(reader).context("Reading bi2.bin")?;

    // apploader.bin
    let mut raw_apploader =
        read_bytes(reader, AppLoaderHeader::STATIC_SIZE).context("Reading apploader header")?;
    let apploader_header = AppLoaderHeader::from_reader(&mut raw_apploader.as_slice())
        .context("Parsing apploader header")?;
    raw_apploader.resize(
        AppLoaderHeader::STATIC_SIZE
            + apploader_header.size as usize
            + apploader_header.trailer_size as usize,
        0,
    );
    reader
        .read_exact(&mut raw_apploader[AppLoaderHeader::STATIC_SIZE..])
        .context("Reading apploader")?;

    // fst.bin
    reader
        .seek(SeekFrom::Start(partition_header.fst_off as u64))
        .context("Seeking to FST offset")?;
    let raw_fst = read_bytes(reader, partition_header.fst_sz as usize).with_context(|| {
        format!(
            "Reading partition FST (offset {}, size {})",
            partition_header.fst_off, partition_header.fst_sz
        )
    })?;
    let root_node = read_fst(&mut Cursor::new(&*raw_fst))?;

    // main.dol
    reader
        .seek(SeekFrom::Start(partition_header.dol_off as u64))
        .context("Seeking to DOL offset")?;
    let mut raw_dol = read_bytes(reader, DolHeader::STATIC_SIZE).context("Reading DOL header")?;
    let dol_header =
        DolHeader::from_reader(&mut raw_dol.as_slice()).context("Parsing DOL header")?;
    let dol_size = dol_header
        .text_offs
        .iter()
        .zip(&dol_header.text_sizes)
        .map(|(offs, size)| offs + size)
        .chain(
            dol_header.data_offs.iter().zip(&dol_header.data_sizes).map(|(offs, size)| offs + size),
        )
        .max()
        .unwrap_or(DolHeader::STATIC_SIZE as u32);
    raw_dol.resize(dol_size as usize, 0);
    reader.read_exact(&mut raw_dol[DolHeader::STATIC_SIZE..]).context("Reading DOL")?;

    Ok(GCPartition {
        raw_boot,
        raw_bi2,
        raw_apploader,
        raw_fst,
        raw_dol,
        header,
        partition_header,
        apploader_header,
        root_node,
        dol_header,
    })
}

impl PartHeader for GCPartition {
    fn root_node(&self) -> &NodeType { &self.root_node }

    fn find_node(&self, path: &str) -> Option<&NodeType> { find_node(&self.root_node, path) }

    fn boot_bytes(&self) -> &[u8] { &self.raw_boot }

    fn bi2_bytes(&self) -> &[u8] { &self.raw_bi2 }

    fn apploader_bytes(&self) -> &[u8] { &self.raw_apploader }

    fn fst_bytes(&self) -> &[u8] { &self.raw_fst }

    fn dol_bytes(&self) -> &[u8] { &self.raw_dol }

    fn disc_header(&self) -> &Header { &self.header }

    fn partition_header(&self) -> &PartitionHeader { &self.partition_header }

    fn apploader_header(&self) -> &AppLoaderHeader { &self.apploader_header }

    fn dol_header(&self) -> &DolHeader { &self.dol_header }
}
