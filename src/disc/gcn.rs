use std::{
    io,
    io::{Read, Seek, SeekFrom},
    mem::size_of,
};

use zerocopy::FromBytes;

use crate::{
    array_ref,
    disc::{
        AppLoaderHeader, DiscBase, DiscHeader, DiscIO, DolHeader, PartitionBase, PartitionHeader,
        PartitionInfo, PartitionKind, PartitionMeta, BI2_SIZE, BOOT_SIZE, MINI_DVD_SIZE,
        SECTOR_SIZE,
    },
    fst::{Node, NodeKind},
    streams::{ReadStream, SharedWindowedReadStream},
    util::{
        div_rem,
        reader::{read_from, read_vec},
    },
    Error, OpenOptions, Result, ResultContext,
};

pub(crate) struct DiscGCN {
    pub(crate) header: DiscHeader,
    pub(crate) disc_size: u64,
    // pub(crate) junk_start: u64,
}

impl DiscGCN {
    pub(crate) fn new(
        _stream: &mut dyn ReadStream,
        header: DiscHeader,
        disc_size: Option<u64>,
    ) -> Result<DiscGCN> {
        // stream.seek(SeekFrom::Start(size_of::<DiscHeader>() as u64)).context("Seeking to partition header")?;
        // let partition_header: PartitionHeader = read_from(stream).context("Reading partition header")?;
        // let junk_start = partition_header.fst_off(false) + partition_header.fst_sz(false);
        Ok(DiscGCN { header, disc_size: disc_size.unwrap_or(MINI_DVD_SIZE) /*, junk_start*/ })
    }
}

fn open_partition<'a>(disc_io: &'a dyn DiscIO) -> Result<Box<dyn PartitionBase + 'a>> {
    let stream = disc_io.open()?;
    Ok(Box::new(PartitionGC { stream, offset: 0, cur_block: u32::MAX, buf: [0; SECTOR_SIZE] }))
}

impl DiscBase for DiscGCN {
    fn header(&self) -> &DiscHeader { &self.header }

    fn partitions(&self) -> Vec<PartitionInfo> {
        vec![PartitionInfo {
            group_index: 0,
            part_index: 0,
            part_offset: 0,
            kind: PartitionKind::Data,
            data_offset: 0,
            data_size: self.disc_size,
            header: None,
            lfg_seed: *array_ref!(self.header.game_id, 0, 4),
            // junk_start: self.junk_start,
        }]
    }

    fn open_partition<'a>(
        &self,
        disc_io: &'a dyn DiscIO,
        index: usize,
        _options: &OpenOptions,
    ) -> Result<Box<dyn PartitionBase + 'a>> {
        if index != 0 {
            return Err(Error::DiscFormat(format!(
                "Invalid partition index {} for GameCube disc",
                index
            )));
        }
        open_partition(disc_io)
    }

    fn open_partition_kind<'a>(
        &self,
        disc_io: &'a dyn DiscIO,
        part_type: PartitionKind,
        _options: &OpenOptions,
    ) -> Result<Box<dyn PartitionBase + 'a>> {
        if part_type != PartitionKind::Data {
            return Err(Error::DiscFormat(format!(
                "Invalid partition type {:?} for GameCube disc",
                part_type
            )));
        }
        open_partition(disc_io)
    }

    fn disc_size(&self) -> u64 { self.disc_size }
}

struct PartitionGC<'a> {
    stream: Box<dyn ReadStream + 'a>,
    offset: u64,
    cur_block: u32,
    buf: [u8; SECTOR_SIZE],
}

impl<'a> Read for PartitionGC<'a> {
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

impl<'a> Seek for PartitionGC<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.offset = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(v) => self.stable_stream_len()?.saturating_add_signed(v),
            SeekFrom::Current(v) => self.offset.saturating_add_signed(v),
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

impl<'a> ReadStream for PartitionGC<'a> {
    fn stable_stream_len(&mut self) -> io::Result<u64> { self.stream.stable_stream_len() }

    fn as_dyn(&mut self) -> &mut dyn ReadStream { self }
}

impl<'a> PartitionBase for PartitionGC<'a> {
    fn meta(&mut self) -> Result<Box<PartitionMeta>> {
        self.seek(SeekFrom::Start(0)).context("Seeking to partition header")?;
        read_part_header(self, false)
    }

    fn open_file(&mut self, node: &Node) -> io::Result<SharedWindowedReadStream> {
        assert_eq!(node.kind(), NodeKind::File);
        self.new_window(node.offset(false), node.length(false))
    }

    fn ideal_buffer_size(&self) -> usize { SECTOR_SIZE }
}

pub(crate) fn read_part_header<R>(reader: &mut R, is_wii: bool) -> Result<Box<PartitionMeta>>
where R: Read + Seek + ?Sized {
    // boot.bin
    let raw_boot: [u8; BOOT_SIZE] = read_from(reader).context("Reading boot.bin")?;
    let partition_header = PartitionHeader::ref_from(&raw_boot[size_of::<DiscHeader>()..]).unwrap();

    // bi2.bin
    let raw_bi2: [u8; BI2_SIZE] = read_from(reader).context("Reading bi2.bin")?;

    // apploader.bin
    let mut raw_apploader: Vec<u8> =
        read_vec(reader, size_of::<AppLoaderHeader>()).context("Reading apploader header")?;
    let apploader_header = AppLoaderHeader::ref_from(raw_apploader.as_slice()).unwrap();
    raw_apploader.resize(
        size_of::<AppLoaderHeader>()
            + apploader_header.size.get() as usize
            + apploader_header.trailer_size.get() as usize,
        0,
    );
    reader
        .read_exact(&mut raw_apploader[size_of::<AppLoaderHeader>()..])
        .context("Reading apploader")?;

    // fst.bin
    reader
        .seek(SeekFrom::Start(partition_header.fst_off(is_wii)))
        .context("Seeking to FST offset")?;
    let raw_fst: Vec<u8> = read_vec(reader, partition_header.fst_sz(is_wii) as usize)
        .with_context(|| {
            format!(
                "Reading partition FST (offset {}, size {})",
                partition_header.fst_off, partition_header.fst_sz
            )
        })?;

    // main.dol
    reader
        .seek(SeekFrom::Start(partition_header.dol_off(is_wii)))
        .context("Seeking to DOL offset")?;
    let mut raw_dol: Vec<u8> =
        read_vec(reader, size_of::<DolHeader>()).context("Reading DOL header")?;
    let dol_header = DolHeader::ref_from(raw_dol.as_slice()).unwrap();
    let dol_size = dol_header
        .text_offs
        .iter()
        .zip(&dol_header.text_sizes)
        .map(|(offs, size)| offs.get() + size.get())
        .chain(
            dol_header
                .data_offs
                .iter()
                .zip(&dol_header.data_sizes)
                .map(|(offs, size)| offs.get() + size.get()),
        )
        .max()
        .unwrap_or(size_of::<DolHeader>() as u32);
    raw_dol.resize(dol_size as usize, 0);
    reader.read_exact(&mut raw_dol[size_of::<DolHeader>()..]).context("Reading DOL")?;

    Ok(Box::new(PartitionMeta {
        raw_boot,
        raw_bi2,
        raw_apploader,
        raw_fst,
        raw_dol,
        raw_ticket: None,
        raw_tmd: None,
        raw_cert_chain: None,
        raw_h3_table: None,
    }))
}
