use std::io;
use std::io::{Read, Seek, SeekFrom};

use binread::prelude::*;

use crate::{div_rem, Result};
use crate::disc::{BI2Header, BUFFER_SIZE, DiscBase, DiscIO, Header, PartHeader, PartReadStream};
use crate::fst::{find_node, Node, node_parser, NodeKind, NodeType};
use crate::streams::{ReadStream, SharedWindowedReadStream};

pub(crate) struct DiscGCN {
    pub(crate) header: Header,
}

pub(crate) fn new_disc_gcn(header: Header) -> Result<DiscGCN> {
    Result::Ok(DiscGCN {
        header
    })
}

impl DiscBase for DiscGCN {
    fn get_header(&self) -> &Header {
        &self.header
    }

    fn get_data_partition<'a>(&self, disc_io: &'a mut dyn DiscIO) -> Result<Box<dyn PartReadStream + 'a>> {
        Result::Ok(Box::from(GCPartReadStream {
            stream: disc_io.begin_read_stream(0)?,
            offset: 0,
            cur_block: u64::MAX,
            buf: [0; BUFFER_SIZE],
        }))
    }
}

struct GCPartReadStream<'a> {
    stream: Box<dyn ReadStream + 'a>,
    offset: u64,
    cur_block: u64,
    buf: [u8; BUFFER_SIZE],
}


impl<'a> Read for GCPartReadStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (mut block, mut block_offset) = div_rem(self.offset as usize, BUFFER_SIZE);
        let mut rem = buf.len();
        let mut read: usize = 0;

        while rem > 0 {
            if block != self.cur_block as usize {
                self.stream.read(&mut self.buf)?;
                self.cur_block = block as u64;
            }

            let mut cache_size = rem;
            if cache_size + block_offset > BUFFER_SIZE {
                cache_size = BUFFER_SIZE - block_offset;
            }

            buf[read..read + cache_size]
                .copy_from_slice(&self.buf[block_offset..block_offset + cache_size]);
            read += cache_size;
            rem -= cache_size;
            block_offset = 0;
            block += 1;
        }

        self.offset += buf.len() as u64;
        io::Result::Ok(buf.len())
    }
}

impl<'a> Seek for GCPartReadStream<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.offset = match pos {
            SeekFrom::Start(v) => v,
            SeekFrom::End(v) => (self.stable_stream_len()? as i64 + v) as u64,
            SeekFrom::Current(v) => (self.offset as i64 + v) as u64,
        };
        let block = self.offset / BUFFER_SIZE as u64;
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

impl<'a> ReadStream for GCPartReadStream<'a> {
    fn stable_stream_len(&mut self) -> io::Result<u64> {
        self.stream.stable_stream_len()
    }
}

impl<'a> PartReadStream for GCPartReadStream<'a> {
    fn begin_file_stream(&mut self, node: &Node) -> io::Result<SharedWindowedReadStream> {
        assert_eq!(node.kind, NodeKind::File);
        io::Result::Ok(self.new_window(node.offset as u64, node.length as u64)?)
    }

    fn read_header(&mut self) -> Result<Box<dyn PartHeader>> {
        self.seek(SeekFrom::Start(0))?;
        Result::Ok(Box::from(self.read_be::<GCPartition>()?))
    }

    fn ideal_buffer_size(&self) -> usize {
        BUFFER_SIZE
    }
}

#[derive(Clone, Debug, PartialEq, BinRead)]
pub(crate) struct GCPartition {
    header: Header,
    bi2_header: BI2Header,
    #[br(seek_before = SeekFrom::Start(header.fst_off as u64))]
    #[br(parse_with = node_parser)]
    root_node: NodeType,
}

impl PartHeader for GCPartition {
    fn root_node(&self) -> &NodeType {
        &self.root_node
    }

    fn find_node(&self, path: &str) -> Option<&NodeType> {
        find_node(&self.root_node, path)
    }
}
