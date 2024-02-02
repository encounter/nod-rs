//! Disc file system types

use std::{
    ffi::CString,
    io,
    io::{Read, Seek, SeekFrom},
};

use encoding_rs::SHIFT_JIS;

use crate::{
    util::reader::{struct_size, FromReader, DYNAMIC_SIZE, U24},
    Result, ResultContext,
};

/// File system node kind.
#[derive(Clone, Debug, PartialEq)]
pub enum NodeKind {
    /// Node is a file.
    File,
    /// Node is a directory.
    Directory,
}

impl FromReader for NodeKind {
    type Args<'a> = ();

    const STATIC_SIZE: usize = 1;

    fn from_reader_args<R>(_reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        match u8::from_reader(_reader)? {
            0 => Ok(NodeKind::File),
            1 => Ok(NodeKind::Directory),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid node kind")),
        }
    }
}

/// An individual file system node.
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    /// File system node type.
    pub kind: NodeKind,

    /// Offset in the string table to the filename.
    pub name_offset: u32,

    /// For files, this is the partition offset of the file data. (Wii: >> 2)
    ///
    /// For directories, this is the children start offset in the FST.
    pub offset: u32,

    /// For files, this is the byte size of the file.
    ///
    /// For directories, this is the children end offset in the FST.
    ///
    /// Number of child files and directories recursively is `length - offset`.
    pub length: u32,

    /// The node name.
    pub name: String,
}

impl FromReader for Node {
    type Args<'a> = ();

    const STATIC_SIZE: usize = struct_size([
        NodeKind::STATIC_SIZE, // type
        U24::STATIC_SIZE,      // name_offset
        u32::STATIC_SIZE,      // offset
        u32::STATIC_SIZE,      // length
    ]);

    fn from_reader_args<R>(reader: &mut R, _args: Self::Args<'_>) -> io::Result<Self>
    where R: Read + ?Sized {
        let kind = NodeKind::from_reader(reader)?;
        let name_offset = U24::from_reader(reader)?.0;
        let offset = u32::from_reader(reader)?;
        let length = u32::from_reader(reader)?;
        Ok(Node { kind, offset, length, name_offset, name: Default::default() })
    }
}

/// Contains a file system node, and if a directory, its children.
#[derive(Clone, Debug, PartialEq)]
pub enum NodeType {
    /// A single file node.
    File(Node),
    /// A directory node with children.
    Directory(Node, Vec<NodeType>),
}

impl FromReader for NodeType {
    type Args<'a> = &'a mut u32;

    const STATIC_SIZE: usize = DYNAMIC_SIZE;

    fn from_reader_args<R>(reader: &mut R, idx: &mut u32) -> io::Result<Self>
    where R: Read + ?Sized {
        let node = Node::from_reader(reader)?;
        *idx += 1;
        Ok(if node.kind == NodeKind::Directory {
            let mut children = Vec::with_capacity((node.length - *idx) as usize);
            while *idx < node.length {
                children.push(NodeType::from_reader_args(reader, idx)?);
            }
            NodeType::Directory(node, children)
        } else {
            NodeType::File(node)
        })
    }
}

fn read_node_name<R>(
    reader: &mut R,
    string_base: u64,
    node: &mut NodeType,
    root: bool,
) -> io::Result<()>
where
    R: Read + Seek + ?Sized,
{
    let mut decode_name = |v: &mut Node| -> io::Result<()> {
        if !root {
            let offset = string_base + v.name_offset as u64;
            reader.seek(SeekFrom::Start(offset))?;

            let c_string = CString::from_reader(reader)?;
            let (decoded, _, errors) = SHIFT_JIS.decode(c_string.as_bytes());
            if errors {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid shift-jis"));
            }
            v.name = decoded.into_owned();
        }
        Ok(())
    };
    match node {
        NodeType::File(inner) => {
            decode_name(inner)?;
        }
        NodeType::Directory(inner, children) => {
            decode_name(inner)?;
            for child in children {
                read_node_name(reader, string_base, child, false)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn read_fst<R>(reader: &mut R) -> Result<NodeType>
where R: Read + Seek + ?Sized {
    let mut node = NodeType::from_reader_args(reader, &mut 0).context("Parsing FST nodes")?;
    let string_base = reader.stream_position().context("Reading FST end position")?;
    read_node_name(reader, string_base, &mut node, true).context("Reading FST node names")?;
    Ok(node)
}

fn matches_name(node: &NodeType, name: &str) -> bool {
    match node {
        NodeType::File(v) => v.name.as_str().eq_ignore_ascii_case(name),
        NodeType::Directory(v, _) => {
            v.name.is_empty() /* root */ || v.name.as_str().eq_ignore_ascii_case(name)
        }
    }
}

pub(crate) fn find_node<'a>(mut node: &'a NodeType, path: &str) -> Option<&'a NodeType> {
    let mut split = path.split('/');
    let mut current = split.next();
    while current.is_some() {
        if matches_name(node, current.unwrap()) {
            match node {
                NodeType::File(_) => {
                    return if split.next().is_none() { Some(node) } else { None };
                }
                NodeType::Directory(v, c) => {
                    // Find child
                    if !v.name.is_empty() || current.unwrap().is_empty() {
                        current = split.next();
                    }
                    if current.is_none() || current.unwrap().is_empty() {
                        return if split.next().is_none() { Some(node) } else { None };
                    }
                    for x in c {
                        if matches_name(x, current.unwrap()) {
                            node = x;
                            break;
                        }
                    }
                }
            }
        } else {
            break;
        }
    }
    None
}
