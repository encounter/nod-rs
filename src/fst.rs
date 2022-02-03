//! Disc file system types

use std::io::{Read, Seek, SeekFrom};

use binrw::{binread, BinReaderExt, BinResult, NullString, ReadOptions};
use encoding_rs::SHIFT_JIS;

/// File system node kind.
#[derive(Clone, Debug, PartialEq)]
pub enum NodeKind {
    File,
    Directory,
}

/// An individual file system node.
#[binread]
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    #[br(temp)]
    type_and_name_offset: u32,
    #[br(calc = if (type_and_name_offset >> 24) != 0 { NodeKind::Directory } else { NodeKind::File })]
    pub kind: NodeKind,

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

    #[br(calc = type_and_name_offset & 0xffffff)]
    name_offset: u32,
    #[br(ignore)]
    /// The node name.
    pub name: Box<str>,
}

/// Contains a file system node, and if a directory, its children.
#[derive(Clone, Debug, PartialEq)]
pub enum NodeType {
    /// A single file node.
    File(Node),
    /// A directory node with children.
    Directory(Node, Vec<NodeType>),
}

fn read_node<R: Read + Seek>(reader: &mut R, ro: &ReadOptions, i: &mut u32) -> BinResult<NodeType> {
    let node = reader.read_type::<Node>(ro.endian())?;
    *i += 1;
    BinResult::Ok(if node.kind == NodeKind::Directory {
        let mut children: Vec<NodeType> = Vec::new();
        children.reserve((node.length - *i) as usize);
        while *i < node.length {
            children.push(read_node(reader, ro, i)?);
        }
        NodeType::Directory(node, children)
    } else {
        NodeType::File(node)
    })
}

fn read_node_name<R: Read + Seek>(
    reader: &mut R,
    ro: &ReadOptions,
    base: u64,
    node: &mut NodeType,
    root: bool,
) -> BinResult<()> {
    let mut decode_name = |v: &mut Node| -> BinResult<()> {
        if !root {
            let offset = base + v.name_offset as u64;
            reader.seek(SeekFrom::Start(offset))?;
            let null_string = reader.read_type::<NullString>(ro.endian())?;
            let (res, _, errors) = SHIFT_JIS.decode(&*null_string.0);
            if errors {
                return BinResult::Err(binrw::Error::Custom {
                    pos: offset,
                    err: Box::new("Failed to decode node name"),
                });
            }
            v.name = res.into();
        }
        BinResult::Ok(())
    };
    match node {
        NodeType::File(v) => {
            decode_name(v)?;
        }
        NodeType::Directory(v, c) => {
            decode_name(v)?;
            for x in c {
                read_node_name(reader, ro, base, x, false)?;
            }
        }
    }
    BinResult::Ok(())
}

pub(crate) fn node_parser<R: Read + Seek>(
    reader: &mut R,
    ro: &ReadOptions,
    _: (),
) -> BinResult<NodeType> {
    let mut node = read_node(reader, ro, &mut 0)?;
    let base = reader.stream_position()?;
    read_node_name(reader, ro, base, &mut node, true)?;
    BinResult::Ok(node)
}

fn matches_name(node: &NodeType, name: &str) -> bool {
    match node {
        NodeType::File(v) => v.name.as_ref().eq_ignore_ascii_case(name),
        NodeType::Directory(v, _) => {
            v.name.is_empty() /* root */ || v.name.as_ref().eq_ignore_ascii_case(name)
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
                    return if split.next().is_none() { Option::Some(node) } else { Option::None };
                }
                NodeType::Directory(v, c) => {
                    // Find child
                    if !v.name.is_empty() || current.unwrap().is_empty() {
                        current = split.next();
                    }
                    if current.is_none() || current.unwrap().is_empty() {
                        return if split.next().is_none() {
                            Option::Some(node)
                        } else {
                            Option::None
                        };
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
    Option::None
}
