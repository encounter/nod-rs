use std::path::{Path, PathBuf};

use argp::FromArgs;
use nod::{
    common::PartitionKind,
    disc::fst::Fst,
    read::{DiscOptions, DiscReader, PartitionOptions},
};
use tracing::info;

use crate::util::path_display;

#[derive(FromArgs, Debug)]
/// Displays information about disc images.
#[argp(subcommand, name = "list")]
pub struct Args {
    #[argp(positional)]
    /// Path to disc image(s)
    file: Vec<PathBuf>,
}

pub fn run(args: Args) -> nod::Result<()> {
    for file in &args.file {
        list_file(file)?;
    }
    Ok(())
}

fn print_fst(fst: Fst, kind: Option<PartitionKind>) {
    for (_idx, node, name) in fst.iter() {
        if let Some(kind) = kind {
            print!("{kind}/");
        }
        println!("{name}{}", if node.is_dir() { "/" } else { "" });
    }
}

fn list_file(path: &Path) -> nod::Result<(), nod::Error> {
    info!("Loading {}", path_display(path));

    if path.ends_with("fst.bin") {
        let bytes = std::fs::read(path)?;
        print_fst(Fst::new(&bytes)?, None);
        return Ok(());
    }

    let disc = DiscReader::new(path, &DiscOptions::default())?;
    let header = disc.header();

    if header.is_wii() {
        for (idx, info) in disc.partitions().iter().enumerate() {
            let mut partition = disc.open_partition(idx, &PartitionOptions::default())?;
            let meta = partition.meta()?;
            print_fst(meta.fst()?, Some(info.kind));
        }
    } else if header.is_gamecube() {
        let mut partition =
            disc.open_partition_kind(PartitionKind::Data, &PartitionOptions::default())?;
        let meta = partition.meta()?;
        print_fst(meta.fst()?, None);
    } else {
        println!("Invalid GC/Wii magic: {:#x?}/{:#x?}", header.gcn_magic, header.wii_magic);
    }

    Ok(())
}
