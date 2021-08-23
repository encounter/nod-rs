use std::{env, fs, io};
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use clap::{AppSettings, clap_app};
use file_size;

use nod::disc::{new_disc_base, PartReadStream};
use nod::fst::NodeType;
use nod::io::{has_extension, new_disc_io};
use nod::Result;

fn main() -> Result<()> {
    let matches = clap_app!(nodtool =>
        (settings: &[
            AppSettings::SubcommandRequiredElseHelp,
            AppSettings::GlobalVersion,
            AppSettings::DeriveDisplayOrder,
            AppSettings::VersionlessSubcommands,
        ])
        (global_settings: &[
            AppSettings::ColoredHelp,
            AppSettings::UnifiedHelpMessage,
        ])
        (version: env!("CARGO_PKG_VERSION"))
        (author: "Luke Street <luke@street.dev>")
        (about: "Tool for reading GameCube and Wii disc images.")
        (long_about: "Tool for reading GameCube and Wii disc images.

Based on <https://github.com/AxioDL/nod>, original authors:
Jack Andersen (jackoalan)
Phillip Stephens (Antidote)")
        (@subcommand extract =>
            (about: "Extract GameCube & Wii disc images")
            (@arg FILE: +required "Path to disc image (ISO or NFS)")
            (@arg DIR: "Output directory (optional)")
            (@arg quiet: -q "Quiet output")
        )
    ).get_matches();
    if let Some(matches) = matches.subcommand_matches("extract") {
        let file: PathBuf = PathBuf::from(matches.value_of("FILE").unwrap());
        let output_dir: PathBuf;
        if let Some(dir) = matches.value_of("DIR") {
            output_dir = PathBuf::from(dir);
        } else if has_extension(file.as_path(), "nfs") {
            // Special logic to extract from content/hif_*.nfs to extracted/..
            if let Some(parent) = file.parent() {
                output_dir = parent.with_file_name("extracted");
            } else {
                output_dir = file.with_extension("");
            }
        } else {
            output_dir = file.with_extension("");
        }
        let mut disc_io = new_disc_io(file.as_path())?;
        let disc_base = new_disc_base(disc_io.as_mut())?;
        let mut partition = disc_base.get_data_partition(disc_io.as_mut())?;
        let header = partition.read_header()?;
        extract_node(header.root_node(), partition.as_mut(), output_dir.as_path())?;
    }
    Result::Ok(())
}

fn extract_node(node: &NodeType, partition: &mut dyn PartReadStream, base_path: &Path) -> io::Result<()> {
    match node {
        NodeType::File(v) => {
            let mut file_path = base_path.to_owned();
            file_path.push(v.name.as_ref());
            println!("Extracting {} (size: {})", file_path.to_string_lossy(), file_size::fit_4(v.length as u64));
            let file = fs::File::create(file_path)?;
            let mut buf_writer = BufWriter::with_capacity(partition.ideal_buffer_size(), file);
            io::copy(&mut partition.begin_file_stream(v)?, &mut buf_writer)?;
        }
        NodeType::Directory(v, c) => {
            if v.name.is_empty() {
                fs::create_dir_all(base_path)?;
                for x in c {
                    extract_node(x, partition, base_path)?;
                }
            } else {
                let mut new_base = base_path.to_owned();
                new_base.push(v.name.as_ref());
                fs::create_dir_all(&new_base)?;
                for x in c {
                    extract_node(x, partition, new_base.as_path())?;
                }
            }
        }
    }
    io::Result::Ok(())
}
