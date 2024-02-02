use std::{
    error::Error,
    fs,
    fs::File,
    io,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use argh_derive::FromArgs;
use nod::{
    disc::{new_disc_base, PartHeader, PartReadStream, PartitionType},
    fst::NodeType,
    io::{has_extension, new_disc_io, DiscIOOptions},
    Result, ResultContext,
};
use sha1::Digest;

#[derive(FromArgs, Debug)]
/// Tool for reading GameCube and Wii disc images.
struct TopLevel {
    #[argh(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum SubCommand {
    Extract(ExtractArgs),
    Convert(ConvertArgs),
    Verify(VerifyArgs),
}

#[derive(FromArgs, Debug)]
/// Extract a disc image.
#[argh(subcommand, name = "extract")]
struct ExtractArgs {
    #[argh(positional)]
    /// path to disc image (ISO or NFS)
    file: PathBuf,
    #[argh(positional)]
    /// output directory (optional)
    out: Option<PathBuf>,
    #[argh(switch, short = 'q')]
    /// quiet output
    quiet: bool,
    #[argh(switch, short = 'h')]
    /// validate disc hashes (Wii only)
    validate: bool,
}

#[derive(FromArgs, Debug)]
/// Extract a disc image.
#[argh(subcommand, name = "convert")]
struct ConvertArgs {
    #[argh(positional)]
    /// path to disc image
    file: PathBuf,
    #[argh(positional)]
    /// output ISO file
    out: PathBuf,
}

#[derive(FromArgs, Debug)]
/// Verifies a disc image.
#[argh(subcommand, name = "verify")]
struct VerifyArgs {
    #[argh(positional)]
    /// path to disc image
    file: PathBuf,
}

fn main() {
    let args: TopLevel = argh::from_env();
    let result = match args.command {
        SubCommand::Convert(c_args) => convert(c_args),
        SubCommand::Extract(c_args) => extract(c_args),
        SubCommand::Verify(c_args) => verify(c_args),
    };
    if let Err(e) = result {
        eprintln!("Failed: {}", e);
        if let Some(source) = e.source() {
            eprintln!("Caused by: {}", source);
        }
        std::process::exit(1);
    }
}

fn convert(args: ConvertArgs) -> Result<()> { convert_and_verify(&args.file, Some(&args.out)) }

fn verify(args: VerifyArgs) -> Result<()> { convert_and_verify(&args.file, None) }

fn convert_and_verify(in_file: &Path, out_file: Option<&Path>) -> Result<()> {
    println!("Loading {}", in_file.display());
    let mut disc_io = new_disc_io(in_file, &DiscIOOptions { rebuild_hashes: true })?;
    let disc_base = new_disc_base(disc_io.as_mut())?;
    let header = disc_base.get_header();
    println!(
        "\nGame ID: {}{}{}{}{}{}",
        header.game_id[0] as char,
        header.game_id[1] as char,
        header.game_id[2] as char,
        header.game_id[3] as char,
        header.game_id[4] as char,
        header.game_id[5] as char
    );
    println!("Game title: {}", header.game_title);
    println!("Disc num: {}", header.disc_num);
    println!("Disc version: {}", header.disc_version);

    let mut stream = disc_io.begin_read_stream(0).context("Creating disc read stream")?;
    let mut crc = crc32fast::Hasher::new();
    let mut md5 = md5::Md5::new();
    let mut sha1 = sha1::Sha1::new();

    let mut file = if let Some(out_file) = out_file {
        Some(
            File::create(out_file)
                .with_context(|| format!("Creating file {}", out_file.display()))?,
        )
    } else {
        None
    };

    const BUFFER_SIZE: usize = 1015808; // LCM(0x8000, 0x7C00)
    let mut buf = vec![0u8; BUFFER_SIZE];
    let mut total_read = 0u64;
    loop {
        let read = stream.read(&mut buf).with_context(|| {
            format!("Reading {} bytes at disc offset {}", BUFFER_SIZE, total_read)
        })?;
        if read == 0 {
            break;
        }
        let slice = &buf[..read];
        crc.update(slice);
        md5.update(slice);
        sha1.update(slice);
        if let Some(file) = &mut file {
            file.write_all(slice).with_context(|| {
                format!("Writing {} bytes at offset {}", slice.len(), total_read)
            })?;
        }
        total_read += read as u64;
    }

    println!();
    println!("CRC32: {:08x}", crc.finalize());
    println!("MD5:   {:032x}", md5.finalize());
    println!("SHA-1: {:040x}", sha1.finalize());
    if let (Some(path), Some(file)) = (out_file, &mut file) {
        file.flush().context("Flushing output file")?;
        println!("Wrote {} to {}", file_size::fit_4(total_read), path.display());
    }
    Ok(())
}

fn extract(args: ExtractArgs) -> Result<()> {
    let output_dir: PathBuf;
    if let Some(dir) = args.out {
        output_dir = dir;
    } else if has_extension(&args.file, "nfs") {
        // Special logic to extract from content/hif_*.nfs to extracted/..
        if let Some(parent) = args.file.parent() {
            output_dir = parent.with_file_name("extracted");
        } else {
            output_dir = args.file.with_extension("");
        }
    } else {
        output_dir = args.file.with_extension("");
    }
    let mut disc_io = new_disc_io(&args.file, &DiscIOOptions { rebuild_hashes: args.validate })?;
    let disc_base = new_disc_base(disc_io.as_mut())?;
    let mut partition =
        disc_base.get_partition(disc_io.as_mut(), PartitionType::Data, args.validate)?;
    let header = partition.read_header()?;
    extract_sys_files(header.as_ref(), &output_dir.join("sys"), args.quiet)?;
    extract_node(header.root_node(), partition.as_mut(), &output_dir.join("files"), args.quiet)?;
    Ok(())
}

fn extract_sys_files(header: &dyn PartHeader, out_dir: &Path, quiet: bool) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("Creating output directory {}", out_dir.display()))?;
    extract_file(header.boot_bytes(), &out_dir.join("boot.bin"), quiet)?;
    extract_file(header.bi2_bytes(), &out_dir.join("bi2.bin"), quiet)?;
    extract_file(header.apploader_bytes(), &out_dir.join("apploader.img"), quiet)?;
    extract_file(header.fst_bytes(), &out_dir.join("fst.bin"), quiet)?;
    extract_file(header.dol_bytes(), &out_dir.join("main.dol"), quiet)?;
    Ok(())
}

fn extract_file(bytes: &[u8], out_path: &Path, quiet: bool) -> Result<()> {
    if !quiet {
        println!(
            "Extracting {} (size: {})",
            out_path.display(),
            file_size::fit_4(bytes.len() as u64)
        );
    }
    fs::write(out_path, bytes).with_context(|| format!("Writing file {}", out_path.display()))?;
    Ok(())
}

fn extract_node(
    node: &NodeType,
    partition: &mut dyn PartReadStream,
    base_path: &Path,
    quiet: bool,
) -> Result<()> {
    match node {
        NodeType::File(v) => {
            let mut file_path = base_path.to_path_buf();
            file_path.push(v.name.as_str());
            if !quiet {
                println!(
                    "Extracting {} (size: {})",
                    file_path.display(),
                    file_size::fit_4(v.length as u64)
                );
            }
            let file = File::create(&file_path)
                .with_context(|| format!("Creating file {}", file_path.display()))?;
            let mut buf_writer = BufWriter::with_capacity(partition.ideal_buffer_size(), file);
            let mut stream = partition.begin_file_stream(v).with_context(|| {
                format!(
                    "Opening file {} on disc for reading (offset {}, size {})",
                    v.name, v.offset, v.length
                )
            })?;
            io::copy(&mut stream, &mut buf_writer)
                .with_context(|| format!("Extracting file {}", file_path.display()))?;
            buf_writer.flush().with_context(|| format!("Flushing file {}", file_path.display()))?;
        }
        NodeType::Directory(v, c) => {
            if v.name.is_empty() {
                fs::create_dir_all(base_path).with_context(|| {
                    format!("Creating output directory {}", base_path.display())
                })?;
                for x in c {
                    extract_node(x, partition, base_path, quiet)?;
                }
            } else {
                let mut new_base = base_path.to_path_buf();
                new_base.push(v.name.as_str());
                fs::create_dir_all(&new_base)
                    .with_context(|| format!("Creating output directory {}", new_base.display()))?;
                for x in c {
                    extract_node(x, partition, new_base.as_path(), quiet)?;
                }
            }
        }
    }
    Ok(())
}
