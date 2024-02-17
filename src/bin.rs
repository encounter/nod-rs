mod argp_version;

use std::{
    borrow::Cow,
    env,
    error::Error,
    ffi::OsStr,
    fs,
    fs::File,
    io,
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        mpsc::{sync_channel, SyncSender},
        Arc,
    },
    thread,
    thread::JoinHandle,
};

use argp::{FromArgValue, FromArgs};
use digest::{Digest, Output};
use enable_ansi_support::enable_ansi_support;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use itertools::Itertools;
use nod::{
    Disc, DiscHeader, Fst, Node, OpenOptions, PartitionBase, PartitionKind, PartitionMeta, Result,
    ResultContext,
};
use supports_color::Stream;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use zerocopy::FromZeroes;

#[derive(FromArgs, Debug)]
/// Tool for reading GameCube and Wii disc images.
struct TopLevel {
    #[argp(subcommand)]
    command: SubCommand,
    #[argp(option, short = 'C')]
    /// Change working directory.
    chdir: Option<PathBuf>,
    #[argp(option, short = 'L')]
    /// Minimum logging level. (Default: info)
    /// Possible values: error, warn, info, debug, trace
    log_level: Option<LogLevel>,
    #[allow(unused)]
    #[argp(switch, short = 'V')]
    /// Print version information and exit.
    version: bool,
    #[argp(switch)]
    /// Disable color output. (env: NO_COLOR)
    no_color: bool,
}

#[derive(FromArgs, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Info(InfoArgs),
    Extract(ExtractArgs),
    Convert(ConvertArgs),
    Verify(VerifyArgs),
}

#[derive(FromArgs, Debug)]
/// Displays information about a disc image.
#[argp(subcommand, name = "info")]
struct InfoArgs {
    #[argp(positional)]
    /// path to disc image
    file: PathBuf,
}

#[derive(FromArgs, Debug)]
/// Extract a disc image.
#[argp(subcommand, name = "extract")]
struct ExtractArgs {
    #[argp(positional)]
    /// path to disc image
    file: PathBuf,
    #[argp(positional)]
    /// output directory (optional)
    out: Option<PathBuf>,
    #[argp(switch, short = 'q')]
    /// quiet output
    quiet: bool,
    #[argp(switch, short = 'h')]
    /// validate disc hashes (Wii only)
    validate: bool,
}

#[derive(FromArgs, Debug)]
/// Converts a disc image to ISO.
#[argp(subcommand, name = "convert")]
struct ConvertArgs {
    #[argp(positional)]
    /// path to disc image
    file: PathBuf,
    #[argp(positional)]
    /// output ISO file
    out: PathBuf,
}

#[derive(FromArgs, Debug)]
/// Verifies a disc image.
#[argp(subcommand, name = "verify")]
struct VerifyArgs {
    #[argp(positional)]
    /// path to disc image
    file: PathBuf,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl FromStr for LogLevel {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "error" => Self::Error,
            "warn" => Self::Warn,
            "info" => Self::Info,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => return Err(()),
        })
    }
}

impl ToString for LogLevel {
    fn to_string(&self) -> String {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
        .to_string()
    }
}

impl FromArgValue for LogLevel {
    fn from_arg_value(value: &OsStr) -> std::result::Result<Self, String> {
        String::from_arg_value(value)
            .and_then(|s| Self::from_str(&s).map_err(|_| "Invalid log level".to_string()))
    }
}

// Duplicated from supports-color so we can check early.
fn env_no_color() -> bool {
    match env::var("NO_COLOR").as_deref() {
        Ok("") | Ok("0") | Err(_) => false,
        Ok(_) => true,
    }
}

fn main() {
    let args: TopLevel = argp_version::from_env();
    let use_colors = if args.no_color || env_no_color() {
        false
    } else {
        // Try to enable ANSI support on Windows.
        let _ = enable_ansi_support();
        // Disable isatty check for supports-color. (e.g. when used with ninja)
        env::set_var("IGNORE_IS_TERMINAL", "1");
        supports_color::on(Stream::Stdout).is_some_and(|c| c.has_basic)
    };

    let format =
        tracing_subscriber::fmt::format().with_ansi(use_colors).with_target(false).without_time();
    let builder = tracing_subscriber::fmt().event_format(format);
    if let Some(level) = args.log_level {
        builder
            .with_max_level(match level {
                LogLevel::Error => LevelFilter::ERROR,
                LogLevel::Warn => LevelFilter::WARN,
                LogLevel::Info => LevelFilter::INFO,
                LogLevel::Debug => LevelFilter::DEBUG,
                LogLevel::Trace => LevelFilter::TRACE,
            })
            .init();
    } else {
        builder
            .with_env_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            )
            .init();
    }

    let mut result = Ok(());
    if let Some(dir) = &args.chdir {
        result = env::set_current_dir(dir).map_err(|e| {
            nod::Error::Io(format!("Failed to change working directory to '{}'", dir.display()), e)
        });
    }
    result = result.and_then(|_| match args.command {
        SubCommand::Info(c_args) => info(c_args),
        SubCommand::Convert(c_args) => convert(c_args),
        SubCommand::Extract(c_args) => extract(c_args),
        SubCommand::Verify(c_args) => verify(c_args),
    });
    if let Err(e) = result {
        eprintln!("Failed: {}", e);
        if let Some(source) = e.source() {
            eprintln!("Caused by: {}", source);
        }
        std::process::exit(1);
    }
}

fn print_header(header: &DiscHeader) {
    println!("Name: {}", header.game_title_str());
    println!("Game ID: {}", header.game_id_str());
    println!("Disc {}, Revision {}", header.disc_num + 1, header.disc_version);
    if header.no_partition_hashes != 0 {
        println!("[!] Disc has no hashes");
    }
    if header.no_partition_encryption != 0 {
        println!("[!] Disc is not encrypted");
    }
}

fn info(args: InfoArgs) -> Result<()> {
    let disc = Disc::new_with_options(args.file, &OpenOptions {
        rebuild_hashes: false,
        validate_hashes: false,
        rebuild_encryption: false,
    })?;
    let header = disc.header();
    print_header(header);

    if header.is_wii() {
        for (idx, info) in disc.partitions().iter().enumerate() {
            println!();
            println!("Partition {}:{}", info.group_index, info.part_index);
            println!("\tType: {}", info.kind);
            println!("\tPartition offset: {:#X}", info.part_offset);
            println!(
                "\tData offset / size: {:#X} / {:#X} ({})",
                info.part_offset + info.data_offset,
                info.data_size,
                file_size::fit_4(info.data_size)
            );
            if let Some(header) = &info.header {
                println!(
                    "\tTMD  offset / size: {:#X} / {:#X}",
                    info.part_offset + header.tmd_off(),
                    header.tmd_size()
                );
                println!(
                    "\tCert offset / size: {:#X} / {:#X}",
                    info.part_offset + header.cert_chain_off(),
                    header.cert_chain_size()
                );
                println!(
                    "\tH3   offset / size: {:#X} / {:#X}",
                    info.part_offset + header.h3_table_off(),
                    header.h3_table_size()
                );
            }

            let mut partition = disc.open_partition(idx)?;
            let meta = partition.meta()?;
            let header = meta.header();
            let tmd = meta.tmd_header();
            let title_id_str = if let Some(tmd) = tmd {
                format!(
                    "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    tmd.title_id[0],
                    tmd.title_id[1],
                    tmd.title_id[2],
                    tmd.title_id[3],
                    tmd.title_id[4],
                    tmd.title_id[5],
                    tmd.title_id[6],
                    tmd.title_id[7]
                )
            } else {
                "N/A".to_string()
            };
            println!("\tName: {}", header.game_title_str());
            println!("\tGame ID: {} ({})", header.game_id_str(), title_id_str);
            println!("\tDisc {}, Revision {}", header.disc_num + 1, header.disc_version);
        }
    } else if header.is_gamecube() {
        // TODO
    } else {
        println!(
            "Invalid GC/Wii magic: {:#010X}/{:#010X}",
            header.gcn_magic.get(),
            header.wii_magic.get()
        );
    }
    Ok(())
}

fn convert(args: ConvertArgs) -> Result<()> { convert_and_verify(&args.file, Some(&args.out)) }

fn verify(args: VerifyArgs) -> Result<()> { convert_and_verify(&args.file, None) }

fn convert_and_verify(in_file: &Path, out_file: Option<&Path>) -> Result<()> {
    println!("Loading {}", in_file.display());
    let disc = Disc::new_with_options(in_file, &OpenOptions {
        rebuild_hashes: true,
        validate_hashes: false,
        rebuild_encryption: true,
    })?;
    let header = disc.header();
    print_header(header);

    let meta = disc.meta()?;
    let mut stream = disc.open()?.take(disc.disc_size());

    let mut file = if let Some(out_file) = out_file {
        Some(
            File::create(out_file)
                .with_context(|| format!("Creating file {}", out_file.display()))?,
        )
    } else {
        None
    };

    println!("\nHashing...");
    let pb = ProgressBar::new(stream.limit());
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
        .unwrap()
        .with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| {
            write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()
        })
        .progress_chars("#>-"));

    const BUFFER_SIZE: usize = 1015808; // LCM(0x8000, 0x7C00)
    let digest_threads = [
        digest_thread::<crc32fast::Hasher>(),
        digest_thread::<md5::Md5>(),
        digest_thread::<sha1::Sha1>(),
        digest_thread::<xxhash_rust::xxh64::Xxh64>(),
    ];

    let (w_tx, w_rx) = sync_channel::<Arc<[u8]>>(1);
    let w_thread = thread::spawn(move || {
        let mut total_written = 0u64;
        while let Ok(data) = w_rx.recv() {
            if let Some(file) = &mut file {
                file.write_all(data.as_ref())
                    .with_context(|| {
                        format!("Writing {} bytes at offset {}", data.len(), total_written)
                    })
                    .unwrap();
            }
            total_written += data.len() as u64;
            pb.set_position(total_written);
        }
        if let Some(mut file) = file {
            file.flush().context("Flushing output file").unwrap();
        }
        pb.finish();
    });

    let mut total_read = 0u64;
    let mut buf = <u8>::new_box_slice_zeroed(BUFFER_SIZE);
    loop {
        let read = stream.read(buf.as_mut()).with_context(|| {
            format!("Reading {} bytes at disc offset {}", BUFFER_SIZE, total_read)
        })?;
        if read == 0 {
            break;
        }

        let arc = Arc::<[u8]>::from(&buf[..read]);
        for (tx, _) in &digest_threads {
            tx.send(arc.clone()).map_err(|_| "Sending data to hash thread")?;
        }
        w_tx.send(arc).map_err(|_| "Sending data to write thread")?;
        total_read += read as u64;
    }
    drop(w_tx); // Close channel
    w_thread.join().unwrap();

    println!();
    if let Some(path) = out_file {
        println!("Wrote {} to {}", file_size::fit_4(total_read), path.display());
    }

    println!();
    for (tx, handle) in digest_threads.into_iter() {
        drop(tx); // Close channel
        match handle.join().unwrap() {
            DigestResult::Crc32(crc) => {
                print!("CRC32: {:08x}", crc);
                if let Some(expected_crc) = meta.crc32 {
                    if expected_crc != crc {
                        print!(" ❌ (expected: {:08x})", expected_crc);
                    } else {
                        print!(" ✅");
                    }
                }
                println!();
            }
            DigestResult::Md5(md5) => {
                print!("MD5:   {:032x}", md5);
                if let Some(expected_md5) = meta.md5 {
                    let expected_md5 = <Output<md5::Md5>>::from(expected_md5);
                    if expected_md5 != md5 {
                        print!(" ❌ (expected: {:032x})", expected_md5);
                    } else {
                        print!(" ✅");
                    }
                }
                println!();
            }
            DigestResult::Sha1(sha1) => {
                print!("SHA-1: {:040x}", sha1);
                if let Some(expected_sha1) = meta.sha1 {
                    let expected_sha1 = <Output<sha1::Sha1>>::from(expected_sha1);
                    if expected_sha1 != sha1 {
                        print!(" ❌ (expected: {:040x})", expected_sha1);
                    } else {
                        print!(" ✅");
                    }
                }
                println!();
            }
            DigestResult::Xxh64(xxh64) => {
                print!("XXH64: {:016x}", xxh64);
                if let Some(expected_xxh64) = meta.xxhash64 {
                    if expected_xxh64 != xxh64 {
                        print!(" ❌ (expected: {:016x})", expected_xxh64);
                    } else {
                        print!(" ✅");
                    }
                }
                println!();
            }
        }
    }
    Ok(())
}

pub fn has_extension(filename: &Path, extension: &str) -> bool {
    match filename.extension() {
        Some(ext) => ext.eq_ignore_ascii_case(extension),
        None => false,
    }
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
    let disc = Disc::new_with_options(&args.file, &OpenOptions {
        rebuild_hashes: args.validate,
        validate_hashes: args.validate,
        rebuild_encryption: false,
    })?;
    let is_wii = disc.header().is_wii();
    let mut partition = disc.open_partition_kind(PartitionKind::Data)?;
    let meta = partition.meta()?;
    extract_sys_files(meta.as_ref(), &output_dir.join("sys"), args.quiet)?;

    // Extract FST
    let files_dir = output_dir.join("files");
    let fst = Fst::new(&meta.raw_fst)?;
    let mut path_segments = Vec::<(Cow<str>, usize)>::new();
    for (idx, node, name) in fst.iter() {
        // Remove ended path segments
        let mut new_size = 0;
        for (_, end) in path_segments.iter() {
            if *end == idx {
                break;
            }
            new_size += 1;
        }
        path_segments.truncate(new_size);

        // Add the new path segment
        let end = if node.is_dir() { node.length(false) as usize } else { idx + 1 };
        path_segments.push((name?, end));

        let path = path_segments.iter().map(|(name, _)| name.as_ref()).join("/");
        if node.is_dir() {
            fs::create_dir_all(files_dir.join(&path))
                .with_context(|| format!("Creating directory {}", path))?;
        } else {
            extract_node(node, partition.as_mut(), &files_dir, &path, is_wii, args.quiet)?;
        }
    }
    Ok(())
}

fn extract_sys_files(data: &PartitionMeta, out_dir: &Path, quiet: bool) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("Creating output directory {}", out_dir.display()))?;
    extract_file(&data.raw_boot, &out_dir.join("boot.bin"), quiet)?;
    extract_file(&data.raw_bi2, &out_dir.join("bi2.bin"), quiet)?;
    extract_file(&data.raw_apploader, &out_dir.join("apploader.img"), quiet)?;
    extract_file(&data.raw_fst, &out_dir.join("fst.bin"), quiet)?;
    extract_file(&data.raw_dol, &out_dir.join("main.dol"), quiet)?;
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
    node: &Node,
    partition: &mut dyn PartitionBase,
    base_path: &Path,
    name: &str,
    is_wii: bool,
    quiet: bool,
) -> Result<()> {
    let file_path = base_path.join(name);
    if !quiet {
        println!(
            "Extracting {} (size: {})",
            file_path.display(),
            file_size::fit_4(node.length(is_wii))
        );
    }
    let file = File::create(&file_path)
        .with_context(|| format!("Creating file {}", file_path.display()))?;
    let mut w = BufWriter::with_capacity(partition.ideal_buffer_size(), file);
    let mut r = partition.open_file(node).with_context(|| {
        format!(
            "Opening file {} on disc for reading (offset {}, size {})",
            name,
            node.offset(is_wii),
            node.length(is_wii)
        )
    })?;
    io::copy(&mut r, &mut w).with_context(|| format!("Extracting file {}", file_path.display()))?;
    w.flush().with_context(|| format!("Flushing file {}", file_path.display()))?;
    Ok(())
}

fn digest_thread<H>() -> (SyncSender<Arc<[u8]>>, JoinHandle<DigestResult>)
where H: Hasher + Send + 'static {
    let (tx, rx) = sync_channel::<Arc<[u8]>>(1);
    let handle = thread::spawn(move || {
        let mut hasher = H::new();
        while let Ok(data) = rx.recv() {
            hasher.update(data.as_ref());
        }
        hasher.finalize()
    });
    (tx, handle)
}

enum DigestResult {
    Crc32(u32),
    Md5(Output<md5::Md5>),
    Sha1(Output<sha1::Sha1>),
    Xxh64(u64),
}

trait Hasher {
    fn new() -> Self;
    fn finalize(self) -> DigestResult;
    fn update(&mut self, data: &[u8]);
}

impl Hasher for md5::Md5 {
    fn new() -> Self { Digest::new() }

    fn finalize(self) -> DigestResult { DigestResult::Md5(Digest::finalize(self)) }

    fn update(&mut self, data: &[u8]) { Digest::update(self, data) }
}

impl Hasher for sha1::Sha1 {
    fn new() -> Self { Digest::new() }

    fn finalize(self) -> DigestResult { DigestResult::Sha1(Digest::finalize(self)) }

    fn update(&mut self, data: &[u8]) { Digest::update(self, data) }
}

impl Hasher for crc32fast::Hasher {
    fn new() -> Self { crc32fast::Hasher::new() }

    fn finalize(self) -> DigestResult { DigestResult::Crc32(crc32fast::Hasher::finalize(self)) }

    fn update(&mut self, data: &[u8]) { crc32fast::Hasher::update(self, data) }
}

impl Hasher for xxhash_rust::xxh64::Xxh64 {
    fn new() -> Self { xxhash_rust::xxh64::Xxh64::new(0) }

    fn finalize(self) -> DigestResult {
        DigestResult::Xxh64(xxhash_rust::xxh64::Xxh64::digest(&self))
    }

    fn update(&mut self, data: &[u8]) { xxhash_rust::xxh64::Xxh64::update(self, data) }
}
