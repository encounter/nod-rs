use std::path::PathBuf;

use argp::FromArgs;

use crate::util::{redump, shared::convert_and_verify};

#[derive(FromArgs, Debug)]
/// Converts a disc image to ISO.
#[argp(subcommand, name = "convert")]
pub struct Args {
    #[argp(positional)]
    /// path to disc image
    file: PathBuf,
    #[argp(positional)]
    /// output ISO file
    out: PathBuf,
    #[argp(switch)]
    /// enable MD5 hashing (slower)
    md5: bool,
    #[argp(option, short = 'd')]
    /// path to DAT file(s) for verification (optional)
    dat: Vec<PathBuf>,
}

pub fn run(args: Args) -> nod::Result<()> {
    if !args.dat.is_empty() {
        println!("Loading dat files...");
        redump::load_dats(args.dat.iter().map(PathBuf::as_ref))?;
    }
    convert_and_verify(&args.file, Some(&args.out), args.md5)
}
