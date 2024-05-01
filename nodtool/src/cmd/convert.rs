use std::path::PathBuf;

use argp::FromArgs;

use crate::util::shared::convert_and_verify;

#[derive(FromArgs, Debug)]
/// Converts a disc image to ISO.
#[argp(subcommand, name = "convert")]
pub struct ConvertArgs {
    #[argp(positional)]
    /// path to disc image
    file: PathBuf,
    #[argp(positional)]
    /// output ISO file
    out: PathBuf,
    #[argp(switch)]
    /// enable MD5 hashing (slower)
    md5: bool,
}

pub fn convert(args: ConvertArgs) -> nod::Result<()> {
    convert_and_verify(&args.file, Some(&args.out), args.md5)
}
