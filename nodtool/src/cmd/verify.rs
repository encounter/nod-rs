use std::path::PathBuf;

use argp::FromArgs;

use crate::util::shared::convert_and_verify;

#[derive(FromArgs, Debug)]
/// Verifies disc images.
#[argp(subcommand, name = "verify")]
pub struct VerifyArgs {
    #[argp(positional)]
    /// path to disc image(s)
    file: Vec<PathBuf>,
    #[argp(switch)]
    /// enable MD5 hashing (slower)
    md5: bool,
}

pub fn verify(args: VerifyArgs) -> nod::Result<()> {
    for file in &args.file {
        convert_and_verify(file, None, args.md5)?;
        println!();
    }
    Ok(())
}
