use argp::FromArgs;

pub mod cmd;
pub(crate) mod util;

#[derive(FromArgs, Debug)]
#[argp(subcommand)]
pub enum SubCommand {
    Info(cmd::info::InfoArgs),
    Extract(cmd::extract::ExtractArgs),
    Convert(cmd::convert::ConvertArgs),
    Verify(cmd::verify::VerifyArgs),
}

pub fn run(command: SubCommand) -> nod::Result<()> {
    match command {
        SubCommand::Info(c_args) => cmd::info::info(c_args),
        SubCommand::Convert(c_args) => cmd::convert::convert(c_args),
        SubCommand::Extract(c_args) => cmd::extract::extract(c_args),
        SubCommand::Verify(c_args) => cmd::verify::verify(c_args),
    }
}
