use argp::FromArgs;

pub mod cmd;
pub(crate) mod util;

#[derive(FromArgs, Debug)]
#[argp(subcommand)]
pub enum SubCommand {
    Dat(cmd::dat::Args),
    Info(cmd::info::Args),
    Extract(cmd::extract::Args),
    Convert(cmd::convert::Args),
    Verify(cmd::verify::Args),
}

pub fn run(command: SubCommand) -> nod::Result<()> {
    match command {
        SubCommand::Dat(c_args) => cmd::dat::run(c_args),
        SubCommand::Info(c_args) => cmd::info::run(c_args),
        SubCommand::Convert(c_args) => cmd::convert::run(c_args),
        SubCommand::Extract(c_args) => cmd::extract::run(c_args),
        SubCommand::Verify(c_args) => cmd::verify::run(c_args),
    }
}
