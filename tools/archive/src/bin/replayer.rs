use archive::replayer::{self, Args};
use shared::anyhow::{Context, Result};
use shared::clap::Parser;
use shared::simple_logger;

fn main() -> Result<()> {
    let args = Args::parse();

    simple_logger::init_with_level(args.log_level).context("could not initialize logger")?;

    if replayer::run(&args) {
        std::process::exit(1);
    }

    Ok(())
}
