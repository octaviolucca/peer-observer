use archive::replayer::{self, Args};
use shared::clap::Parser;
use shared::simple_logger;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args = Args::parse();

    if let Err(e) = simple_logger::init_with_level(args.log_level) {
        eprintln!("replayer tool error: {}", e);
    }

    if replayer::run(&args) {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
