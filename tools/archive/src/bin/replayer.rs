use archive::read::ArchiveReader;
use shared::clap;
use shared::clap::Parser;
use shared::protobuf::event::{event::PeerObserverEvent, Event};
use shared::{log, simple_logger};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(version, about = "Read and display peer-observer archive files")]
struct Args {
    /// Archive files to read.
    #[arg(value_name = "FILE", required = true)]
    files: Vec<PathBuf>,

    /// The log level the tool should run on.
    #[arg(short, long, default_value_t = log::Level::Info)]
    log_level: log::Level,
}

fn main() -> ExitCode {
    let args = Args::parse();

    if let Err(e) = simple_logger::init_with_level(args.log_level) {
        eprintln!("replayer tool error: {}", e);
    }

    let mut had_error = false;

    for path in &args.files {
        if args.files.len() > 1 {
            println!("=== {} ===", path.display());
        }

        let archive = match ArchiveReader::open(path) {
            Ok(archive) => archive,
            Err(e) => {
                log::error!("failed to read archive {}: {e}", path.display());
                had_error = true;
                continue;
            }
        };

        println!("header: {}", archive.header);

        let mut events_count = 0;
        for (idx, event) in archive.enumerate() {
            let n = idx + 1;
            let event = match event {
                Ok(event) => event,
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                    log::warn!(
                        "archive {} ended unexpectedly while reading event {n}: {e}",
                        path.display()
                    );
                    break;
                }
                Err(e) => {
                    log::error!(
                        "failed to read archive {} at event {n}: {e}",
                        path.display()
                    );
                    had_error = true;
                    break;
                }
            };

            if let Err(e) = print_event(n, &event) {
                log::warn!(
                    "failed to display archive {} event {n}: {e}",
                    path.display()
                );
            }
            events_count = n;
        }

        println!("total: {} events", events_count);
    }

    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn print_event(n: usize, event: &Event) -> Result<(), &'static str> {
    let ts = event.timestamp;
    match &event.peer_observer_event {
        Some(PeerObserverEvent::EbpfExtractor(e)) => {
            let ebpf_event = e.ebpf_event.as_ref().ok_or("missing ebpf event")?;
            println!("[{n}] ts={ts} ebpf: {ebpf_event}");
        }
        Some(PeerObserverEvent::RpcExtractor(r)) => {
            let rpc_event = r.rpc_event.as_ref().ok_or("missing rpc event")?;
            println!("[{n}] ts={ts} rpc: {rpc_event}");
        }
        Some(PeerObserverEvent::P2pExtractor(p)) => {
            let p2p_event = p.p2p_event.as_ref().ok_or("missing p2p event")?;
            println!("[{n}] ts={ts} p2p: {p2p_event}");
        }
        Some(PeerObserverEvent::LogExtractor(l)) => {
            let log_event = l.log_event.as_ref().ok_or("missing log event")?;
            println!("[{n}] ts={ts} log: {log_event}");
        }
        Some(PeerObserverEvent::IpcExtractor(i)) => {
            let ipc_event = i.ipc_event.as_ref().ok_or("missing ipc event")?;
            println!("[{n}] ts={ts} ipc: {ipc_event}");
        }
        None => println!("[{n}] ts={ts} <unknown>"),
    }

    Ok(())
}
