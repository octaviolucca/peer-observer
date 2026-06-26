use crate::read::ArchiveReader;
use shared::clap;
use shared::clap::Parser;
use shared::log;
use shared::protobuf::event::{event::PeerObserverEvent, Event};
use std::io;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(version, about = "Read and display peer-observer archive files")]
pub struct Args {
    /// Archive files to read.
    #[arg(value_name = "FILE", required = true)]
    pub files: Vec<PathBuf>,

    /// The log level the tool should run on.
    #[arg(short, long, default_value_t = log::Level::Info)]
    pub log_level: log::Level,
}

#[derive(Debug)]
pub enum ReplayFileError {
    OpenArchive(io::Error),
    UnexpectedEof {
        event_number: usize,
        source: io::Error,
    },
    ReadEvent {
        event_number: usize,
        source: io::Error,
    },
}

impl ReplayFileError {
    fn events_count(&self) -> Option<usize> {
        match self {
            ReplayFileError::OpenArchive(_) => None,
            ReplayFileError::UnexpectedEof { event_number, .. }
            | ReplayFileError::ReadEvent { event_number, .. } => Some(event_number - 1),
        }
    }
}

pub fn run(args: &Args) -> bool {
    let mut had_error = false;

    for path in &args.files {
        if args.files.len() > 1 {
            log::info!("=== {} ===", path.display());
        }

        match replay_file(path) {
            Ok(events_count) => log::info!("total: {} events", events_count),
            Err(error) => {
                log_replay_error(path, &error);
                if let Some(events_count) = error.events_count() {
                    log::info!("total: {} events", events_count);
                }
                had_error = true;
            }
        }
    }

    had_error
}

pub fn replay_file(path: &Path) -> Result<usize, ReplayFileError> {
    let archive = match ArchiveReader::open(path) {
        Ok(archive) => archive,
        Err(e) => return Err(ReplayFileError::OpenArchive(e)),
    };

    log::info!("header: {}", archive.header);

    let mut events_count = 0;
    for (idx, event) in archive.enumerate() {
        let n = idx + 1;
        let event = match event {
            Ok(event) => event,
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                return Err(ReplayFileError::UnexpectedEof {
                    event_number: n,
                    source: e,
                });
            }
            Err(e) => {
                return Err(ReplayFileError::ReadEvent {
                    event_number: n,
                    source: e,
                });
            }
        };

        if let Err(e) = display_event(n, &event) {
            log::warn!(
                "failed to display archive {} event {n}: {e}",
                path.display()
            );
        }
        events_count = n;
    }

    Ok(events_count)
}

fn log_replay_error(path: &Path, error: &ReplayFileError) {
    match error {
        ReplayFileError::OpenArchive(e) => {
            log::error!("failed to read archive {}: {e}", path.display());
        }
        ReplayFileError::UnexpectedEof {
            event_number,
            source,
        } => {
            log::error!(
                "archive {} ended unexpectedly while reading event {event_number}: {source}",
                path.display()
            );
        }
        ReplayFileError::ReadEvent {
            event_number,
            source,
        } => {
            log::error!(
                "failed to read archive {} at event {event_number}: {source}",
                path.display()
            );
        }
    }
}

fn display_event(n: usize, event: &Event) -> Result<(), &'static str> {
    let ts = event.timestamp;
    match &event.peer_observer_event {
        Some(PeerObserverEvent::EbpfExtractor(e)) => {
            let ebpf_event = e.ebpf_event.as_ref().ok_or("missing ebpf event")?;
            log::info!("[{n}] ts={ts} ebpf: {ebpf_event}");
        }
        Some(PeerObserverEvent::RpcExtractor(r)) => {
            let rpc_event = r.rpc_event.as_ref().ok_or("missing rpc event")?;
            log::info!("[{n}] ts={ts} rpc: {rpc_event}");
        }
        Some(PeerObserverEvent::P2pExtractor(p)) => {
            let p2p_event = p.p2p_event.as_ref().ok_or("missing p2p event")?;
            log::info!("[{n}] ts={ts} p2p: {p2p_event}");
        }
        Some(PeerObserverEvent::LogExtractor(l)) => {
            let log_event = l.log_event.as_ref().ok_or("missing log event")?;
            log::info!("[{n}] ts={ts} log: {log_event}");
        }
        Some(PeerObserverEvent::IpcExtractor(i)) => {
            let ipc_event = i.ipc_event.as_ref().ok_or("missing ipc event")?;
            log::info!("[{n}] ts={ts} ipc: {ipc_event}");
        }
        None => log::info!("[{n}] ts={ts} <unknown>"),
    }

    Ok(())
}
