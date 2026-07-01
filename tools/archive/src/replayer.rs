use crate::read::ArchiveReader;
use shared::anyhow::{Context, Result};
use shared::clap;
use shared::clap::Parser;
use shared::log;
use shared::protobuf::event::{event::PeerObserverEvent, Event};
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

pub fn run(args: &Args) -> bool {
    let mut had_error = false;

    for path in &args.files {
        if args.files.len() > 1 {
            log::info!("=== {} ===", path.display());
        }

        match replay_file(path) {
            Ok(events_count) => log::info!("total: {} events", events_count),
            Err(error) => {
                log::error!("{:#}", error);
                had_error = true;
            }
        }
    }

    had_error
}

pub fn replay_file(path: &Path) -> Result<usize> {
    let archive =
        ArchiveReader::open(path).with_context(|| format!("reading archive {}", path.display()))?;

    log::info!("header: {}", archive.header);

    let mut events_count = 0;
    for (idx, event) in archive.enumerate() {
        let n = idx + 1;
        let event =
            event.with_context(|| format!("error at event {n} in archive {}", path.display()))?;

        if let Err(e) = display_event(n, &event) {
            log::warn!(
                "failed to display archive {} event {n}: {:#}",
                path.display(),
                e
            );
        }
        events_count = n;
    }

    Ok(events_count)
}

fn display_event(n: usize, event: &Event) -> Result<()> {
    let ts = event.timestamp;
    match &event.peer_observer_event {
        Some(PeerObserverEvent::EbpfExtractor(e)) => {
            let ebpf_event = e.ebpf_event.as_ref().context("missing ebpf event")?;
            log::info!("[{n}] ts={ts} ebpf: {ebpf_event}");
        }
        Some(PeerObserverEvent::RpcExtractor(r)) => {
            let rpc_event = r.rpc_event.as_ref().context("missing rpc event")?;
            log::info!("[{n}] ts={ts} rpc: {rpc_event}");
        }
        Some(PeerObserverEvent::P2pExtractor(p)) => {
            let p2p_event = p.p2p_event.as_ref().context("missing p2p event")?;
            log::info!("[{n}] ts={ts} p2p: {p2p_event}");
        }
        Some(PeerObserverEvent::LogExtractor(l)) => {
            let log_event = l.log_event.as_ref().context("missing log event")?;
            log::info!("[{n}] ts={ts} log: {log_event}");
        }
        Some(PeerObserverEvent::IpcExtractor(i)) => {
            let ipc_event = i.ipc_event.as_ref().context("missing ipc event")?;
            log::info!("[{n}] ts={ts} ipc: {ipc_event}");
        }
        None => log::info!("[{n}] ts={ts} <unknown>"),
    }

    Ok(())
}
