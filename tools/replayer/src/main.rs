use std::collections::HashMap;
use std::path::PathBuf;

use shared::clap;
use shared::clap::Parser;
use shared::protobuf::ebpf_extractor::ebpf;
use shared::protobuf::event::event::PeerObserverEvent;

#[derive(Parser)]
#[command(version, about = "Read and display peer-observer archive files")]
struct Args {
    /// Archive files to read.
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// List peers found in the archive.
    #[arg(long)]
    list_peers: bool,

    /// Only include events with timestamp >= this value (milliseconds).
    #[arg(long)]
    from: Option<u64>,

    /// Only include events with timestamp <= this value (milliseconds).
    #[arg(long)]
    to: Option<u64>,
}

struct Peer {
    addr: String,
    messages: u64,
}

fn main() {
    let args = Args::parse();

    let multiple_files = args.files.len() > 1;
    for path in &args.files {
        if multiple_files {
            println!("=== {} ===", path.display());
        }
        match replayer::read_archive(path) {
            Ok(mut archive) => {
                if args.from.is_some() || args.to.is_some() {
                    let from = args.from.unwrap_or(0);
                    let to = args.to.unwrap_or(u64::MAX);
                    archive
                        .events
                        .retain(|event| (from..=to).contains(&event.timestamp));
                }
                if args.list_peers {
                    print_peers(&archive);
                } else {
                    print_events(&archive);
                }
            }
            Err(e) => eprintln!("error reading {}: {}", path.display(), e),
        }
    }
}

fn print_events(archive: &replayer::Archive) {
    println!(
        "header: version={} git={}",
        archive.header.version,
        archive
            .header
            .git_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    for (index, event) in archive.events.iter().enumerate() {
        let num = index + 1;
        let ts = event.timestamp;
        match &event.peer_observer_event {
            Some(PeerObserverEvent::EbpfExtractor(ebpf)) => {
                println!(
                    "[{num}] ts={ts} ebpf: {}",
                    ebpf.ebpf_event.as_ref().unwrap()
                )
            }
            Some(PeerObserverEvent::RpcExtractor(rpc)) => {
                println!("[{num}] ts={ts} rpc: {}", rpc.rpc_event.as_ref().unwrap())
            }
            Some(PeerObserverEvent::P2pExtractor(p2p)) => {
                println!("[{num}] ts={ts} p2p: {}", p2p.p2p_event.as_ref().unwrap())
            }
            Some(PeerObserverEvent::LogExtractor(log)) => {
                println!("[{num}] ts={ts} log: {}", log.log_event.as_ref().unwrap())
            }
            Some(PeerObserverEvent::IpcExtractor(ipc)) => {
                println!("[{num}] ts={ts} ipc: {}", ipc.ipc_event.as_ref().unwrap())
            }
            None => println!("[{num}] ts={ts} <unknown>"),
        }
    }
    println!("total: {} events", archive.events.len());
}

fn collect_peers(archive: &replayer::Archive) -> HashMap<u64, Peer> {
    let mut peers: HashMap<u64, Peer> = HashMap::new();
    for event in &archive.events {
        if let Some(PeerObserverEvent::EbpfExtractor(ebpf)) = &event.peer_observer_event {
            if let Some(ebpf::EbpfEvent::Message(msg)) = &ebpf.ebpf_event {
                let peer = peers.entry(msg.meta.peer_id).or_insert_with(|| Peer {
                    addr: msg.meta.addr.clone(),
                    messages: 0,
                });
                peer.messages += 1;
            }
        }
    }
    peers
}

fn print_peers(archive: &replayer::Archive) {
    let peers = collect_peers(archive);
    if peers.is_empty() {
        eprintln!("no peers found in archive");
        return;
    }
    let mut sorted_peers: Vec<_> = peers.into_iter().collect();
    sorted_peers.sort_by(|a, b| b.1.messages.cmp(&a.1.messages));
    println!("{:<10} {:<25} Messages", "Peer ID", "Address");
    for (peer_id, peer) in &sorted_peers {
        println!("{:<10} {:<25} {}", peer_id, peer.addr, peer.messages);
    }
}
