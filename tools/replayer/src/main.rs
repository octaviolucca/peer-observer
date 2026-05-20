use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use shared::clap;
use shared::clap::Parser;
use shared::protobuf::ebpf_extractor::ebpf;
use shared::protobuf::ebpf_extractor::message::message_event::Msg;
use shared::protobuf::ebpf_extractor::message::MessageEvent;
use shared::protobuf::event::event::PeerObserverEvent;

#[derive(Parser)]
#[command(version, about = "Read and display peer-observer archive files")]
struct Args {
    /// Archive files to read.
    #[arg(required = true)]
    files: Vec<PathBuf>,

    /// Output a sequence diagram (mermaid format).
    #[arg(long, conflicts_with = "list_peers")]
    sequence_diagram: bool,

    /// Write sequence diagram as a self-contained HTML file.
    #[arg(long, requires = "sequence_diagram")]
    html: Option<PathBuf>,

    /// Filter sequence diagram to specific peer IDs.
    #[arg(long, requires = "sequence_diagram")]
    peer: Vec<u64>,

    /// List peers found in the archive.
    #[arg(long, conflicts_with = "sequence_diagram")]
    list_peers: bool,

    /// Write P2P events as CSV to a file.
    #[arg(long, conflicts_with_all = ["sequence_diagram", "list_peers"])]
    csv: Option<PathBuf>,

    /// Filter to specific message types, comma-separated (e.g. ping,inv,tx).
    #[arg(long, value_delimiter = ',')]
    msg_type: Vec<String>,

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

    if args.sequence_diagram && args.files.len() > 1 {
        eprintln!("error: --sequence-diagram only supports a single archive file");
        std::process::exit(1);
    }

    if args.csv.is_some() && args.files.len() > 1 {
        eprintln!("error: --csv only supports a single archive file");
        std::process::exit(1);
    }

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
                if !args.msg_type.is_empty() {
                    archive.events.retain(|event| {
                        if let Some(PeerObserverEvent::EbpfExtractor(ebpf)) =
                            &event.peer_observer_event
                        {
                            if let Some(ebpf::EbpfEvent::Message(msg)) = &ebpf.ebpf_event {
                                return args.msg_type.iter().any(|t| t == &msg.meta.command);
                            }
                        }
                        false
                    });
                }
                if let Some(csv_path) = &args.csv {
                    write_csv(csv_path, &archive);
                } else if args.list_peers {
                    print_peers(&archive);
                } else if args.sequence_diagram {
                    let mermaid = build_sequence_diagram(&archive, &args.peer);
                    if let Some(mermaid) = mermaid {
                        if let Some(html_path) = &args.html {
                            write_html(html_path, &mermaid);
                        } else {
                            print!("{mermaid}");
                        }
                    }
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

fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

fn write_csv(path: &Path, archive: &replayer::Archive) {
    let write = || -> std::io::Result<()> {
        let mut file = File::create(path)?;
        writeln!(file, "timestamp,peer_id,addr,command,direction,size")?;
        for event in &archive.events {
            if let Some(PeerObserverEvent::EbpfExtractor(ebpf)) = &event.peer_observer_event {
                if let Some(ebpf::EbpfEvent::Message(msg)) = &ebpf.ebpf_event {
                    writeln!(
                        file,
                        "{},{},{},{},{},{}",
                        event.timestamp,
                        msg.meta.peer_id,
                        csv_escape(&msg.meta.addr),
                        csv_escape(&msg.meta.command),
                        if msg.meta.inbound { "in" } else { "out" },
                        msg.meta.size,
                    )?;
                }
            }
        }
        Ok(())
    };
    if let Err(e) = write() {
        eprintln!("error writing {}: {}", path.display(), e);
        std::process::exit(1);
    }
    eprintln!("wrote {}", path.display());
}

fn collect_peers(archive: &replayer::Archive, peer_filter: &[u64]) -> HashMap<u64, Peer> {
    let mut peers: HashMap<u64, Peer> = HashMap::new();
    for event in &archive.events {
        if let Some(PeerObserverEvent::EbpfExtractor(ebpf)) = &event.peer_observer_event {
            if let Some(ebpf::EbpfEvent::Message(msg)) = &ebpf.ebpf_event {
                let peer_id = msg.meta.peer_id;
                if !peer_filter.is_empty() && !peer_filter.contains(&peer_id) {
                    continue;
                }
                let peer = peers.entry(peer_id).or_insert_with(|| Peer {
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
    let peers = collect_peers(archive, &[]);
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

fn build_sequence_diagram(archive: &replayer::Archive, peer_filter: &[u64]) -> Option<String> {
    let peers = collect_peers(archive, peer_filter);

    if peers.is_empty() {
        eprintln!("no P2P messages found in archive");
        return None;
    }

    let mut out = String::new();
    out.push_str("sequenceDiagram\n");
    out.push_str("    participant Node as Our Node\n");
    let mut sorted_peers: Vec<_> = peers.iter().collect();
    sorted_peers.sort_by_key(|(id, _)| *id);
    for (peer_id, peer) in &sorted_peers {
        let addr = sanitize_for_mermaid(&peer.addr);
        out.push_str(&format!(
            "    participant P{} as Peer {} ({})\n",
            peer_id, peer_id, addr
        ));
    }
    out.push('\n');

    for event in &archive.events {
        if let Some(PeerObserverEvent::EbpfExtractor(ebpf)) = &event.peer_observer_event {
            if let Some(ebpf::EbpfEvent::Message(msg)) = &ebpf.ebpf_event {
                let peer_id = msg.meta.peer_id;
                if !peer_filter.is_empty() && !peer_filter.contains(&peer_id) {
                    continue;
                }
                let label = message_label(msg);

                if msg.meta.inbound {
                    out.push_str(&format!("    P{}->>Node: {}\n", peer_id, label));
                } else {
                    out.push_str(&format!("    Node->>P{}: {}\n", peer_id, label));
                }
            }
        }
    }

    Some(out)
}

fn write_html(path: &Path, mermaid: &str) {
    let html = format!(
        "<!DOCTYPE html>\n\
         <html><head>\n\
         <script src=\"https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js\"></script>\n\
         <script>mermaid.initialize({{ maxTextSize: 500000 }});</script>\n\
         </head><body>\n\
         <pre class=\"mermaid\">\n\
         {mermaid}\
         </pre>\n\
         </body></html>\n"
    );
    if let Err(e) = std::fs::write(path, &html) {
        eprintln!("error writing {}: {}", path.display(), e);
        std::process::exit(1);
    }
    eprintln!("wrote {}", path.display());
}

/// Escape characters that break mermaid/HTML rendering (e.g. user_agent in version messages)
fn sanitize_for_mermaid(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\n', " ")
        .replace('\r', "")
}

fn message_label(msg: &MessageEvent) -> String {
    let detail = message_detail(msg);
    let label = if detail.is_empty() {
        if msg.meta.size > 0 {
            format!("{} ({}B)", msg.meta.command, msg.meta.size)
        } else {
            msg.meta.command.clone()
        }
    } else {
        format!("{} ({})", msg.meta.command, detail)
    };
    sanitize_for_mermaid(&label)
}

fn message_detail(msg: &MessageEvent) -> String {
    match &msg.msg {
        Some(Msg::Ping(ping)) => format!("nonce: {:#x}", ping.value),
        Some(Msg::Pong(pong)) => format!("nonce: {:#x}", pong.value),
        Some(Msg::Inv(inv)) => format!("{} items", inv.items.len()),
        Some(Msg::Getdata(getdata)) => format!("{} items", getdata.items.len()),
        Some(Msg::Headers(headers)) => format!("{} headers", headers.headers.len()),
        Some(Msg::Addr(addr)) => format!("{} addrs", addr.addresses.len()),
        Some(Msg::Addrv2(addrv2)) => format!("{} addrs", addrv2.addresses.len()),
        Some(Msg::Version(version)) => {
            format!("ua={} height={}", version.user_agent, version.start_height)
        }
        Some(Msg::Feefilter(feefilter)) => format!("fee={}", feefilter.fee),
        Some(Msg::Sendcompact(sendcompact)) => format!("v={}", sendcompact.version),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::protobuf::ebpf_extractor::message::{
        Addr, AddrV2, FeeFilter, GetData, Headers, Inv, Metadata, Ping, Pong, SendCompact, Version,
    };
    use shared::protobuf::ebpf_extractor::Ebpf;
    use shared::protobuf::event::Event;

    // --- helpers ---

    fn make_meta(command: &str, peer_id: u64, inbound: bool, size: u64) -> Metadata {
        Metadata {
            peer_id,
            addr: "127.0.0.1:8333".to_string(),
            conn_type: 1,
            command: command.to_string(),
            inbound,
            size,
        }
    }

    fn make_msg_event(meta: Metadata, msg: Option<Msg>) -> MessageEvent {
        MessageEvent { meta, msg }
    }

    fn make_archive(events: Vec<Event>) -> replayer::Archive {
        replayer::Archive {
            header: replayer::ArchiveHeader {
                version: 1,
                git_hash: [0; 4],
            },
            events,
        }
    }

    fn make_event(peer_id: u64, addr: &str, command: &str, inbound: bool) -> Event {
        Event {
            timestamp: 1000,
            peer_observer_event: Some(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Message(MessageEvent {
                    meta: Metadata {
                        peer_id,
                        addr: addr.to_string(),
                        conn_type: 1,
                        command: command.to_string(),
                        inbound,
                        size: 0,
                    },
                    msg: None,
                })),
            })),
        }
    }

    // --- collect_peers ---

    #[test]
    fn test_collect_peers_empty() {
        let archive = make_archive(vec![]);
        let peers = collect_peers(&archive, &[]);
        assert!(peers.is_empty());
    }

    #[test]
    fn test_collect_peers_counts() {
        let archive = make_archive(vec![
            make_event(5, "1.2.3.4:8333", "ping", true),
            make_event(5, "1.2.3.4:8333", "pong", false),
            make_event(5, "1.2.3.4:8333", "inv", true),
            make_event(10, "5.6.7.8:8333", "ping", true),
        ]);
        let peers = collect_peers(&archive, &[]);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[&5].addr, "1.2.3.4:8333");
        assert_eq!(peers[&5].messages, 3);
        assert_eq!(peers[&10].messages, 1);
    }

    #[test]
    fn test_collect_peers_with_filter() {
        let archive = make_archive(vec![
            make_event(5, "1.2.3.4:8333", "ping", true),
            make_event(10, "5.6.7.8:8333", "ping", true),
        ]);
        let peers = collect_peers(&archive, &[5]);
        assert_eq!(peers.len(), 1);
        assert!(peers.contains_key(&5));
        assert!(!peers.contains_key(&10));
    }

    #[test]
    fn test_collect_peers_filter_no_match() {
        let archive = make_archive(vec![make_event(5, "1.2.3.4:8333", "ping", true)]);
        let peers = collect_peers(&archive, &[999]);
        assert!(peers.is_empty());
    }

    // --- message_detail ---

    #[test]
    fn test_message_detail_ping() {
        let msg = make_msg_event(
            make_meta("ping", 1, true, 8),
            Some(Msg::Ping(Ping { value: 0xdeadbeef })),
        );
        assert_eq!(message_detail(&msg), "nonce: 0xdeadbeef");
    }

    #[test]
    fn test_message_detail_pong() {
        let msg = make_msg_event(
            make_meta("pong", 1, false, 8),
            Some(Msg::Pong(Pong { value: 0xcafe })),
        );
        assert_eq!(message_detail(&msg), "nonce: 0xcafe");
    }

    #[test]
    fn test_message_detail_inv() {
        let msg = make_msg_event(
            make_meta("inv", 1, true, 100),
            Some(Msg::Inv(Inv {
                items: vec![Default::default(); 3],
            })),
        );
        assert_eq!(message_detail(&msg), "3 items");
    }

    #[test]
    fn test_message_detail_getdata() {
        let msg = make_msg_event(
            make_meta("getdata", 1, false, 100),
            Some(Msg::Getdata(GetData {
                items: vec![Default::default(); 5],
            })),
        );
        assert_eq!(message_detail(&msg), "5 items");
    }

    #[test]
    fn test_message_detail_headers() {
        let msg = make_msg_event(
            make_meta("headers", 1, true, 100),
            Some(Msg::Headers(Headers {
                headers: vec![Default::default(); 2],
            })),
        );
        assert_eq!(message_detail(&msg), "2 headers");
    }

    #[test]
    fn test_message_detail_addr() {
        let msg = make_msg_event(
            make_meta("addr", 1, true, 100),
            Some(Msg::Addr(Addr {
                addresses: vec![Default::default(); 10],
            })),
        );
        assert_eq!(message_detail(&msg), "10 addrs");
    }

    #[test]
    fn test_message_detail_addrv2() {
        let msg = make_msg_event(
            make_meta("addrv2", 1, true, 100),
            Some(Msg::Addrv2(AddrV2 {
                addresses: vec![Default::default(); 4],
            })),
        );
        assert_eq!(message_detail(&msg), "4 addrs");
    }

    #[test]
    fn test_message_detail_version() {
        let msg = make_msg_event(
            make_meta("version", 1, true, 100),
            Some(Msg::Version(Version {
                version: 70016,
                services: 1033,
                timestamp: 0,
                receiver: Default::default(),
                sender: Default::default(),
                nonce: 0,
                user_agent: "/Satoshi:25.0.0/".to_string(),
                start_height: 800000,
                relay: true,
            })),
        );
        assert_eq!(message_detail(&msg), "ua=/Satoshi:25.0.0/ height=800000");
    }

    #[test]
    fn test_message_detail_feefilter() {
        let msg = make_msg_event(
            make_meta("feefilter", 1, true, 8),
            Some(Msg::Feefilter(FeeFilter { fee: 1000 })),
        );
        assert_eq!(message_detail(&msg), "fee=1000");
    }

    #[test]
    fn test_message_detail_sendcompact() {
        let msg = make_msg_event(
            make_meta("sendcmpct", 1, false, 9),
            Some(Msg::Sendcompact(SendCompact {
                send_compact: true,
                version: 2,
            })),
        );
        assert_eq!(message_detail(&msg), "v=2");
    }

    #[test]
    fn test_message_detail_unknown() {
        let msg = make_msg_event(make_meta("verack", 1, true, 0), Some(Msg::Verack(true)));
        assert_eq!(message_detail(&msg), "");
    }

    #[test]
    fn test_message_detail_none() {
        let msg = make_msg_event(make_meta("wtxidrelay", 1, true, 0), None);
        assert_eq!(message_detail(&msg), "");
    }

    // --- message_label ---

    #[test]
    fn test_message_label_with_detail() {
        let msg = make_msg_event(
            make_meta("ping", 1, true, 8),
            Some(Msg::Ping(Ping { value: 42 })),
        );
        assert_eq!(message_label(&msg), "ping (nonce: 0x2a)");
    }

    #[test]
    fn test_message_label_no_detail_with_size() {
        let msg = make_msg_event(make_meta("verack", 1, true, 100), Some(Msg::Verack(true)));
        assert_eq!(message_label(&msg), "verack (100B)");
    }

    #[test]
    fn test_message_label_no_detail_no_size() {
        let msg = make_msg_event(make_meta("verack", 1, true, 0), Some(Msg::Verack(true)));
        assert_eq!(message_label(&msg), "verack");
    }

    #[test]
    fn test_message_label_escapes_special_chars() {
        let msg = make_msg_event(
            make_meta("version", 1, true, 100),
            Some(Msg::Version(Version {
                version: 70016,
                services: 1033,
                timestamp: 0,
                receiver: Default::default(),
                sender: Default::default(),
                nonce: 0,
                user_agent: "<script>alert(1)</script>".to_string(),
                start_height: 800000,
                relay: true,
            })),
        );
        let label = message_label(&msg);
        assert!(!label.contains('<'));
        assert!(!label.contains('>'));
        assert!(label.contains("&lt;script&gt;"));
    }

    // --- csv_escape ---

    #[test]
    fn test_csv_escape_plain() {
        assert_eq!(csv_escape("127.0.0.1:8333"), "127.0.0.1:8333");
    }

    #[test]
    fn test_csv_escape_comma() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn test_csv_escape_quotes() {
        assert_eq!(csv_escape("say \"hello\""), "\"say \"\"hello\"\"\"");
    }

    #[test]
    fn test_csv_escape_newline() {
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
    }
}
