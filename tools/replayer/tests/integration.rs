use std::io::Write;
use std::process::Command;

use shared::prost::Message as _;
use shared::protobuf::ebpf_extractor::ebpf;
use shared::protobuf::ebpf_extractor::message::{
    message_event::Msg, MessageEvent, Metadata, Ping, Pong,
};
use shared::protobuf::ebpf_extractor::Ebpf;
use shared::protobuf::event::event::PeerObserverEvent;
use shared::protobuf::event::Event;
use shared::zstd;

const HEADER_SIZE: usize = 16;

fn build_archive_bytes(version: u8, git_hash: [u8; 4], events: &[Event]) -> Vec<u8> {
    let mut buf = vec![0u8; HEADER_SIZE];
    buf[0..2].copy_from_slice(b"PA");
    buf[2] = version;
    buf[3..7].copy_from_slice(&git_hash);
    for event in events {
        let encoded = event.encode_length_delimited_to_vec();
        buf.extend_from_slice(&encoded);
    }
    buf
}

fn make_meta(command: &str, peer_id: u64, inbound: bool, size: u64) -> Metadata {
    Metadata {
        peer_id,
        addr: format!("127.0.0.{}:8333", peer_id),
        conn_type: 1,
        command: command.to_string(),
        inbound,
        size,
    }
}

fn make_msg_event(
    peer_id: u64,
    command: &str,
    inbound: bool,
    size: u64,
    msg: Option<Msg>,
) -> Event {
    Event {
        timestamp: 1000 + peer_id * 100,
        peer_observer_event: Some(PeerObserverEvent::EbpfExtractor(Ebpf {
            ebpf_event: Some(ebpf::EbpfEvent::Message(MessageEvent {
                meta: make_meta(command, peer_id, inbound, size),
                msg,
            })),
        })),
    }
}

fn make_msg_event_ts(
    ts: u64,
    peer_id: u64,
    command: &str,
    inbound: bool,
    size: u64,
    msg: Option<Msg>,
) -> Event {
    Event {
        timestamp: ts,
        peer_observer_event: Some(PeerObserverEvent::EbpfExtractor(Ebpf {
            ebpf_event: Some(ebpf::EbpfEvent::Message(MessageEvent {
                meta: make_meta(command, peer_id, inbound, size),
                msg,
            })),
        })),
    }
}

fn write_archive(name: &str, events: &[Event]) -> std::path::PathBuf {
    let buf = build_archive_bytes(1, [0xde, 0xad, 0xbe, 0xef], events);
    let path = std::env::temp_dir().join(format!("replayer-integ-{}", name));
    std::fs::write(&path, &buf).unwrap();
    path
}

fn write_archive_zst(name: &str, events: &[Event]) -> std::path::PathBuf {
    let buf = build_archive_bytes(1, [0xde, 0xad, 0xbe, 0xef], events);
    let mut encoder = zstd::Encoder::new(Vec::new(), 3).unwrap();
    encoder.write_all(&buf).unwrap();
    let compressed = encoder.finish().unwrap();
    let path = std::env::temp_dir().join(format!("replayer-integ-{}.zst", name));
    std::fs::write(&path, &compressed).unwrap();
    path
}

fn replayer() -> Command {
    Command::new(env!("CARGO_BIN_EXE_replayer"))
}

// --- print_events ---

#[test]
fn test_print_events_header() {
    let path = write_archive("events-header.bin", &[]);
    let output = replayer().arg(path).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("header: version=1 git=deadbeef"));
    assert!(stdout.contains("total: 0 events"));
}

#[test]
fn test_print_events_with_messages() {
    let events = vec![
        make_msg_event(1, "ping", true, 8, Some(Msg::Ping(Ping { value: 42 }))),
        make_msg_event(2, "pong", false, 8, Some(Msg::Pong(Pong { value: 42 }))),
    ];
    let path = write_archive("events-msgs.bin", &events);
    let output = replayer().arg(path).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("[1] ts=1100 ebpf:"));
    assert!(stdout.contains("[2] ts=1200 ebpf:"));
    assert!(stdout.contains("total: 2 events"));
}

#[test]
fn test_print_events_multiple_files() {
    let events = vec![make_msg_event(
        1,
        "ping",
        true,
        8,
        Some(Msg::Ping(Ping { value: 1 })),
    )];
    let p1 = write_archive("multi-1.bin", &events);
    let p2 = write_archive("multi-2.bin", &events);
    let output = replayer().arg(&p1).arg(&p2).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("=== "));
}

// --- sequence diagram (mermaid) ---

#[test]
fn test_sequence_diagram_basic() {
    let events = vec![
        make_msg_event_ts(1000, 5, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event_ts(
            1050,
            5,
            "pong",
            false,
            8,
            Some(Msg::Pong(Pong { value: 1 })),
        ),
    ];
    let path = write_archive("seq-basic.bin", &events);
    let output = replayer()
        .arg("--sequence-diagram")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("sequenceDiagram"));
    assert!(stdout.contains("participant Node as Our Node"));
    assert!(stdout.contains("participant P5 as Peer 5"));
    assert!(stdout.contains("P5->>Node:"));
    assert!(stdout.contains("Node->>P5:"));
}

#[test]
fn test_sequence_diagram_peer_filter() {
    let events = vec![
        make_msg_event(5, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event(10, "ping", true, 8, Some(Msg::Ping(Ping { value: 2 }))),
    ];
    let path = write_archive("seq-filter.bin", &events);
    let output = replayer()
        .arg("--sequence-diagram")
        .arg("--peer")
        .arg("5")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("P5"));
    assert!(!stdout.contains("P10"));
}

#[test]
fn test_sequence_diagram_multiple_peers() {
    let events = vec![
        make_msg_event(5, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event(10, "pong", false, 8, Some(Msg::Pong(Pong { value: 2 }))),
    ];
    let path = write_archive("seq-multi-peer.bin", &events);
    let output = replayer()
        .arg("--sequence-diagram")
        .arg("--peer")
        .arg("5")
        .arg("--peer")
        .arg("10")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("P5"));
    assert!(stdout.contains("P10"));
}

#[test]
fn test_sequence_diagram_no_messages() {
    let path = write_archive("seq-empty.bin", &[]);
    let output = replayer()
        .arg("--sequence-diagram")
        .arg(path)
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("no P2P messages found"));
}

#[test]
fn test_sequence_diagram_peer_filter_no_match() {
    let events = vec![make_msg_event(
        5,
        "ping",
        true,
        8,
        Some(Msg::Ping(Ping { value: 1 })),
    )];
    let path = write_archive("seq-no-match.bin", &events);
    let output = replayer()
        .arg("--sequence-diagram")
        .arg("--peer")
        .arg("999")
        .arg(path)
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("no P2P messages found"));
}

#[test]
fn test_sequence_diagram_indentation() {
    let events = vec![make_msg_event(
        5,
        "ping",
        true,
        8,
        Some(Msg::Ping(Ping { value: 1 })),
    )];
    let path = write_archive("seq-indent.bin", &events);
    let output = replayer()
        .arg("--sequence-diagram")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    for line in stdout.lines().skip(1) {
        if !line.is_empty() {
            assert!(line.starts_with("    "), "line not indented: {:?}", line);
        }
    }
}

// --- CLI edge cases ---

#[test]
fn test_no_files_error() {
    let output = replayer().output().unwrap();
    assert!(!output.status.success());
}

#[test]
fn test_bad_file_error() {
    let path = std::env::temp_dir().join("replayer-integ-nonexistent.bin");
    let output = replayer().arg(path).output().unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("error reading"));
}

#[test]
fn test_peer_requires_sequence_diagram() {
    let output = replayer()
        .arg("--peer")
        .arg("5")
        .arg("/dev/null")
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn test_zst_archive() {
    let events = vec![make_msg_event(
        1,
        "ping",
        true,
        8,
        Some(Msg::Ping(Ping { value: 1 })),
    )];
    let path = write_archive_zst("compressed", &events);
    let output = replayer().arg(path).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("total: 1 events"));
}

#[test]
fn test_sequence_diagram_rejects_multiple_files() {
    let events = vec![make_msg_event(
        5,
        "ping",
        true,
        8,
        Some(Msg::Ping(Ping { value: 1 })),
    )];
    let p1 = write_archive("seq-multi-1.bin", &events);
    let p2 = write_archive("seq-multi-2.bin", &events);
    let output = replayer()
        .arg("--sequence-diagram")
        .arg(&p1)
        .arg(&p2)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("single archive file"));
}

// --- time filter ---

#[test]
fn test_from_filter() {
    let events = vec![
        make_msg_event_ts(1000, 1, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event_ts(2000, 1, "ping", true, 8, Some(Msg::Ping(Ping { value: 2 }))),
        make_msg_event_ts(3000, 1, "ping", true, 8, Some(Msg::Ping(Ping { value: 3 }))),
    ];
    let path = write_archive("from-filter.bin", &events);
    let output = replayer()
        .arg("--from")
        .arg("2000")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("total: 2 events"));
}

#[test]
fn test_to_filter() {
    let events = vec![
        make_msg_event_ts(1000, 1, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event_ts(2000, 1, "ping", true, 8, Some(Msg::Ping(Ping { value: 2 }))),
        make_msg_event_ts(3000, 1, "ping", true, 8, Some(Msg::Ping(Ping { value: 3 }))),
    ];
    let path = write_archive("to-filter.bin", &events);
    let output = replayer()
        .arg("--to")
        .arg("2000")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("total: 2 events"));
}

#[test]
fn test_from_to_filter() {
    let events = vec![
        make_msg_event_ts(1000, 1, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event_ts(2000, 1, "ping", true, 8, Some(Msg::Ping(Ping { value: 2 }))),
        make_msg_event_ts(3000, 1, "ping", true, 8, Some(Msg::Ping(Ping { value: 3 }))),
    ];
    let path = write_archive("from-to-filter.bin", &events);
    let output = replayer()
        .arg("--from")
        .arg("1500")
        .arg("--to")
        .arg("2500")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("total: 1 events"));
}

#[test]
fn test_from_to_filter_with_sequence_diagram() {
    let events = vec![
        make_msg_event_ts(1000, 5, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event_ts(
            2000,
            5,
            "pong",
            false,
            8,
            Some(Msg::Pong(Pong { value: 1 })),
        ),
        make_msg_event_ts(
            3000,
            10,
            "ping",
            true,
            8,
            Some(Msg::Ping(Ping { value: 2 })),
        ),
    ];
    let path = write_archive("from-to-seq.bin", &events);
    let output = replayer()
        .arg("--sequence-diagram")
        .arg("--to")
        .arg("2000")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("P5"));
    assert!(!stdout.contains("P10"));
}

// --- msg-type filter ---

#[test]
fn test_msg_type_filter() {
    let events = vec![
        make_msg_event(1, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event(2, "pong", false, 8, Some(Msg::Pong(Pong { value: 1 }))),
        make_msg_event(1, "inv", true, 100, None),
    ];
    let path = write_archive("msg-type-filter.bin", &events);
    let output = replayer()
        .arg("--msg-type")
        .arg("ping")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("total: 1 events"));
}

#[test]
fn test_msg_type_filter_comma_separated() {
    let events = vec![
        make_msg_event(1, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event(2, "pong", false, 8, Some(Msg::Pong(Pong { value: 1 }))),
        make_msg_event(1, "inv", true, 100, None),
    ];
    let path = write_archive("msg-type-comma.bin", &events);
    let output = replayer()
        .arg("--msg-type")
        .arg("ping,pong")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("total: 2 events"));
}

#[test]
fn test_msg_type_filter_with_sequence_diagram() {
    let events = vec![
        make_msg_event_ts(1000, 5, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event_ts(
            2000,
            5,
            "pong",
            false,
            8,
            Some(Msg::Pong(Pong { value: 1 })),
        ),
        make_msg_event_ts(3000, 5, "inv", true, 100, None),
    ];
    let path = write_archive("msg-type-seq.bin", &events);
    let output = replayer()
        .arg("--sequence-diagram")
        .arg("--msg-type")
        .arg("ping")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("ping"));
    assert!(!stdout.contains("pong"));
    assert!(!stdout.contains("inv"));
}

#[test]
fn test_msg_type_filter_with_csv() {
    let events = vec![
        make_msg_event_ts(1000, 1, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event_ts(
            2000,
            1,
            "pong",
            false,
            8,
            Some(Msg::Pong(Pong { value: 1 })),
        ),
        make_msg_event_ts(3000, 1, "inv", true, 100, None),
    ];
    let archive_path = write_archive("msg-type-csv.bin", &events);
    let csv_path = std::env::temp_dir().join("replayer-integ-msg-type.csv");
    let output = replayer()
        .arg("--csv")
        .arg(&csv_path)
        .arg("--msg-type")
        .arg("ping,inv")
        .arg(archive_path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let csv = std::fs::read_to_string(&csv_path).unwrap();
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 3); // header + 2 rows
    assert!(lines[1].contains("ping"));
    assert!(lines[2].contains("inv"));
}

#[test]
fn test_msg_type_filter_no_match() {
    let events = vec![make_msg_event(
        1,
        "ping",
        true,
        8,
        Some(Msg::Ping(Ping { value: 1 })),
    )];
    let path = write_archive("msg-type-nomatch.bin", &events);
    let output = replayer()
        .arg("--msg-type")
        .arg("tx")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("total: 0 events"));
}

// --- list-peers ---

#[test]
fn test_list_peers() {
    let events = vec![
        make_msg_event(5, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event(5, "pong", false, 8, Some(Msg::Pong(Pong { value: 1 }))),
        make_msg_event(10, "ping", true, 8, Some(Msg::Ping(Ping { value: 2 }))),
    ];
    let path = write_archive("list-peers.bin", &events);
    let output = replayer().arg("--list-peers").arg(path).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Peer ID"));
    assert!(stdout.contains("Address"));
    assert!(stdout.contains("Messages"));
    assert!(stdout.contains("5"));
    assert!(stdout.contains("10"));
    assert!(stdout.contains("127.0.0.5:8333"));
    assert!(stdout.contains("127.0.0.10:8333"));
}

#[test]
fn test_list_peers_empty() {
    let path = write_archive("list-peers-empty.bin", &[]);
    let output = replayer().arg("--list-peers").arg(path).output().unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("no peers found"));
}

#[test]
fn test_list_peers_conflicts_with_sequence_diagram() {
    let output = replayer()
        .arg("--list-peers")
        .arg("--sequence-diagram")
        .arg("/dev/null")
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn test_list_peers_message_count() {
    let events = vec![
        make_msg_event(5, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event(5, "pong", false, 8, Some(Msg::Pong(Pong { value: 1 }))),
        make_msg_event(5, "inv", true, 100, None),
    ];
    let path = write_archive("list-peers-count.bin", &events);
    let output = replayer().arg("--list-peers").arg(path).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    // peer 5 has 3 messages
    let peer_line = stdout.lines().find(|l| l.contains("127.0.0.5")).unwrap();
    assert!(peer_line.contains("3"));
}

// --- html output ---

#[test]
fn test_html_output() {
    let events = vec![make_msg_event(
        5,
        "ping",
        true,
        8,
        Some(Msg::Ping(Ping { value: 1 })),
    )];
    let archive_path = write_archive("html-out.bin", &events);
    let html_path = std::env::temp_dir().join("replayer-integ-html-out.html");
    let output = replayer()
        .arg("--sequence-diagram")
        .arg("--html")
        .arg(&html_path)
        .arg(archive_path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("wrote"));
    let html = std::fs::read_to_string(&html_path).unwrap();
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("mermaid"));
    assert!(html.contains("sequenceDiagram"));
    assert!(html.contains("P5"));
}

#[test]
fn test_html_no_stdout() {
    let events = vec![make_msg_event(
        5,
        "ping",
        true,
        8,
        Some(Msg::Ping(Ping { value: 1 })),
    )];
    let archive_path = write_archive("html-no-stdout.bin", &events);
    let html_path = std::env::temp_dir().join("replayer-integ-html-no-stdout.html");
    let output = replayer()
        .arg("--sequence-diagram")
        .arg("--html")
        .arg(&html_path)
        .arg(archive_path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.is_empty());
}

#[test]
fn test_html_bad_path() {
    let events = vec![make_msg_event(
        5,
        "ping",
        true,
        8,
        Some(Msg::Ping(Ping { value: 1 })),
    )];
    let archive_path = write_archive("html-bad-path.bin", &events);
    let output = replayer()
        .arg("--sequence-diagram")
        .arg("--html")
        .arg("/nonexistent/dir/out.html")
        .arg(archive_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("error writing"));
}

// --- csv ---

#[test]
fn test_csv_messages() {
    let events = vec![
        make_msg_event_ts(1000, 5, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event_ts(
            2000,
            10,
            "pong",
            false,
            8,
            Some(Msg::Pong(Pong { value: 1 })),
        ),
    ];
    let archive_path = write_archive("csv-msgs.bin", &events);
    let csv_path = std::env::temp_dir().join("replayer-integ-csv-msgs.csv");
    let output = replayer()
        .arg("--csv")
        .arg(&csv_path)
        .arg(archive_path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("wrote"));
    let csv = std::fs::read_to_string(&csv_path).unwrap();
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines[0], "timestamp,peer_id,addr,command,direction,size");
    assert_eq!(lines[1], "1000,5,127.0.0.5:8333,ping,in,8");
    assert_eq!(lines[2], "2000,10,127.0.0.10:8333,pong,out,8");
    assert_eq!(lines.len(), 3);
}

#[test]
fn test_csv_empty() {
    let archive_path = write_archive("csv-empty.bin", &[]);
    let csv_path = std::env::temp_dir().join("replayer-integ-csv-empty.csv");
    let output = replayer()
        .arg("--csv")
        .arg(&csv_path)
        .arg(archive_path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let csv = std::fs::read_to_string(&csv_path).unwrap();
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 1); // header only
}

#[test]
fn test_csv_conflicts_with_sequence_diagram() {
    let output = replayer()
        .arg("--csv")
        .arg("/dev/null")
        .arg("--sequence-diagram")
        .arg("/dev/null")
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn test_csv_conflicts_with_list_peers() {
    let output = replayer()
        .arg("--csv")
        .arg("/dev/null")
        .arg("--list-peers")
        .arg("/dev/null")
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn test_csv_with_time_filter() {
    let events = vec![
        make_msg_event_ts(1000, 1, "ping", true, 8, Some(Msg::Ping(Ping { value: 1 }))),
        make_msg_event_ts(
            2000,
            1,
            "pong",
            false,
            8,
            Some(Msg::Pong(Pong { value: 1 })),
        ),
        make_msg_event_ts(3000, 1, "inv", true, 100, None),
    ];
    let archive_path = write_archive("csv-time.bin", &events);
    let csv_path = std::env::temp_dir().join("replayer-integ-csv-time.csv");
    let output = replayer()
        .arg("--csv")
        .arg(&csv_path)
        .arg("--from")
        .arg("1500")
        .arg("--to")
        .arg("2500")
        .arg(archive_path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let csv = std::fs::read_to_string(&csv_path).unwrap();
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 2); // header + 1 row
    assert!(lines[1].starts_with("2000,"));
}

#[test]
fn test_csv_no_stdout() {
    let events = vec![make_msg_event(
        5,
        "ping",
        true,
        8,
        Some(Msg::Ping(Ping { value: 1 })),
    )];
    let archive_path = write_archive("csv-no-stdout.bin", &events);
    let csv_path = std::env::temp_dir().join("replayer-integ-csv-no-stdout.csv");
    let output = replayer()
        .arg("--csv")
        .arg(&csv_path)
        .arg(archive_path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.is_empty());
}

#[test]
fn test_csv_bad_path() {
    let events = vec![make_msg_event(
        5,
        "ping",
        true,
        8,
        Some(Msg::Ping(Ping { value: 1 })),
    )];
    let archive_path = write_archive("csv-bad-path.bin", &events);
    let output = replayer()
        .arg("--csv")
        .arg("/nonexistent/dir/out.csv")
        .arg(archive_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("error writing"));
}

#[test]
fn test_csv_rejects_multiple_files() {
    let events = vec![make_msg_event(
        5,
        "ping",
        true,
        8,
        Some(Msg::Ping(Ping { value: 1 })),
    )];
    let p1 = write_archive("csv-multi-1.bin", &events);
    let p2 = write_archive("csv-multi-2.bin", &events);
    let csv_path = std::env::temp_dir().join("replayer-integ-csv-multi.csv");
    let output = replayer()
        .arg("--csv")
        .arg(&csv_path)
        .arg(&p1)
        .arg(&p2)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("single archive file"));
}

// --- message label in diagram output ---

#[test]
fn test_diagram_message_with_size_no_detail() {
    let events = vec![make_msg_event(5, "tx", true, 500, None)];
    let path = write_archive("seq-size.bin", &events);
    let output = replayer()
        .arg("--sequence-diagram")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("tx (500B)"));
}

#[test]
fn test_diagram_message_no_size_no_detail() {
    let events = vec![make_msg_event(
        5,
        "verack",
        true,
        0,
        Some(Msg::Verack(true)),
    )];
    let path = write_archive("seq-no-size.bin", &events);
    let output = replayer()
        .arg("--sequence-diagram")
        .arg(path)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("verack"));
    assert!(!stdout.contains("(0B)"));
}
