use archive::replayer::{self, Args, ReplayFileError};
use shared::{
    log,
    prost::Message,
    protobuf::{
        archive::ArchiveHeader,
        event::{event::PeerObserverEvent, Event},
        rpc_extractor::{self, rpc},
    },
};
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn test_event() -> Event {
    Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
        rpc_event: Some(rpc::RpcEvent::Uptime(12345)),
    }))
    .unwrap()
}

fn archive_bytes(events: &[Event]) -> Vec<u8> {
    let mut bytes = ArchiveHeader { created: 1 }.encode_length_delimited_to_vec();
    for event in events {
        bytes.extend(event.encode_length_delimited_to_vec());
    }
    bytes
}

fn temp_path(test_name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "archive_replayer_{test_name}_{}_{}.bin",
        std::process::id(),
        nonce
    ))
}

fn write_temp_archive(test_name: &str, bytes: Vec<u8>) -> PathBuf {
    let path = temp_path(test_name);
    fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn replays_valid_archive() {
    let path = write_temp_archive("valid", archive_bytes(&[test_event()]));

    assert_eq!(replayer::replay_file(&path).unwrap(), 1);

    let args = Args {
        files: vec![path.clone()],
        log_level: log::Level::Info,
    };
    assert!(!replayer::run(&args));

    let _ = fs::remove_file(path);
}

#[test]
fn missing_header_is_an_archive_error() {
    let path = write_temp_archive("missing_header", Vec::new());

    match replayer::replay_file(&path).unwrap_err() {
        ReplayFileError::OpenArchive(source) => {
            assert_eq!(source.kind(), ErrorKind::Other);
            assert!(source.to_string().contains("missing header"));
        }
        other => panic!("expected OpenArchive error, got {other:?}"),
    }

    let _ = fs::remove_file(path);
}

#[test]
fn truncated_event_is_an_unexpected_eof() {
    let mut bytes = ArchiveHeader { created: 1 }.encode_length_delimited_to_vec();
    let mut event_bytes = test_event().encode_length_delimited_to_vec();
    event_bytes.pop();
    bytes.extend(event_bytes);
    let path = write_temp_archive("truncated_event", bytes);

    match replayer::replay_file(&path).unwrap_err() {
        ReplayFileError::UnexpectedEof {
            event_number,
            source,
        } => {
            assert_eq!(event_number, 1);
            assert_eq!(source.kind(), ErrorKind::UnexpectedEof);
        }
        other => panic!("expected UnexpectedEof error, got {other:?}"),
    }

    let _ = fs::remove_file(path);
}

#[test]
fn malformed_event_is_a_read_error() {
    let mut bytes = ArchiveHeader { created: 1 }.encode_length_delimited_to_vec();
    bytes.push(1);
    bytes.push(0xff);
    let path = write_temp_archive("malformed_event", bytes);

    match replayer::replay_file(&path).unwrap_err() {
        ReplayFileError::ReadEvent {
            event_number,
            source,
        } => {
            assert_eq!(event_number, 1);
            assert_eq!(source.kind(), ErrorKind::Other);
        }
        other => panic!("expected ReadEvent error, got {other:?}"),
    }

    let _ = fs::remove_file(path);
}

#[test]
fn display_error_is_not_fatal() {
    let event = Event::new(PeerObserverEvent::RpcExtractor(rpc_extractor::Rpc {
        rpc_event: None,
    }))
    .unwrap();
    let path = write_temp_archive("display_error", archive_bytes(&[event]));

    assert_eq!(replayer::replay_file(&path).unwrap(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn run_reports_archive_error() {
    let missing_path = temp_path("missing_file");
    let args = Args {
        files: vec![missing_path],
        log_level: log::Level::Info,
    };

    assert!(replayer::run(&args));
}
