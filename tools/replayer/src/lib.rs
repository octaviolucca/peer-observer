use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use shared::prost::Message;
use shared::protobuf::event::Event;
use shared::zstd;

const HEADER_SIZE: usize = 16;

pub struct ArchiveHeader {
    pub version: u8,
    pub git_hash: [u8; 4],
}

pub struct Archive {
    pub header: ArchiveHeader,
    pub events: Vec<Event>,
}

/// Build a raw archive buffer from header fields and encoded events.
/// Used by tests to create valid archive data without the archiver.
#[cfg(test)]
fn build_archive_bytes(version: u8, git_hash: [u8; 4], events: &[Event]) -> Vec<u8> {
    use shared::prost::Message as _;
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

pub fn read_archive(path: &Path) -> std::io::Result<Archive> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    if path.extension() == Some(OsStr::new("zst")) {
        zstd::Decoder::new(file)?.read_to_end(&mut buf)?;
    } else {
        file.read_to_end(&mut buf)?;
    }

    if buf.len() < HEADER_SIZE {
        return Err(std::io::Error::other(format!(
            "file too small: {} bytes",
            buf.len()
        )));
    }

    if &buf[0..2] != b"PA" {
        return Err(std::io::Error::other(format!(
            "invalid magic: {:02x}{:02x} (expected \"PA\")",
            buf[0], buf[1]
        )));
    }

    let header = ArchiveHeader {
        version: buf[2],
        git_hash: [buf[3], buf[4], buf[5], buf[6]],
    };

    let data = &buf[HEADER_SIZE..];
    let mut cursor = 0;
    let mut events = Vec::new();

    while cursor < data.len() {
        let mut wire = &data[cursor..];
        let payload_len = shared::prost::decode_length_delimiter(&mut wire)
            .map_err(|e| std::io::Error::other(format!("bad length at byte {cursor}: {e}")))?;
        let varint_len = (data.len() - cursor) - wire.len();
        let event = Event::decode(&data[cursor + varint_len..cursor + varint_len + payload_len])
            .map_err(|e| std::io::Error::other(format!("decode error at byte {cursor}: {e}")))?;
        cursor += varint_len + payload_len;
        events.push(event);
    }

    Ok(Archive { header, events })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::protobuf::ebpf_extractor::ebpf;
    use shared::protobuf::ebpf_extractor::message::{
        message_event::Msg, MessageEvent, Metadata, Ping, Version,
    };
    use shared::protobuf::ebpf_extractor::Ebpf;
    use shared::protobuf::event::event::PeerObserverEvent;
    use std::io::Write;

    fn make_test_event(ts: u64) -> Event {
        Event {
            timestamp: ts,
            peer_observer_event: Some(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Message(MessageEvent {
                    meta: Metadata {
                        peer_id: 1,
                        addr: "127.0.0.1:8333".to_string(),
                        conn_type: 1,
                        command: "ping".to_string(),
                        inbound: true,
                        size: 8,
                    },
                    msg: Some(Msg::Ping(Ping { value: 42 })),
                })),
            })),
        }
    }

    fn write_tmp_file(name: &str, data: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("replayer-test-{}", name));
        std::fs::write(&path, data).unwrap();
        path
    }

    #[test]
    fn test_read_archive_valid_no_events() {
        let buf = build_archive_bytes(1, [0xaa, 0xbb, 0xcc, 0xdd], &[]);
        let path = write_tmp_file("valid-empty.bin", &buf);
        let archive = read_archive(&path).unwrap();
        assert_eq!(archive.header.version, 1);
        assert_eq!(archive.header.git_hash, [0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(archive.events.is_empty());
    }

    #[test]
    fn test_read_archive_valid_with_events() {
        let events = vec![make_test_event(1000), make_test_event(2000)];
        let buf = build_archive_bytes(1, [0x01, 0x02, 0x03, 0x04], &events);
        let path = write_tmp_file("valid-events.bin", &buf);
        let archive = read_archive(&path).unwrap();
        assert_eq!(archive.events.len(), 2);
        assert_eq!(archive.events[0].timestamp, 1000);
        assert_eq!(archive.events[1].timestamp, 2000);
    }

    #[test]
    fn test_read_archive_too_small() {
        let path = write_tmp_file("too-small.bin", &[0u8; 10]);
        let err = read_archive(&path).err().unwrap();
        assert!(err.to_string().contains("file too small"));
    }

    #[test]
    fn test_read_archive_bad_magic() {
        let mut buf = vec![0u8; 16];
        buf[0..2].copy_from_slice(b"XX");
        let path = write_tmp_file("bad-magic.bin", &buf);
        let err = read_archive(&path).err().unwrap();
        assert!(err.to_string().contains("invalid magic"));
    }

    #[test]
    fn test_read_archive_truncated_event() {
        let mut buf = build_archive_bytes(1, [0; 4], &[]);
        // Append a varint length that promises more bytes than available
        buf.push(0x80); // varint: incomplete
        let path = write_tmp_file("truncated.bin", &buf);
        let err = read_archive(&path).err().unwrap();
        assert!(err.to_string().contains("bad length"));
    }

    #[test]
    fn test_read_archive_corrupt_event() {
        let mut buf = build_archive_bytes(1, [0; 4], &[]);
        // Length delimiter says 5 bytes, then garbage
        buf.push(5);
        buf.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff]);
        let path = write_tmp_file("corrupt.bin", &buf);
        let err = read_archive(&path).err().unwrap();
        assert!(err.to_string().contains("decode error"));
    }

    #[test]
    fn test_read_archive_zst_extension() {
        let events = vec![make_test_event(5000)];
        let raw = build_archive_bytes(1, [0; 4], &events);
        let mut encoder = zstd::Encoder::new(Vec::new(), 3).unwrap();
        encoder.write_all(&raw).unwrap();
        let compressed = encoder.finish().unwrap();
        let path = write_tmp_file("compressed.bin.zst", &compressed);
        let archive = read_archive(&path).unwrap();
        assert_eq!(archive.events.len(), 1);
        assert_eq!(archive.events[0].timestamp, 5000);
    }

    #[test]
    fn test_read_archive_large_event() {
        let event = Event {
            timestamp: 1000,
            peer_observer_event: Some(PeerObserverEvent::EbpfExtractor(Ebpf {
                ebpf_event: Some(ebpf::EbpfEvent::Message(MessageEvent {
                    meta: Metadata {
                        peer_id: 1,
                        addr: "127.0.0.1:8333".to_string(),
                        conn_type: 1,
                        command: "version".to_string(),
                        inbound: true,
                        size: 200,
                    },
                    msg: Some(Msg::Version(Version {
                        version: 70016,
                        services: 1033,
                        timestamp: 0,
                        receiver: Default::default(),
                        sender: Default::default(),
                        nonce: 0,
                        user_agent: "a]".repeat(100),
                        start_height: 800000,
                        relay: true,
                    })),
                })),
            })),
        };
        let buf = build_archive_bytes(1, [0; 4], &[event]);
        let path = write_tmp_file("large-event.bin", &buf);
        let archive = read_archive(&path).unwrap();
        assert_eq!(archive.events.len(), 1);
        assert_eq!(archive.events[0].timestamp, 1000);
    }

    #[test]
    fn test_read_archive_file_not_found() {
        let path = std::path::PathBuf::from("/tmp/replayer-test-nonexistent.bin");
        assert!(read_archive(&path).is_err());
    }
}
