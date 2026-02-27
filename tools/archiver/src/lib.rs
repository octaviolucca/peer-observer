mod error;

pub use error::RuntimeError;

use shared::clap;
use shared::clap::Parser;
use shared::futures::stream::StreamExt;
use shared::log;
use shared::nats_util;
use shared::prost::Message;
use shared::protobuf::ebpf_extractor::ebpf;
use shared::protobuf::event::event::PeerObserverEvent;
use shared::protobuf::event::Event;
use shared::tokio::sync::watch;
use std::path::PathBuf;

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"POBS_ARC";
const VERSION: u8 = 1;

#[derive(Serialize)]
struct Manifest<'a> {
    session: Session,
    files: &'a [FileEntry],
}

#[derive(Serialize)]
struct Session {
    version: u8,
    nats_address: String,
    created_at: u64,
    finished_at: u64,
    total_events: u64,
    total_files: u32,
}

#[derive(Serialize)]
struct FileEntry {
    name: String,
    size_bytes: u64,
    events: u64,
    first_timestamp: u64,
    last_timestamp: u64,
    event_types: Vec<String>,
    checksum: String,
}

#[derive(Parser, Debug, Clone)]
#[command(version, about = "Archive peer-observer events to disk")]
pub struct Args {
    /// Arguments for the connection to the NATS server.
    #[command(flatten)]
    pub nats: nats_util::NatsArgs,

    /// Output directory for archive files.
    #[arg(short, long)]
    pub output_dir: PathBuf,

    /// Base name for archive files (e.g., "mainnet" -> "mainnet.0.bin").
    #[arg(short, long, default_value = "archive")]
    pub base_name: String,

    /// Maximum file size in bytes before rotation (default: 1GB).
    #[arg(long, default_value_t = 1_073_741_824)]
    pub max_file_size: u64,

    /// The log level the tool should run on.
    #[arg(short, long, default_value_t = log::Level::Info)]
    pub log_level: log::Level,

    /// If passed, archive P2P message events.
    #[arg(long)]
    pub messages: bool,

    /// If passed, archive P2P connection events.
    #[arg(long)]
    pub connections: bool,

    /// If passed, archive addrman events.
    #[arg(long)]
    pub addrman: bool,

    /// If passed, archive mempool events.
    #[arg(long)]
    pub mempool: bool,

    /// If passed, archive validation events.
    #[arg(long)]
    pub validation: bool,

    /// If passed, archive RPC events.
    #[arg(long)]
    pub rpc: bool,

    /// If passed, archive p2p-extractor events.
    #[arg(long)]
    pub p2p_extractor: bool,

    /// If passed, archive log-extractor events.
    #[arg(long)]
    pub log_extractor: bool,
}

impl Args {
    /// Returns true if all event types should be archived (no filters specified).
    pub fn show_all(&self) -> bool {
        !(self.messages
            || self.connections
            || self.addrman
            || self.mempool
            || self.validation
            || self.rpc
            || self.p2p_extractor
            || self.log_extractor)
    }
}

pub async fn run(args: Args, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), RuntimeError> {
    if args.show_all() {
        log::info!("archiving all events: {}", args.show_all());
    } else {
        log::info!("archiving all events:           {}", args.show_all());
        log::info!("archiving P2P messages:         {}", args.messages);
        log::info!("archiving P2P connections:      {}", args.connections);
        log::info!("archiving addrman events:       {}", args.addrman);
        log::info!("archiving mempool events:       {}", args.mempool);
        log::info!("archiving validation events:    {}", args.validation);
        log::info!("archiving rpc events:           {}", args.rpc);
        log::info!("archiving p2p_extractor events: {}", args.p2p_extractor);
        log::info!("archiving log_extractor events: {}", args.log_extractor);
    }

    let nc = nats_util::prepare_connection(&args.nats)?
        .connect(&args.nats.address)
        .await?;

    let mut sub = nc.subscribe("*").await?;
    log::info!("Connected to NATS-server at {}", args.nats.address);

    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    fs::create_dir_all(&args.output_dir)?;
    let mut file_index: u32 = 0;
    let mut bytes_written: u64 = 16; // header
    let (mut file_path, mut writer, mut hasher) =
        create_archive_file(&args.output_dir, &args.base_name, file_index)?;
    log::info!("Created archive file: {}", file_path.display());

    let mut event_count: u64 = 0;
    let mut file_events: u64 = 0;
    let mut first_timestamp: u64 = 0;
    let mut last_timestamp: u64 = 0;
    let mut event_types: HashSet<String> = HashSet::new();
    let mut manifest_files: Vec<FileEntry> = Vec::new();

    loop {
        shared::tokio::select! {
            maybe_msg = sub.next() => {

                if let Some(msg) = maybe_msg {
                    let event = Event::decode(msg.payload.as_ref())?;
                    if should_archive(&event, &args){
                        let event_bytes = write_event(&mut writer, &event, &mut hasher)?;
                        bytes_written += event_bytes as u64;
                        event_count += 1;
                        file_events += 1;

                        if first_timestamp == 0 {
                            first_timestamp = event.timestamp;
                        }
                        last_timestamp = event.timestamp;
                        event_types.insert(event_type_name(&event));

                        if bytes_written >= args.max_file_size {
                            writer.flush()?;
                            log::info!("file rotation: {} reached {:.2} MB", file_path.display(), bytes_written as f64 / 1_048_576.0);
                            let checksum = format!("{:x}", hasher.finalize());
                            let mut sorted_types: Vec<String> = event_types.drain().collect();
                            sorted_types.sort();

                            manifest_files.push(FileEntry {
                                name: format!("{}.{}.bin", args.base_name, file_index),
                                size_bytes: bytes_written,
                                events: file_events,
                                first_timestamp,
                                last_timestamp,
                                event_types: sorted_types,
                                checksum,
                            });

                            write_manifest(
                                &args.output_dir,
                                &args.base_name,
                                &args.nats.address,
                                created_at,
                                event_count,
                                &manifest_files,
                            )?;

                            file_index += 1;
                            bytes_written = 16;
                            file_events = 0;
                            first_timestamp = 0;
                            last_timestamp = 0;
                            let (new_path, new_writer, new_hasher) = create_archive_file(&args.output_dir, &args.base_name, file_index)?;
                            file_path = new_path;
                            writer = new_writer;
                            hasher = new_hasher;
                            log::info!("Created archive file: {}", file_path.display());
                        }
                    }
                } else {
                    break; // subscription ended
                }
            }
            res = shutdown_rx.changed() => {
                match res {
                    Ok(_) => {
                        if *shutdown_rx.borrow() {
                            log::info!("archiver tool received shutdown signal.");
                            break;
                        }
                    }
                    Err(_) => {
                        // all senders dropped -> treat as shutdown
                        log::warn!("The shutdown notification sender was dropped. Shutting down.");
                        break;
                    }
                }
            }
        }
    }

    writer.flush()?;
    let checksum = format!("{:x}", hasher.finalize());
    let mut sorted_types: Vec<String> = event_types.drain().collect();
    sorted_types.sort();

    manifest_files.push(FileEntry {
        name: format!("{}.{}.bin", args.base_name, file_index),
        size_bytes: bytes_written,
        events: file_events,
        first_timestamp,
        last_timestamp,
        event_types: sorted_types,
        checksum,
    });

    write_manifest(
        &args.output_dir,
        &args.base_name,
        &args.nats.address,
        created_at,
        event_count,
        &manifest_files,
    )?;

    log::info!(
        "shutting down. total events archived: {}, files: {}",
        event_count,
        file_index + 1
    );
    Ok(())
}

fn should_archive(event: &Event, args: &Args) -> bool {
    if args.show_all() {
        return true;
    }
    match event.peer_observer_event.as_ref().unwrap() {
        PeerObserverEvent::EbpfExtractor(ebpf) => match ebpf.ebpf_event.as_ref().unwrap() {
            ebpf::EbpfEvent::Message(_) => args.messages,
            ebpf::EbpfEvent::Connection(_) => args.connections,
            ebpf::EbpfEvent::Addrman(_) => args.addrman,
            ebpf::EbpfEvent::Mempool(_) => args.mempool,
            ebpf::EbpfEvent::Validation(_) => args.validation,
        },
        PeerObserverEvent::RpcExtractor(_) => args.rpc,
        PeerObserverEvent::P2pExtractor(_) => args.p2p_extractor,
        PeerObserverEvent::LogExtractor(_) => args.log_extractor,
    }
}

fn event_type_name(event: &Event) -> String {
    match event.peer_observer_event.as_ref().unwrap() {
        PeerObserverEvent::EbpfExtractor(e) => match e.ebpf_event.as_ref().unwrap() {
            ebpf::EbpfEvent::Message(_) => "messages".to_string(),
            ebpf::EbpfEvent::Connection(_) => "connections".to_string(),
            ebpf::EbpfEvent::Addrman(_) => "addrman".to_string(),
            ebpf::EbpfEvent::Mempool(_) => "mempool".to_string(),
            ebpf::EbpfEvent::Validation(_) => "validation".to_string(),
        },
        PeerObserverEvent::RpcExtractor(_) => "rpc".to_string(),
        PeerObserverEvent::P2pExtractor(_) => "p2p_extractor".to_string(),
        PeerObserverEvent::LogExtractor(_) => "log_extractor".to_string(),
    }
}

fn write_manifest(
    output_dir: &PathBuf,
    base_name: &str,
    nats_address: &str,
    created_at: u64,
    event_count: u64,
    files: &[FileEntry],
) -> std::io::Result<()> {
    let finished_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let manifest = Manifest {
        session: Session {
            version: VERSION,
            nats_address: nats_address.to_string(),
            created_at,
            finished_at,
            total_events: event_count,
            total_files: files.len() as u32,
        },
        files,
    };
    let manifest_path = output_dir.join(format!("{}.manifest.toml", base_name));
    let toml_str = toml::to_string_pretty(&manifest)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    fs::write(&manifest_path, &toml_str)?;
    log::info!("wrote manifest: {}", manifest_path.display());
    Ok(())
}

fn write_event(
    writer: &mut BufWriter<File>,
    event: &Event,
    hasher: &mut Sha256,
) -> std::io::Result<usize> {
    let buf = event.encode_length_delimited_to_vec();
    writer.write_all(&buf)?;
    hasher.update(&buf);
    Ok(buf.len())
}

// header: 16 bytes = MAGIC (8B) + VERSION (1B) + reserved (7B)
fn write_header(writer: &mut BufWriter<File>, hasher: &mut Sha256) -> std::io::Result<()> {
    let mut header = [0u8; 16];
    header[..8].copy_from_slice(MAGIC);
    header[8] = VERSION;
    writer.write_all(&header)?;
    hasher.update(&header);
    writer.flush()?;
    Ok(())
}

fn create_archive_file(
    output_dir: &PathBuf,
    base_name: &str,
    index: u32,
) -> std::io::Result<(PathBuf, BufWriter<File>, Sha256)> {
    let file_path = output_dir.join(format!("{}.{}.bin", base_name, index));
    let file = File::create(&file_path)?;
    let mut writer = BufWriter::new(file);
    let mut hasher = Sha256::new();
    write_header(&mut writer, &mut hasher)?;
    Ok((file_path, writer, hasher))
}
