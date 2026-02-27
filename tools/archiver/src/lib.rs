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

use std::fs::{self, File};
use std::io::{BufWriter, Write};

const MAGIC: &[u8; 8] = b"POBS_ARC";
const VERSION: u8 = 1;

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

    fs::create_dir_all(&args.output_dir)?;
    let mut file_index: u32 = 0;
    let mut bytes_written: u64 = 16; // header
    let (mut file_path, mut writer) =
        create_archive_file(&args.output_dir, &args.base_name, file_index)?;
    log::info!("Created archive file: {}", file_path.display());

    let mut event_count: u64 = 0;
    loop {
        shared::tokio::select! {
            maybe_msg = sub.next() => {

                if let Some(msg) = maybe_msg {
                    let event = Event::decode(msg.payload.as_ref())?;
                    if should_archive(&event, &args){
                        let event_bytes = write_event(&mut writer, &event)?;
                        bytes_written += event_bytes as u64;
                        event_count += 1;
                        if event_count % 1000 == 0 {
                            log::info!("archived {} events ({:.2} MB)", event_count, bytes_written as f64 / 1_048_576.0);
                        }
                        if bytes_written >= args.max_file_size {
                            writer.flush()?;
                            log::info!("file rotation: {} reached {:.2} MB", file_path.display(), bytes_written as f64 / 1_048_576.0);
                            file_index += 1;
                            bytes_written = 16;
                            let (new_path, new_writer) = create_archive_file(&args.output_dir, &args.base_name, file_index)?;
                            file_path = new_path;
                            writer = new_writer;
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
    log::info!(
        "shutting down. total events archived: {}, file: {}",
        event_count,
        file_path.display()
    );
    writer.flush()?;
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

fn write_event(writer: &mut BufWriter<File>, event: &Event) -> std::io::Result<usize> {
    let buf = event.encode_length_delimited_to_vec();
    writer.write_all(&buf)?;
    Ok(buf.len())
}

fn write_header(writer: &mut BufWriter<File>) -> std::io::Result<()> {
    writer.write_all(MAGIC)?; // 8 bytes: "POBS_ARC"
    writer.write_all(&[VERSION])?; // 1 byte
    writer.write_all(&[0u8; 7])?; // 7 bytes: reserved
    writer.flush()?;
    Ok(())
}

fn create_archive_file(
    output_dir: &PathBuf,
    base_name: &str,
    index: u32,
) -> std::io::Result<(PathBuf, BufWriter<File>)> {
    let file_path = output_dir.join(format!("{}.{}.bin", base_name, index));
    let file = File::create(&file_path)?;
    let mut writer = BufWriter::new(file);
    write_header(&mut writer)?;
    Ok((file_path, writer))
}
