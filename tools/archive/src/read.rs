use shared::prost::decode_length_delimiter;
use shared::prost::Message;
use shared::protobuf::archive::ArchiveHeader;
use shared::protobuf::event::Event;
use shared::zstd;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufReader, ErrorKind, Read};
use std::path::Path;

/// Original uncompressed bytes read from the archive, including unknown fields
/// and the actual length delimiter (which need not use its shortest encoding).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameSize {
    pub protobuf_bytes: usize,
    pub delimiter_bytes: usize,
}

impl FrameSize {
    pub fn framed_bytes(&self) -> usize {
        self.protobuf_bytes + self.delimiter_bytes
    }
}

#[derive(Debug)]
pub struct ArchiveRecord {
    pub event: Event,
    pub size: FrameSize,
}

#[derive(Debug)]
pub struct ArchiveReader<R> {
    reader: BufReader<R>,
    buf: Vec<u8>,
    pub header: ArchiveHeader,
    header_size: FrameSize,
}

impl ArchiveReader<Box<dyn Read>> {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;

        // TODO: we could detect the file type based on the ZSTD magic
        // being present or not..
        let reader: Box<dyn Read> = if path.extension() == Some(OsStr::new("zst")) {
            Box::new(zstd::Decoder::new(file)?)
        } else {
            Box::new(file)
        };

        Self::new(reader)
    }
}

impl<R: Read> ArchiveReader<R> {
    pub fn new(reader: R) -> io::Result<Self> {
        let mut reader = BufReader::new(reader);
        let mut buf = Vec::new();

        let (header, header_size) = read_message(&mut reader, &mut buf)?
            .ok_or_else(|| io::Error::other("missing header"))?;

        Ok(Self {
            reader,
            buf,
            header,
            header_size,
        })
    }

    pub fn header_size(&self) -> FrameSize {
        self.header_size
    }

    pub fn next_record(&mut self) -> Option<io::Result<ArchiveRecord>> {
        read_message(&mut self.reader, &mut self.buf)
            .transpose()
            .map(|result| result.map(|(event, size)| ArchiveRecord { event, size }))
    }
}

impl<R: Read> Iterator for ArchiveReader<R> {
    type Item = io::Result<Event>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_record()
            .map(|result| result.map(|record| record.event))
    }
}

fn read_message<M: Message + Default>(
    reader: &mut impl Read,
    buf: &mut Vec<u8>,
) -> io::Result<Option<(M, FrameSize)>> {
    let (protobuf_bytes, delimiter_bytes) = match read_length_delimiter(reader)? {
        Some(length) => length,
        // A clean EOF at a message boundary is the normal end of the archive.
        None => return Ok(None),
    };

    buf.clear();
    buf.resize(protobuf_bytes, 0);

    reader.read_exact(buf)?;

    let msg = M::decode(&buf[..]).map_err(io::Error::other)?;

    Ok(Some((
        msg,
        FrameSize {
            protobuf_bytes,
            delimiter_bytes,
        },
    )))
}

/// Reads a protobuf varint length prefix from `reader`.
///
/// Returns `Ok(None)` on a clean EOF at a message boundary (the normal end of
/// the archive); an EOF partway through the varint surfaces as `UnexpectedEof`.
///
/// prost only decodes a length delimiter from an in-memory `Buf`, so the prefix
/// has to be pulled off the stream first. Its encoded length is not known up
/// front, so we read one byte at a time until the varint's continuation bit
/// clears and hand the collected bytes to prost to decode.
fn read_length_delimiter(reader: &mut impl Read) -> io::Result<Option<(usize, usize)>> {
    let mut bytes = Vec::with_capacity(10);
    loop {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return Ok(None),
            Ok(0) => return Err(io::Error::from(ErrorKind::UnexpectedEof)),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
        bytes.push(byte[0]);

        // Stop once the continuation bit clears. Cap at the maximum varint
        // length so a malformed prefix can't make us read forever; prost then
        // rejects it.
        if byte[0] & 0x80 == 0 || bytes.len() == 10 {
            break;
        }
    }

    decode_length_delimiter(&mut bytes.as_slice())
        .map(|length| Some((length, bytes.len())))
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Yields at most one byte per `read`, so a multi-byte length prefix
    /// arrives split across several reads.
    struct Trickle<R>(R);

    impl<R: Read> Read for Trickle<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.0.read(&mut buf[..1])
        }
    }

    #[test]
    fn reads_single_byte_length_prefix() {
        let mut reader = Cursor::new(vec![0x05]);
        assert_eq!(read_length_delimiter(&mut reader).unwrap(), Some((5, 1)));
    }

    #[test]
    fn reads_multi_byte_length_prefix_split_across_reads() {
        // 300 encodes as the two-byte varint [0xAC, 0x02]. A prefix split across
        // reads must still decode to the full value.
        let mut reader = Trickle(Cursor::new(vec![0xAC, 0x02]));
        assert_eq!(read_length_delimiter(&mut reader).unwrap(), Some((300, 2)));
    }

    #[test]
    fn returns_none_on_clean_eof_at_boundary() {
        let mut reader = Cursor::new(Vec::new());
        assert_eq!(read_length_delimiter(&mut reader).unwrap(), None);
    }

    #[test]
    fn errors_on_truncated_length_prefix() {
        // A lone continuation byte with no follow-up is a truncated varint.
        let mut reader = Cursor::new(vec![0x80]);
        let err = read_length_delimiter(&mut reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn read_message_returns_none_on_clean_eof() {
        let mut reader = BufReader::new(Cursor::new(Vec::new()));
        let mut buf = Vec::new();
        let msg: Option<(ArchiveHeader, FrameSize)> = read_message(&mut reader, &mut buf).unwrap();
        assert!(msg.is_none());
    }
}
