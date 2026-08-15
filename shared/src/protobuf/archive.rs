use crate::prost::Message;
use crate::util::current_timestamp;

use std::fmt;

// structs are generated via the archive/header.proto file
include!(concat!(env!("OUT_DIR"), "/header.rs"));

impl ArchiveHeader {
    pub fn new(low_data: bool) -> Self {
        Self {
            created: current_timestamp(),
            low_data: Some(low_data),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_length_delimited_to_vec()
    }
}

impl fmt::Display for ArchiveHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let low_data = match self.low_data {
            Some(true) => "true",
            Some(false) => "false",
            // Archives written before the low_data field existed.
            None => "unknown",
        };
        write!(
            f,
            "ArchiveHeader(created={}, low_data={})",
            self.created, low_data
        )
    }
}
