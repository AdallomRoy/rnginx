//! ngx_event_pipe.{c,h}
//! Buffering upstream response through temp files with configurable limits

use std::rc::Rc;

use ngx_core::buf::Chain;

use crate::core::*;
use crate::request::*;

/// Event pipe for buffering upstream response
pub struct EventPipe {
    pub buffer_size: usize,
    pub bufs: Vec<Chain>,
    pub temp_file_size: i64,
    pub max_temp_file_size: i64,
    pub temp_file_write_size: usize,
}

impl EventPipe {
    pub fn new(
        buffer_size: usize,
        num_bufs: usize,
        max_temp_file_size: i64,
        temp_file_write_size: usize,
    ) -> Self {
        EventPipe {
            buffer_size,
            bufs: Vec::with_capacity(num_bufs),
            temp_file_size: 0,
            max_temp_file_size,
            temp_file_write_size,
        }
    }

    /// Add data to the pipe (from upstream)
    pub fn input(&mut self, _data: &[u8]) -> i64 {
        // TODO: Buffer data or write to temp file if needed
        0
    }

    /// Output data to client (call via body_filter)
    pub fn output(&mut self) -> Option<Chain> {
        // TODO: Return next buffered chain to send to client
        None
    }

    /// Check if all data has been output
    pub fn is_empty(&self) -> bool {
        self.bufs.is_empty() && self.temp_file_size == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_pipe_creation() {
        let pipe = EventPipe::new(4096, 8, 1024 * 1024 * 1024, 16384);
        assert_eq!(pipe.buffer_size, 4096);
        assert!(pipe.is_empty());
    }
}
