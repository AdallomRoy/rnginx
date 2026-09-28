//! ngx_stream_upstream.c: the upstream{} blocks, the upstream variables.

/// ngx_stream_upstream_state_t
#[derive(Clone, Default, Debug)]
pub struct UpstreamState {
    pub response_time: u64,
    pub connect_time: u64,
    pub first_byte_time: u64,
    pub bytes_sent: i64,
    pub bytes_received: i64,
    pub peer: Option<Vec<u8>>,
}

/// ngx_stream_upstream_t
pub struct StreamUpstream {}
