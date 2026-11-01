//! `muobserve-ipc`: Shared wire contracts, Apache Arrow schemas, and RPC envelopes for MuObserve.

/// Canonical 4-byte frame magic for MuObserve IPC streams (`"MUOB"`).
pub const MAGIC: [u8; 4] = *b"MUOB";

/// Current wire protocol version.
pub const CURRENT_VERSION: u16 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_constants() {
        assert_eq!(&MAGIC, b"MUOB");
        assert_eq!(CURRENT_VERSION, 1);
    }
}
