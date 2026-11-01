use crate::error::IpcError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Canonical W3C Trace Context version (`0x00`).
pub const W3C_TRACEPARENT_VERSION: u8 = 0x00;

/// W3C `trace-flags` bit mask indicating the trace is sampled (`0x01`).
pub const TRACE_FLAG_SAMPLED: u8 = 0x01;

/// W3C Trace Context (`traceparent`) representation (`00-<trace-id>-<parent-id>-<trace-flags>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceContext {
    pub version: u8,
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub trace_flags: u8,
}

impl TraceContext {
    /// Creates a validated [`TraceContext`], rejecting all-zero `trace_id` or `span_id`
    /// as required by the W3C Trace Context specification.
    pub fn new(trace_id: [u8; 16], span_id: [u8; 8], trace_flags: u8) -> Result<Self, IpcError> {
        if trace_id == [0u8; 16] {
            return Err(IpcError::InvalidTraceContext(
                "trace_id must not be all zeros".to_string(),
            ));
        }
        if span_id == [0u8; 8] {
            return Err(IpcError::InvalidTraceContext(
                "span_id must not be all zeros".to_string(),
            ));
        }
        Ok(Self {
            version: W3C_TRACEPARENT_VERSION,
            trace_id,
            span_id,
            trace_flags,
        })
    }

    /// Creates a root [`TraceContext`] with the sampled flag set according to `sampled`.
    pub fn new_root(
        trace_id: [u8; 16],
        root_span_id: [u8; 8],
        sampled: bool,
    ) -> Result<Self, IpcError> {
        let flags = if sampled { TRACE_FLAG_SAMPLED } else { 0x00 };
        Self::new(trace_id, root_span_id, flags)
    }

    /// Deterministically constructs a non-zero root [`TraceContext`] from 64-bit seeds.
    #[must_use]
    pub fn from_seed(seed_high: u64, seed_low: u64, span_seed: u64, sampled: bool) -> Self {
        let mut trace_id = [0u8; 16];
        let hi = if seed_high == 0 && seed_low == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed_high
        };
        trace_id[..8].copy_from_slice(&hi.to_be_bytes());
        trace_id[8..].copy_from_slice(&seed_low.to_be_bytes());

        let non_zero_span = if span_seed == 0 {
            0x517c_c1b7_2722_0a95
        } else {
            span_seed
        };
        let span_id = non_zero_span.to_be_bytes();
        let trace_flags = if sampled { TRACE_FLAG_SAMPLED } else { 0x00 };

        Self {
            version: W3C_TRACEPARENT_VERSION,
            trace_id,
            span_id,
            trace_flags,
        }
    }

    /// Creates a child [`TraceContext`] sharing the same `trace_id` and `trace_flags`
    /// with a new `child_span_id`.
    pub fn child_span(&self, child_span_id: [u8; 8]) -> Result<Self, IpcError> {
        if child_span_id == [0u8; 8] {
            return Err(IpcError::InvalidTraceContext(
                "child span_id must not be all zeros".to_string(),
            ));
        }
        Ok(Self {
            version: self.version,
            trace_id: self.trace_id,
            span_id: child_span_id,
            trace_flags: self.trace_flags,
        })
    }

    /// Derives a deterministic non-zero child [`TraceContext`] using a 64-bit step counter.
    #[must_use]
    pub fn next_deterministic_child(&self, step_counter: u64) -> Self {
        let parent_u64 = u64::from_be_bytes(self.span_id);
        let mixed = parent_u64
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(step_counter.wrapping_add(1));
        let non_zero = if mixed == 0 { 1 } else { mixed };
        Self {
            version: self.version,
            trace_id: self.trace_id,
            span_id: non_zero.to_be_bytes(),
            trace_flags: self.trace_flags,
        }
    }

    /// Parses a W3C `traceparent` header string (`00-<32hex>-<16hex>-<2hex>`).
    pub fn parse_traceparent(header: &str) -> Result<Self, IpcError> {
        let trimmed = header.trim();
        let parts: Vec<&str> = trimmed.split('-').collect();
        if parts.len() != 4 {
            return Err(IpcError::InvalidTraceContext(format!(
                "expected 4 hyphen-delimited fields, got {}",
                parts.len()
            )));
        }

        if parts[0].len() != 2 {
            return Err(IpcError::InvalidTraceContext(
                "version field must be 2 lowercase hex characters".to_string(),
            ));
        }
        let mut version_buf = [0u8; 1];
        decode_lowercase_hex(parts[0], &mut version_buf)?;
        let version = version_buf[0];
        if version != W3C_TRACEPARENT_VERSION {
            return Err(IpcError::InvalidTraceContext(format!(
                "unsupported traceparent version 0x{version:02x} (expected 0x00)"
            )));
        }

        let trace_id = parse_trace_id_hex(parts[1])?;
        let span_id = parse_span_id_hex(parts[2])?;

        if parts[3].len() != 2 {
            return Err(IpcError::InvalidTraceContext(
                "trace_flags field must be 2 lowercase hex characters".to_string(),
            ));
        }
        let mut flags_buf = [0u8; 1];
        decode_lowercase_hex(parts[3], &mut flags_buf)?;

        Ok(Self {
            version,
            trace_id,
            span_id,
            trace_flags: flags_buf[0],
        })
    }

    /// Formats this context as a canonical W3C `traceparent` string (`00-<32hex>-<16hex>-<2hex>`).
    #[must_use]
    pub fn to_traceparent(&self) -> String {
        format!(
            "{:02x}-{}-{}-{:02x}",
            self.version,
            self.trace_id_hex(),
            self.span_id_hex(),
            self.trace_flags
        )
    }

    /// Returns the 32-character lowercase hexadecimal `trace_id`.
    #[must_use]
    pub fn trace_id_hex(&self) -> String {
        encode_hex(&self.trace_id)
    }

    /// Returns the 16-character lowercase hexadecimal `span_id`.
    #[must_use]
    pub fn span_id_hex(&self) -> String {
        encode_hex(&self.span_id)
    }

    /// Returns `true` if `TRACE_FLAG_SAMPLED` (`0x01`) is set.
    #[must_use]
    pub const fn is_sampled(&self) -> bool {
        (self.trace_flags & TRACE_FLAG_SAMPLED) != 0
    }
}

impl fmt::Display for TraceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_traceparent())
    }
}

impl FromStr for TraceContext {
    type Err = IpcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_traceparent(s)
    }
}

/// Parses a 32-character lowercase hex string into a non-zero 16-byte W3C `trace_id`.
pub fn parse_trace_id_hex(hex: &str) -> Result<[u8; 16], IpcError> {
    if hex.len() != 32 {
        return Err(IpcError::InvalidTraceContext(format!(
            "trace_id must be 32 lowercase hex characters, got {}",
            hex.len()
        )));
    }
    let mut out = [0u8; 16];
    decode_lowercase_hex(hex, &mut out)?;
    if out == [0u8; 16] {
        return Err(IpcError::InvalidTraceContext(
            "trace_id must not be all zeros".to_string(),
        ));
    }
    Ok(out)
}

/// Parses a 16-character lowercase hex string into a non-zero 8-byte W3C `span_id`.
pub fn parse_span_id_hex(hex: &str) -> Result<[u8; 8], IpcError> {
    if hex.len() != 16 {
        return Err(IpcError::InvalidTraceContext(format!(
            "span_id must be 16 lowercase hex characters, got {}",
            hex.len()
        )));
    }
    let mut out = [0u8; 8];
    decode_lowercase_hex(hex, &mut out)?;
    if out == [0u8; 8] {
        return Err(IpcError::InvalidTraceContext(
            "span_id must not be all zeros".to_string(),
        ));
    }
    Ok(out)
}

/// Encodes a byte slice as lowercase hexadecimal.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_lowercase_hex(hex: &str, out: &mut [u8]) -> Result<(), IpcError> {
    if hex.len() != out.len() * 2 {
        return Err(IpcError::InvalidTraceContext(
            "hex length mismatch".to_string(),
        ));
    }
    let bytes = hex.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = decode_nibble(bytes[i * 2])?;
        let lo = decode_nibble(bytes[i * 2 + 1])?;
        *slot = (hi << 4) | lo;
    }
    Ok(())
}

fn decode_nibble(c: u8) -> Result<u8, IpcError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(IpcError::InvalidTraceContext(format!(
            "invalid lowercase hex character {:?}",
            c as char
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_w3c_traceparent_roundtrip() {
        let raw = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let ctx = TraceContext::parse_traceparent(raw).expect("valid traceparent");
        assert_eq!(ctx.version, 0x00);
        assert_eq!(ctx.trace_id_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(ctx.span_id_hex(), "00f067aa0ba902b7");
        assert!(ctx.is_sampled());
        assert_eq!(ctx.to_traceparent(), raw);
        assert_eq!(ctx.to_string(), raw);
    }

    #[test]
    fn test_rejects_all_zero_trace_or_span_id() {
        assert!(TraceContext::parse_traceparent(
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
        )
        .is_err());
        assert!(TraceContext::parse_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"
        )
        .is_err());
        assert!(TraceContext::new([0u8; 16], [1u8; 8], 1).is_err());
        assert!(TraceContext::new([1u8; 16], [0u8; 8], 1).is_err());
    }

    #[test]
    fn test_rejects_uppercase_or_malformed_traceparent() {
        assert!(TraceContext::parse_traceparent(
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01"
        )
        .is_err());
        assert!(TraceContext::parse_traceparent(
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        )
        .is_err());
        assert!(TraceContext::parse_traceparent("00-short-span-01").is_err());
    }

    #[test]
    fn test_child_span_and_deterministic_derivation() {
        let root = TraceContext::from_seed(0x1234, 0x5678, 0x9abc, true);
        let child = root.next_deterministic_child(1);
        assert_eq!(child.trace_id, root.trace_id);
        assert_ne!(child.span_id, root.span_id);
        assert_ne!(child.span_id, [0u8; 8]);
        assert!(root.child_span([0u8; 8]).is_err());
    }
}
