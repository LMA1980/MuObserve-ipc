/// Canonical replacement token emitted by [`DeterministicSecretRedactor`].
pub const REDACTED_PLACEHOLDER: &str = "[REDACTED:MUOBSERVE]";

/// Compile-time contract for deterministic secret scrubbing prior to Edge WAL persistence
/// or upstream telemetry transmission.
pub trait SecretRedactor: Send + Sync {
    /// Scrubs sensitive credentials, private keys, and tokens from `input`.
    fn redact(&self, input: &str) -> String;
}

/// Deterministic zero-ReDoS secret redactor covering PEM blocks, Bearer tokens,
/// GitHub PATs (`ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_`, `github_pat_`), AWS access keys (`AKIA`, `ASIA`),
/// and key-value assignments (`password`, `secret`, `token`, `api_key`, `apikey`, `client_secret`, `webhook_secret`).
#[derive(Debug, Clone, Copy, Default)]
pub struct DeterministicSecretRedactor;

impl DeterministicSecretRedactor {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SecretRedactor for DeterministicSecretRedactor {
    fn redact(&self, input: &str) -> String {
        let after_pem = redact_pem_blocks(input);
        let after_bearer = redact_bearer_tokens(&after_pem);
        let after_prefixes = redact_known_token_prefixes(&after_bearer);
        let after_aws = redact_aws_keys(&after_prefixes);
        redact_key_value_pairs(&after_aws)
    }
}

fn redact_pem_blocks(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(begin_idx) = rest.find("-----BEGIN ") {
        let after_begin = &rest[begin_idx..];
        if let Some(header_end_rel) = after_begin.find("PRIVATE KEY-----") {
            out.push_str(&rest[..begin_idx]);
            out.push_str(REDACTED_PLACEHOLDER);

            let search_from = begin_idx + header_end_rel + "PRIVATE KEY-----".len();
            let tail = &rest[search_from..];
            if let Some(end_marker_rel) = tail.find("-----END ") {
                let after_end = &tail[end_marker_rel..];
                if let Some(footer_end_rel) = after_end.find("PRIVATE KEY-----") {
                    let resume_idx =
                        search_from + end_marker_rel + footer_end_rel + "PRIVATE KEY-----".len();
                    rest = &rest[resume_idx..];
                    continue;
                }
            }
            return out;
        }
        let advance = begin_idx + "-----BEGIN ".len();
        out.push_str(&rest[..advance]);
        rest = &rest[advance..];
    }

    out.push_str(rest);
    out
}

fn redact_bearer_tokens(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if i + 7 <= len && bytes[i..i + 7].eq_ignore_ascii_case(b"bearer ") {
            let prev_ok = i == 0 || !is_ident_char(bytes[i - 1]);
            if prev_ok {
                out.push_str(&input[i..i + 7]);
                i += 7;
                while i < len && bytes[i] == b' ' {
                    i += 1;
                }
                if input[i..].starts_with(REDACTED_PLACEHOLDER) {
                    out.push_str(REDACTED_PLACEHOLDER);
                    i += REDACTED_PLACEHOLDER.len();
                    continue;
                }
                let start = i;
                while i < len && is_token_value_char(bytes[i]) {
                    i += 1;
                }
                if i > start {
                    out.push_str(REDACTED_PLACEHOLDER);
                }
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn redact_known_token_prefixes(input: &str) -> String {
    const PREFIXES: &[&str] = &["github_pat_", "ghp_", "gho_", "ghs_", "ghu_", "ghr_"];
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    'outer: while i < len {
        for &prefix in PREFIXES {
            let p_len = prefix.len();
            if i + p_len <= len && &input[i..i + p_len] == prefix {
                let mut j = i + p_len;
                while j < len && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                if j > i + p_len {
                    out.push_str(REDACTED_PLACEHOLDER);
                    i = j;
                    continue 'outer;
                }
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn redact_aws_keys(input: &str) -> String {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        if i + 20 <= len && (&bytes[i..i + 4] == b"AKIA" || &bytes[i..i + 4] == b"ASIA") {
            let prev_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            let next_ok = i + 20 == len || !bytes[i + 20].is_ascii_alphanumeric();
            let body_ok = bytes[i + 4..i + 20]
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
            if prev_ok && next_ok && body_ok {
                out.push_str(REDACTED_PLACEHOLDER);
                i += 20;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn redact_key_value_pairs(input: &str) -> String {
    const KEYS: &[&[u8]] = &[
        b"webhook_secret",
        b"client_secret",
        b"password",
        b"api_key",
        b"apikey",
        b"secret",
        b"token",
    ];
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    'outer: while i < len {
        for &key in KEYS {
            let k_len = key.len();
            if i + k_len < len && bytes[i..i + k_len].eq_ignore_ascii_case(key) {
                let prev_ok = i == 0 || !is_ident_char(bytes[i - 1]);
                let after_key = i + k_len;
                if prev_ok && (bytes[after_key] == b'=' || bytes[after_key] == b':') {
                    // Emit the key and assignment delimiter
                    let mut cursor = after_key + 1;
                    while cursor < len && bytes[cursor] == b' ' {
                        cursor += 1;
                    }
                    // Handle optional quote character
                    let quote = if cursor < len && (bytes[cursor] == b'"' || bytes[cursor] == b'\'')
                    {
                        let q = bytes[cursor];
                        cursor += 1;
                        Some(q)
                    } else {
                        None
                    };

                    out.push_str(&input[i..cursor]);
                    if input[cursor..].starts_with(REDACTED_PLACEHOLDER) {
                        out.push_str(REDACTED_PLACEHOLDER);
                        cursor += REDACTED_PLACEHOLDER.len();
                    } else {
                        let val_start = cursor;
                        if let Some(q) = quote {
                            while cursor < len && bytes[cursor] != q {
                                cursor += 1;
                            }
                        } else {
                            while cursor < len && is_kv_value_char(bytes[cursor]) {
                                cursor += 1;
                            }
                        }

                        if cursor > val_start {
                            out.push_str(REDACTED_PLACEHOLDER);
                        }
                    }
                    if let Some(q) = quote {
                        if cursor < len && bytes[cursor] == q {
                            out.push(q as char);
                            cursor += 1;
                        }
                    }
                    i = cursor;
                    continue 'outer;
                }
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

const fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

const fn is_token_value_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b'+' | b'=')
}

const fn is_kv_value_char(b: u8) -> bool {
    !b.is_ascii_whitespace() && !matches!(b, b',' | b';' | b'&' | b'"' | b'\'' | b')' | b'}' | b']')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_bearer_github_and_aws_tokens() {
        let redactor = DeterministicSecretRedactor::new();
        let line = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sig gh=ghp_1234567890abcdefABCDEF pat=github_pat_99887766_aabb aws=AKIAIOSFODNN7EXAMPLE";
        let scrubbed = redactor.redact(line);
        assert!(!scrubbed.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        assert!(!scrubbed.contains("ghp_1234567890abcdefABCDEF"));
        assert!(!scrubbed.contains("github_pat_99887766_aabb"));
        assert!(!scrubbed.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(scrubbed.contains("Authorization: Bearer [REDACTED:MUOBSERVE]"));
        assert!(scrubbed.contains("aws=[REDACTED:MUOBSERVE]"));
    }

    #[test]
    fn test_redact_pem_and_key_value_pairs() {
        let redactor = DeterministicSecretRedactor::new();
        let input = "db password=supersecretvalue123 api_key=\"sk-live-999\" -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY----- done";
        let scrubbed = redactor.redact(input);
        assert_eq!(
            scrubbed,
            "db password=[REDACTED:MUOBSERVE] api_key=\"[REDACTED:MUOBSERVE]\" [REDACTED:MUOBSERVE] done"
        );
    }
}
