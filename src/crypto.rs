use sha2::{Digest, Sha256};

use crate::error::AppError;

/// Secrets from the operating system's generator.
pub struct Random;

impl Random {
    pub const BASE62: &'static [u8; 62] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    pub fn bytes(length: usize) -> Result<Vec<u8>, AppError> {
        let mut bytes = vec![0_u8; length];
        getrandom::fill(&mut bytes).map_err(|_| AppError::Internal)?;
        Ok(bytes)
    }

    /// Uniform base62: rejection sampling drops bytes >= 248 (= 4 × 62), so no
    /// character is more likely than another. 43 characters carry 256 bits.
    pub fn base62(length: usize) -> Result<String, AppError> {
        let mut out = String::with_capacity(length);
        while out.len() < length {
            for byte in Self::bytes(64)?.into_iter().filter(|byte| *byte < 248) {
                if out.len() == length {
                    break;
                }
                out.push(char::from(Self::BASE62[usize::from(byte % 62)]));
            }
        }
        Ok(out)
    }

    pub fn hex(length: usize) -> Result<String, AppError> {
        Ok(Self::bytes(length)?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }
}

/// Stored stand-ins for high-entropy secrets (API keys, session tokens): the
/// secret itself is never kept, and its 256 random bits make a slow hash
/// unnecessary.
pub struct Fingerprint;

impl Fingerprint {
    pub fn sha256_hex(value: &str) -> String {
        format!("{:x}", Sha256::digest(value.as_bytes()))
    }
}
