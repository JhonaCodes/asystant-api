use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::error::AppError;
use crate::crypto::{Fingerprint, Random};

/// RFC 6238 time-based codes: HMAC-SHA1, 6 digits, 30-second steps.
pub struct Totp;

impl Totp {
    pub const STEP_SECONDS: i64 = 30;
    pub const SECRET_LEN: usize = 20;
    const DIGITS_MODULO: u32 = 1_000_000;
    const BASE32: &'static [u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    pub fn generate_secret() -> Result<Vec<u8>, AppError> {
        Random::bytes(Self::SECRET_LEN)
    }

    pub fn step(now: DateTime<Utc>) -> i64 {
        now.timestamp().div_euclid(Self::STEP_SECONDS)
    }

    pub fn code(secret: &[u8], step: i64) -> Result<u32, AppError> {
        let mut mac = Hmac::<Sha1>::new_from_slice(secret).map_err(|_| AppError::Internal)?;
        mac.update(&step.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let offset = usize::from(digest[digest.len() - 1] & 0x0f);
        let value = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        Ok(value % Self::DIGITS_MODULO)
    }

    /// Accepts the current step and one on each side for clock drift. Returns
    /// the matching step only if it is newer than `last_step`, so a code that
    /// was already used can never be used again.
    pub fn verify(secret: &[u8], code: &str, now: DateTime<Utc>, last_step: i64) -> Option<i64> {
        let digits: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if digits.len() != 6 || !digits.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let current = Self::step(now);
        let mut matched = None;
        for step in [current - 1, current, current + 1] {
            let expected = Self::code(secret, step).ok()?;
            let candidate = format!("{expected:06}");
            if bool::from(candidate.as_bytes().ct_eq(digits.as_bytes())) && step > last_step {
                matched = Some(step);
            }
        }
        matched
    }

    pub fn base32(secret: &[u8]) -> String {
        let mut out = String::new();
        let mut buffer = 0_u32;
        let mut bits = 0_u32;
        for byte in secret {
            buffer = (buffer << 8) | u32::from(*byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(char::from(Self::BASE32[((buffer >> bits) & 0x1f) as usize]));
            }
        }
        if bits > 0 {
            out.push(char::from(
                Self::BASE32[((buffer << (5 - bits)) & 0x1f) as usize],
            ));
        }
        out
    }

    /// The `otpauth://` link authenticator apps read from a QR code or paste.
    pub fn provisioning_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
        let issuer = Self::encode(issuer);
        format!(
            "otpauth://totp/{issuer}:{}?secret={}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
            Self::encode(account),
            Self::base32(secret)
        )
    }

    fn encode(value: &str) -> String {
        value
            .bytes()
            .map(|byte| match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' => {
                    char::from(byte).to_string()
                }
                _ => format!("%{byte:02X}"),
            })
            .collect()
    }
}

/// Administrator passwords: argon2id, 64 MiB, 3 passes.
pub struct Passwords;

impl Passwords {
    pub const MIN_LEN: usize = 12;
    pub const MAX_LEN: usize = 256;

    fn hasher() -> Result<Argon2<'static>, AppError> {
        let params = Params::new(64 * 1024, 3, 1, None).map_err(|_| AppError::Internal)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    pub fn validate(password: &str) -> Result<(), AppError> {
        let length = password.chars().count();
        if !(Self::MIN_LEN..=Self::MAX_LEN).contains(&length)
            || password.chars().any(char::is_control)
        {
            return Err(AppError::Invalid);
        }
        Ok(())
    }

    pub fn hash(password: &str) -> Result<String, AppError> {
        Self::validate(password)?;
        let salt = SaltString::encode_b64(&Random::bytes(16)?).map_err(|_| AppError::Internal)?;
        Ok(Self::hasher()?
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| AppError::Internal)?
            .to_string())
    }

    pub fn verify(hash: &str, password: &str) -> bool {
        let (Ok(parsed), Ok(hasher)) = (PasswordHash::new(hash), Self::hasher()) else {
            return false;
        };
        hasher.verify_password(password.as_bytes(), &parsed).is_ok()
    }

    /// A random 24-character password for a new or reset administrator.
    pub fn generate() -> Result<String, AppError> {
        Random::base62(24)
    }
}

/// Random tokens for sessions and forms.
pub struct Tokens;

impl Tokens {
    /// 32 random bytes as 64 hex characters.
    pub fn random() -> Result<String, AppError> {
        Random::hex(32)
    }

    pub fn hash(token: &str) -> String {
        Fingerprint::sha256_hex(token)
    }

    pub fn equal(left: &str, right: &str) -> bool {
        left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
    }
}
