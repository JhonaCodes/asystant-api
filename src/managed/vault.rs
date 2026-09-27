use std::fmt::{Debug, Formatter};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, Generate, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::Deserialize;

use crate::error::AppError;
use crate::managed::model::{ManagedKeyAllocation, ManagedSecret, OpenRouterManagedKeyData};

const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Symmetric encryption for secrets the server must read back. XChaCha20-Poly1305
/// with a random 24-byte nonce per operation; the nonce travels in front of the
/// ciphertext.
pub struct SecretBox {
    cipher: XChaCha20Poly1305,
}

impl SecretBox {
    /// The key arrives in base64 and must decode to exactly 32 bytes. It fails at
    /// startup, not on the first request: with a wrong key no stored secret can
    /// be read back.
    pub fn from_base64_key(encoded: &str) -> Result<Self, AppError> {
        let raw = BASE64
            .decode(encoded.trim())
            .map_err(|_| AppError::Invalid)?;
        let key: [u8; KEY_LEN] = raw.as_slice().try_into().map_err(|_| AppError::Invalid)?;
        Ok(Self {
            cipher: XChaCha20Poly1305::new(&Key::from(key)),
        })
    }

    /// Returns `nonce || ciphertext`.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, AppError> {
        // `generate()` panics if the system RNG fails; here that is an error.
        let nonce = XNonce::try_generate().map_err(|_| AppError::Internal)?;
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| AppError::Internal)?;
        let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Fails if the data was altered or the key is not the one that sealed it.
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, AppError> {
        if sealed.len() <= NONCE_LEN {
            return Err(AppError::Internal);
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce_bytes).map_err(|_| AppError::Internal)?;
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| AppError::Internal)
    }
}

/// Read side only: sealing builds the JSON with `expose()` so the secret's
/// redacting `Serialize` never reaches the ciphertext.
#[derive(Deserialize)]
struct EncryptedPayload {
    version: u8,
    allocation: ManagedKeyAllocation,
    key_hash: String,
    secret: ManagedSecret,
}

/// Not a data model: ciphertext never goes to JSON nor Debug output.
#[derive(Clone)]
pub struct ManagedSealedKey(Vec<u8>);

impl Debug for ManagedSealedKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ManagedSealedKey([REDACTED])")
    }
}

impl ManagedSealedKey {
    /// Authenticated ciphertext, never the API key text.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

pub struct ManagedKeyVault {
    cipher: SecretBox,
}

impl ManagedKeyVault {
    pub fn from_base64_key(key: &str) -> Result<Self, AppError> {
        Ok(Self {
            cipher: SecretBox::from_base64_key(key)?,
        })
    }

    pub fn seal(
        &self,
        allocation: &ManagedKeyAllocation,
        hash: &str,
        key: &ManagedSecret,
    ) -> Result<ManagedSealedKey, AppError> {
        OpenRouterManagedKeyData::validate_hash(hash)?;
        let payload = serde_json::to_vec(&serde_json::json!({
            "version": 1, "allocation": allocation, "key_hash": hash, "secret": key.expose()
        }))
        .map_err(|_| AppError::Internal)?;
        if payload.len() > 65_496 {
            return Err(AppError::Internal);
        }
        Ok(ManagedSealedKey(self.cipher.seal(&payload)?))
    }

    pub fn open(
        &self,
        allocation: &ManagedKeyAllocation,
        hash: &str,
        sealed: &[u8],
    ) -> Result<ManagedSecret, AppError> {
        OpenRouterManagedKeyData::validate_hash(hash)?;
        if !(41..=65_536).contains(&sealed.len()) {
            return Err(AppError::Internal);
        }
        let plaintext = self.cipher.open(sealed)?;
        let payload: EncryptedPayload =
            serde_json::from_slice(&plaintext).map_err(|_| AppError::Internal)?;
        if payload.version != 1 || payload.allocation != *allocation || payload.key_hash != hash {
            return Err(AppError::Internal);
        }
        Ok(payload.secret)
    }
}
