use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AEAD encryption/decryption failed")]
    Aead,
    #[error("invalid key length")]
    KeyLength,
    #[error("too many skipped messages (possible DoS)")]
    TooManySkipped,
    #[error("message key not available for this header")]
    NoMessageKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("malformed input: {0}")]
    Malformed(&'static str),
}

pub type Result<T> = core::result::Result<T, CryptoError>;
