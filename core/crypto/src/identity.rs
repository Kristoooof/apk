//! Identity model (EP2PC-002 §2.3, EP2PC-004 §4.3).
//!
//! Every user has a long-term **Ed25519** signing key (source of the PeerID and used
//! only for signatures) and a long-term **X25519** key used for Diffie-Hellman during
//! the initial handshake. The Ed25519 private key never leaves the device unencrypted.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};

/// Long-term identity. Contains secret material — keep it inside the Rust core only.
pub struct Identity {
    signing: SigningKey,
    dh_secret: XSecret,
}

/// The public half of an identity, safe to share (goes in the QR code, EP2PC-003 §3.3).
#[derive(Clone)]
pub struct IdentityPublic {
    pub ed25519: [u8; 32],
    pub x25519: [u8; 32],
}

impl Identity {
    /// Generate a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let dh_secret = XSecret::from(seed);
        seed.zeroize();
        Self { signing, dh_secret }
    }

    /// Restore an identity from stored secret bytes (see EP2PC-007 §7.4).
    pub fn from_secret_bytes(ed25519_secret: &[u8; 32], x25519_secret: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(ed25519_secret),
            dh_secret: XSecret::from(*x25519_secret),
        }
    }

    pub fn ed25519_secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn x25519_secret_bytes(&self) -> [u8; 32] {
        self.dh_secret.to_bytes()
    }

    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            ed25519: self.signing.verifying_key().to_bytes(),
            x25519: XPublic::from(&self.dh_secret).to_bytes(),
        }
    }

    /// PeerID = the Ed25519 public key (its multihash form is produced by libp2p, EP2PC-003 §3.2).
    pub fn peer_id_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    pub(crate) fn dh_secret(&self) -> &XSecret {
        &self.dh_secret
    }
}

impl IdentityPublic {
    pub fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.ed25519).map_err(|_| CryptoError::BadSignature)?;
        vk.verify(msg, &Signature::from_bytes(signature))
            .map_err(|_| CryptoError::BadSignature)
    }

    pub fn x25519_public(&self) -> XPublic {
        XPublic::from(self.x25519)
    }

    /// Serialize as ed25519(32) || x25519(32) for the QR code / contact storage.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.ed25519);
        out[32..].copy_from_slice(&self.x25519);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 64 {
            return Err(CryptoError::Malformed("identity public must be 64 bytes"));
        }
        let mut ed = [0u8; 32];
        let mut x = [0u8; 32];
        ed.copy_from_slice(&b[..32]);
        x.copy_from_slice(&b[32..]);
        Ok(Self { ed25519: ed, x25519: x })
    }
}
