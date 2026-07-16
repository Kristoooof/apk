//! X3DH-style initial key agreement (EP2PC-004 §4.4).
//!
//! The responder publishes a *signed prekey* (an X25519 keypair signed by its Ed25519
//! identity). The initiator combines three Diffie-Hellman outputs into a shared secret
//! `SK`, which then seeds the Double Ratchet. Identity authentication is provided by the
//! Ed25519 signature over the prekey, preventing MITM at session start
//! (EP2PC-004 §4.11).

use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::identity::{Identity, IdentityPublic};
use crate::kdf::SymKey;

/// A signed prekey held by a responder.
pub struct SignedPreKey {
    secret: XSecret,
    pub public: [u8; 32],
    pub signature: [u8; 64],
}

/// The public bundle a responder advertises so others can start a session with it.
#[derive(Clone)]
pub struct PreKeyBundle {
    pub identity: IdentityPublic,
    pub spk_public: [u8; 32],
    pub spk_signature: [u8; 64],
}

impl SignedPreKey {
    pub fn generate(owner: &Identity) -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let secret = XSecret::from(seed);
        seed.zeroize();
        let public = XPublic::from(&secret).to_bytes();
        let signature = owner.sign(&public);
        Self {
            secret,
            public,
            signature,
        }
    }

    /// Reconstruct a signed prekey from a persisted secret (EP2PC-007 §7.4). The public key
    /// and signature are recomputed; Ed25519 signing is deterministic, so the signature is
    /// identical to the original.
    pub fn from_secret_bytes(owner: &Identity, secret_bytes: &[u8; 32]) -> Self {
        let secret = XSecret::from(*secret_bytes);
        let public = XPublic::from(&secret).to_bytes();
        let signature = owner.sign(&public);
        Self { secret, public, signature }
    }

    /// The 32-byte secret, for encrypted-at-rest persistence.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn bundle(&self, owner: &Identity) -> PreKeyBundle {
        PreKeyBundle {
            identity: owner.public(),
            spk_public: self.public,
            spk_signature: self.signature,
        }
    }

    pub(crate) fn secret(&self) -> &XSecret {
        &self.secret
    }

    /// Clone the secret so the responder can hand it to its Double Ratchet.
    pub(crate) fn secret_clone(&self) -> XSecret {
        self.secret.clone()
    }
}

impl PreKeyBundle {
    /// Serialize as identity(64) || spk_public(32) || spk_signature(64) = 160 bytes, for
    /// the QR code (EP2PC-003 §3.3).
    pub fn to_bytes(&self) -> [u8; 160] {
        let mut out = [0u8; 160];
        out[..64].copy_from_slice(&self.identity.to_bytes());
        out[64..96].copy_from_slice(&self.spk_public);
        out[96..].copy_from_slice(&self.spk_signature);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 160 {
            return Err(CryptoError::Malformed("prekey bundle must be 160 bytes"));
        }
        let identity = IdentityPublic::from_bytes(&b[..64])?;
        let mut spk_public = [0u8; 32];
        let mut spk_signature = [0u8; 64];
        spk_public.copy_from_slice(&b[64..96]);
        spk_signature.copy_from_slice(&b[96..]);
        // Verify the signature immediately so a malformed/forged bundle is rejected here.
        identity
            .verify(&spk_public, &spk_signature)
            .map_err(|_| CryptoError::BadSignature)?;
        Ok(Self { identity, spk_public, spk_signature })
    }
}

fn derive_sk(dh1: &[u8], dh2: &[u8], dh3: &[u8]) -> SymKey {
    let mut ikm = Vec::with_capacity(96);
    // 0xFF prefix per X3DH spec to domain-separate from other DH usage.
    ikm.extend_from_slice(&[0xFFu8; 32]);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut sk = [0u8; 32];
    hk.expand(b"EP2PC_X3DH_v1", &mut sk).expect("32 ok");
    ikm.zeroize();
    SymKey(sk)
}

/// Initiator side. Returns (shared_secret, our_ephemeral_public, responder_prekey_public).
/// The initiator seeds its ratchet with `DHr = responder_prekey_public`.
pub fn initiate(initiator: &Identity, bundle: &PreKeyBundle) -> Result<(SymKey, [u8; 32], [u8; 32])> {
    bundle
        .identity
        .verify(&bundle.spk_public, &bundle.spk_signature)
        .map_err(|_| CryptoError::BadSignature)?;

    let mut eph_seed = [0u8; 32];
    OsRng.fill_bytes(&mut eph_seed);
    let ek = XSecret::from(eph_seed);
    eph_seed.zeroize();
    let ek_pub = XPublic::from(&ek).to_bytes();

    let spk_pub = XPublic::from(bundle.spk_public);
    let ib_dh_pub = bundle.identity.x25519_public();

    let dh1 = initiator.dh_secret().diffie_hellman(&spk_pub);
    let dh2 = ek.diffie_hellman(&ib_dh_pub);
    let dh3 = ek.diffie_hellman(&spk_pub);

    let sk = derive_sk(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes());
    Ok((sk, ek_pub, bundle.spk_public))
}

/// Responder side. `initiator_pub` is the initiator's identity; `initiator_ephemeral`
/// is the ephemeral public sent in the first message.
pub fn respond(
    responder: &Identity,
    spk: &SignedPreKey,
    initiator_pub: &IdentityPublic,
    initiator_ephemeral: &[u8; 32],
) -> SymKey {
    let ia_dh_pub = initiator_pub.x25519_public();
    let ek_pub = XPublic::from(*initiator_ephemeral);

    let dh1 = spk.secret().diffie_hellman(&ia_dh_pub);
    let dh2 = responder.dh_secret().diffie_hellman(&ek_pub);
    let dh3 = spk.secret().diffie_hellman(&ek_pub);

    derive_sk(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes())
}
