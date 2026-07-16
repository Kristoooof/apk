//! Key-derivation primitives for the Double Ratchet (EP2PC-004 §4.5, §4.6).
//!
//! All derivations use HKDF-SHA256 (root chain) or HMAC-SHA256 (symmetric chain),
//! exactly as in the Signal Double Ratchet specification.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// A 32-byte secret chain/root key. Zeroized on drop.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SymKey(pub [u8; 32]);

impl SymKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Material derived for a single message: a 32-byte AEAD key + 12-byte nonce.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MessageKey {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
}

/// KDF_RK: advance the root key using a fresh DH output.
/// Returns (new_root_key, new_chain_key).
pub fn kdf_rk(root_key: &[u8; 32], dh_out: &[u8; 32]) -> (SymKey, SymKey) {
    let hk = Hkdf::<Sha256>::new(Some(&root_key[..]), &dh_out[..]);
    let mut okm = [0u8; 64];
    hk.expand(b"EP2PC_RootChain_v1", &mut okm)
        .expect("64 is a valid HKDF length");
    let mut rk = [0u8; 32];
    let mut ck = [0u8; 32];
    rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (SymKey(rk), SymKey(ck))
}

/// KDF_CK: advance a symmetric chain key by one step.
/// Returns (next_chain_key, message_key_material).
pub fn kdf_ck(chain_key: &[u8; 32]) -> (SymKey, MessageKey) {
    // message key = HMAC(ck, 0x01), next chain key = HMAC(ck, 0x02)
    let mut mac = HmacSha256::new_from_slice(chain_key).expect("hmac key");
    mac.update(&[0x01]);
    let mk_seed = mac.finalize().into_bytes();

    let mut mac2 = HmacSha256::new_from_slice(chain_key).expect("hmac key");
    mac2.update(&[0x02]);
    let next_ck_bytes = mac2.finalize().into_bytes();

    let mut next_ck = [0u8; 32];
    next_ck.copy_from_slice(&next_ck_bytes);

    // Expand the message-key seed into an AEAD key + nonce.
    let hk = Hkdf::<Sha256>::new(None, &mk_seed);
    let mut okm = [0u8; 44];
    hk.expand(b"EP2PC_MessageKey_v1", &mut okm)
        .expect("44 is a valid HKDF length");
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    okm.zeroize();

    (SymKey(next_ck), MessageKey { key, nonce })
}
