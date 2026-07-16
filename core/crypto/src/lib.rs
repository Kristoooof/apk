//! EP2PC cryptography core (EP2PC-004).
//!
//! Primitives: Ed25519 (identity/auth), X25519 (DH), HKDF-SHA256 (derivation),
//! ChaCha20-Poly1305 (AEAD), Double Ratchet (session evolution).
//!
//! SECURITY NOTE: this is a from-scratch reference implementation intended to be
//! reviewed and audited by an independent party before production use, exactly as
//! required by EP2PC-009 §9.7. It is correct-by-construction against the Signal spec
//! and covered by the tests below, but it has NOT undergone third-party audit.

pub mod aead;
pub mod error;
pub mod identity;
pub mod kdf;
pub mod ratchet;
pub mod x3dh;

pub use error::{CryptoError, Result};
pub use identity::{Identity, IdentityPublic};
pub use ratchet::{Header, Ratchet};
pub use x3dh::{PreKeyBundle, SignedPreKey};

/// Plain SHA-256, exposed so other crates (e.g. `ep2pc-net` for hashed group topics,
/// EP2PC-006 §6.2) can reuse the same vetted primitive instead of an ad-hoc hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Domain-separated SHA-256 (prefix a context label to avoid cross-use collisions).
pub fn sha256_labeled(label: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update((label.len() as u32).to_be_bytes());
    h.update(label);
    h.update(data);
    h.finalize().into()
}

/// Fill a buffer with cryptographically secure random bytes from the OS CSPRNG.
pub fn fill_random(buf: &mut [u8]) {
    use rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(buf);
}

/// Verify a bare Ed25519 signature against a 32-byte public key. Used where the verifier
/// only has a peer's Ed25519 public key (= its PeerID), e.g. a storage peer checking a
/// recipient's signed store-and-forward ACK (EP2PC-003 §3.7.4).
pub fn verify_signature(ed25519_pub: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    match VerifyingKey::from_bytes(ed25519_pub) {
        Ok(vk) => vk.verify(msg, &Signature::from_bytes(signature)).is_ok(),
        Err(_) => false,
    }
}

/// Convenience: establish two ratchets from a completed X3DH handshake.
///
/// In the real protocol the initiator sends its identity + ephemeral in the first
/// message; here we return both ratchets for testing and local wiring.
pub fn establish_session(
    initiator: &Identity,
    responder: &Identity,
    responder_spk: &SignedPreKey,
) -> Result<(Ratchet, Ratchet)> {
    let bundle = responder_spk.bundle(responder);
    let (sk_a, eph_pub, prekey_pub) = x3dh::initiate(initiator, &bundle)?;
    let alice = Ratchet::init_initiator(sk_a, prekey_pub);

    let sk_b = x3dh::respond(responder, responder_spk, &initiator.public(), &eph_pub);
    let bob = Ratchet::init_responder(sk_b, x25519_clone(responder_spk));

    Ok((alice, bob))
}

/// Initiator side of a real (asynchronous) session start: from a contact's published
/// `PreKeyBundle`, produce the initiator ratchet and the ephemeral public key that must be
/// sent in the first message so the responder can complete the handshake (EP2PC-004 §4.4).
pub fn initiate_session(
    initiator: &Identity,
    bundle: &PreKeyBundle,
) -> Result<(Ratchet, [u8; 32])> {
    let (sk, eph_pub, prekey_pub) = x3dh::initiate(initiator, bundle)?;
    Ok((Ratchet::init_initiator(sk, prekey_pub), eph_pub))
}

/// Responder side: given the initiator's public identity and the ephemeral carried in the
/// first message, produce the ratchet used to receive from that peer (EP2PC-004 §4.4).
pub fn respond_session(
    responder: &Identity,
    own_spk: &SignedPreKey,
    initiator_pub: &IdentityPublic,
    initiator_ephemeral: &[u8; 32],
) -> Ratchet {
    let sk = x3dh::respond(responder, own_spk, initiator_pub, initiator_ephemeral);
    Ratchet::init_responder(sk, own_spk.secret_clone())
}

// SignedPreKey keeps its secret private; expose a clone path for the responder ratchet.
fn x25519_clone(spk: &SignedPreKey) -> x25519_dalek::StaticSecret {
    spk.secret_clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_session() -> (Ratchet, Ratchet) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let bob_spk = SignedPreKey::generate(&bob);
        establish_session(&alice, &bob, &bob_spk).unwrap()
    }

    #[test]
    fn identity_sign_verify() {
        let id = Identity::generate();
        let pubk = id.public();
        let sig = id.sign(b"hello ep2pc");
        assert!(pubk.verify(b"hello ep2pc", &sig).is_ok());
        assert!(pubk.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn aead_roundtrip_and_tamper() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let ct = aead::seal(&key, &nonce, b"secret", b"ad").unwrap();
        assert_eq!(aead::open(&key, &nonce, &ct, b"ad").unwrap(), b"secret");
        // wrong AAD must fail
        assert!(aead::open(&key, &nonce, &ct, b"other").is_err());
        // flipped byte must fail
        let mut bad = ct.clone();
        bad[0] ^= 0x01;
        assert!(aead::open(&key, &nonce, &bad, b"ad").is_err());
    }

    #[test]
    fn ratchet_basic_pingpong() {
        let (mut alice, mut bob) = new_session();

        // Alice -> Bob
        let (h1, c1) = alice.encrypt(b"hi bob", b"").unwrap();
        assert_eq!(bob.decrypt(&h1, &c1, b"").unwrap(), b"hi bob");

        // Bob -> Alice (triggers a DH ratchet on Alice's side)
        let (h2, c2) = bob.encrypt(b"hi alice", b"").unwrap();
        assert_eq!(alice.decrypt(&h2, &c2, b"").unwrap(), b"hi alice");

        // Alice -> Bob again
        let (h3, c3) = alice.encrypt(b"how are you", b"").unwrap();
        assert_eq!(bob.decrypt(&h3, &c3, b"").unwrap(), b"how are you");
    }

    #[test]
    fn ratchet_out_of_order() {
        let (mut alice, mut bob) = new_session();

        let (h1, c1) = alice.encrypt(b"msg1", b"").unwrap();
        let (h2, c2) = alice.encrypt(b"msg2", b"").unwrap();
        let (h3, c3) = alice.encrypt(b"msg3", b"").unwrap();

        // Bob receives 3, then 1, then 2 (skipped keys are stored and reused).
        assert_eq!(bob.decrypt(&h3, &c3, b"").unwrap(), b"msg3");
        assert_eq!(bob.decrypt(&h1, &c1, b"").unwrap(), b"msg1");
        assert_eq!(bob.decrypt(&h2, &c2, b"").unwrap(), b"msg2");
    }

    #[test]
    fn ratchet_many_rounds() {
        let (mut alice, mut bob) = new_session();
        for i in 0..50u32 {
            let m = format!("a->b {i}");
            let (h, c) = alice.encrypt(m.as_bytes(), b"conv").unwrap();
            assert_eq!(bob.decrypt(&h, &c, b"conv").unwrap(), m.as_bytes());

            let r = format!("b->a {i}");
            let (h2, c2) = bob.encrypt(r.as_bytes(), b"conv").unwrap();
            assert_eq!(alice.decrypt(&h2, &c2, b"conv").unwrap(), r.as_bytes());
        }
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let (mut alice, _bob) = new_session();
        let (mut alice2, mut bob2) = new_session();
        let (h, c) = alice.encrypt(b"top secret", b"").unwrap();
        // bob2 belongs to a different session -> must fail, never panic.
        assert!(bob2.decrypt(&h, &c, b"").is_err());
        let _ = &mut alice2;
    }

    #[test]
    fn sha256_known_answer() {
        // NIST/standard vector: SHA-256("abc").
        let digest = sha256(b"abc");
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // domain separation changes the output.
        assert_ne!(sha256(b"abc"), sha256_labeled(b"ctx", b"abc"));
    }

    #[test]
    fn bare_signature_verify() {
        let id = Identity::generate();
        let peer = id.peer_id_bytes(); // == Ed25519 public key
        let sig = id.sign(b"message-id-42");
        assert!(verify_signature(&peer, b"message-id-42", &sig));
        // wrong message or flipped signature must fail.
        assert!(!verify_signature(&peer, b"message-id-43", &sig));
        let mut bad = sig;
        bad[0] ^= 0x01;
        assert!(!verify_signature(&peer, b"message-id-42", &bad));
    }
}
