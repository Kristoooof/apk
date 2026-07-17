//! EP2PC message engine.
//!
//! This is the layer that makes the verified pieces work together:
//!   * `ep2pc-crypto` — X3DH handshake + Double Ratchet session (EP2PC-004),
//!   * `ep2pc-proto`  — the `EncryptedMessage` wire envelope (EP2PC-004 §4.8, EP2PC-005),
//!   * a `SessionStore` — persistence of the per-peer ratchet state (EP2PC-007 §7.4),
//!   * a `ContactResolver` — the public identity of a known contact (added via QR, §3.3).
//!
//! Session bootstrap (EP2PC-004 §4.4):
//!   * The initiator calls [`Engine::establish_outbound`] with the contact's `PreKeyBundle`
//!     (obtained from the QR code). This creates the initiator ratchet and remembers the
//!     X3DH ephemeral to attach to the first outgoing message.
//!   * The responder needs no prior call: on receiving a first message that carries an
//!     `x3dh_ephemeral`, [`Engine::decrypt`] looks up the sender's identity via the
//!     `ContactResolver`, completes the handshake, installs the session, and decrypts.
//!
//! The network layer (`ep2pc-net`) only ever sees encoded `EncryptedMessage` bytes — never
//! plaintext, never key material.

use std::collections::HashMap;

use ep2pc_crypto::{
    initiate_session, respond_session, Header, Identity, IdentityPublic, PreKeyBundle, Ratchet,
    SignedPreKey,
};
use ep2pc_proto::{decode, encode, EncryptedMessage};

/// Cipher-suite marker stored in `EncryptedMessage.cipher_suite` (EP2PC-004 §4.2).
pub const SUITE_CHACHA20_POLY1305: u32 = 1;

/// Persistence boundary for per-peer ratchet state (EP2PC-007 §7.4).
///
/// Implementations must treat the stored bytes as opaque and confidential — they contain
/// the serialized Double Ratchet state, from which future message keys derive.
pub trait SessionStore {
    fn load_session(&self, peer: &[u8]) -> Option<Vec<u8>>;
    fn save_session(&mut self, peer: &[u8], state: &[u8]);
}

/// Look up the stored public identity of a known contact (added via QR, EP2PC-003 §3.3).
/// Needed on the responder side to authenticate and complete an incoming handshake.
pub trait ContactResolver {
    fn identity_of(&self, peer: &[u8]) -> Option<IdentityPublic>;
}

/// In-memory backend for tests (implements both traits).
#[derive(Default)]
pub struct MemBackend {
    sessions: HashMap<Vec<u8>, Vec<u8>>,
    contacts: HashMap<Vec<u8>, IdentityPublic>,
}
impl MemBackend {
    pub fn add_contact(&mut self, peer: &[u8], id: IdentityPublic) {
        self.contacts.insert(peer.to_vec(), id);
    }
}
impl SessionStore for MemBackend {
    fn load_session(&self, peer: &[u8]) -> Option<Vec<u8>> {
        self.sessions.get(peer).cloned()
    }
    fn save_session(&mut self, peer: &[u8], state: &[u8]) {
        self.sessions.insert(peer.to_vec(), state.to_vec());
    }
}
impl ContactResolver for MemBackend {
    fn identity_of(&self, peer: &[u8]) -> Option<IdentityPublic> {
        self.contacts.get(peer).cloned()
    }
}

#[derive(Debug)]
pub enum EngineError {
    /// No ratchet session exists for the peer, and none could be bootstrapped.
    NoSession,
    /// A first message arrived from a peer that isn't in the contact list.
    UnknownContact,
    /// A cryptographic operation failed (bad key/signature, tampered ciphertext).
    Crypto(ep2pc_crypto::CryptoError),
    /// The wire bytes could not be decoded as an `EncryptedMessage`.
    Decode,
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::NoSession => write!(f, "no session for peer"),
            EngineError::UnknownContact => write!(f, "message from unknown contact"),
            EngineError::Crypto(e) => write!(f, "crypto error: {e}"),
            EngineError::Decode => write!(f, "wire decode error"),
        }
    }
}
impl std::error::Error for EngineError {}

/// The message engine. `B` is a single backend providing both session persistence and
/// contact lookup (in production, the SQLCipher-backed `Store`).
pub struct Engine<B: SessionStore + ContactResolver> {
    identity: Identity,
    backend: B,
    local_prekey: SignedPreKey,
    /// peer -> our X3DH ephemeral to attach until the peer replies (handshake confirmed).
    pending_x3dh: HashMap<Vec<u8>, [u8; 32]>,
}

impl<B: SessionStore + ContactResolver> Engine<B> {
    pub fn new(identity: Identity, backend: B, local_prekey: SignedPreKey) -> Self {
        Self {
            identity,
            backend,
            local_prekey,
            pending_x3dh: HashMap::new(),
        }
    }

    /// Our public prekey bundle to share via QR so others can start a session (EP2PC-003 §3.3).
    pub fn own_bundle(&self) -> PreKeyBundle {
        self.local_prekey.bundle(&self.identity)
    }

    /// Install a freshly negotiated ratchet for `peer` and persist it.
    pub fn install_session(&mut self, peer: &[u8], ratchet: &Ratchet) {
        self.backend.save_session(peer, &ratchet.serialize());
    }

    /// Initiator-side session start from a contact's bundle (from their QR). After this,
    /// the first `encrypt` to `peer` carries the X3DH ephemeral so the responder can
    /// complete the handshake.
    pub fn establish_outbound(
        &mut self,
        peer: &[u8],
        their_bundle: &PreKeyBundle,
    ) -> Result<(), EngineError> {
        let (ratchet, ephemeral) =
            initiate_session(&self.identity, their_bundle).map_err(EngineError::Crypto)?;
        self.install_session(peer, &ratchet);
        self.pending_x3dh.insert(peer.to_vec(), ephemeral);
        Ok(())
    }

    /// Encrypt an application `Envelope` (serialized plaintext, EP2PC-005 §5.4) for `peer`,
    /// advancing and persisting the ratchet. Returns encoded `EncryptedMessage` bytes.
    pub fn encrypt(
        &mut self,
        peer: &[u8],
        conversation_id: &[u8],
        plaintext_envelope: &[u8],
    ) -> Result<Vec<u8>, EngineError> {
        let state = self.backend.load_session(peer).ok_or(EngineError::NoSession)?;
        let mut ratchet = Ratchet::deserialize(&state).map_err(EngineError::Crypto)?;

        let (header, ciphertext) = ratchet
            .encrypt(plaintext_envelope, conversation_id)
            .map_err(EngineError::Crypto)?;
        self.backend.save_session(peer, &ratchet.serialize());

        let x3dh_ephemeral = self
            .pending_x3dh
            .get(peer)
            .map(|e| e.to_vec())
            .unwrap_or_default();

        let msg = EncryptedMessage {
            message_id: random16(),
            sender_id: self.identity.peer_id_bytes().to_vec(),
            conversation_id: conversation_id.to_vec(),
            timestamp: now_millis(),
            ratchet_header: header.to_bytes().to_vec(),
            ciphertext,
            cipher_suite: SUITE_CHACHA20_POLY1305,
            x3dh_ephemeral,
        };
        Ok(encode(&msg))
    }

    /// Decrypt an `EncryptedMessage` received from `peer`. If no session exists yet and the
    /// message carries an X3DH ephemeral, the handshake is completed automatically using the
    /// contact's stored identity (responder side, EP2PC-004 §4.4).
    pub fn decrypt(&mut self, peer: &[u8], wire: &[u8]) -> Result<Vec<u8>, EngineError> {
        let msg: EncryptedMessage = decode(wire).map_err(|_| EngineError::Decode)?;

        // Bootstrap a responder session on first contact if needed.
        if self.backend.load_session(peer).is_none() {
            if msg.x3dh_ephemeral.len() != 32 {
                return Err(EngineError::NoSession);
            }
            let their_id = self
                .backend
                .identity_of(peer)
                .ok_or(EngineError::UnknownContact)?;
            let mut eph = [0u8; 32];
            eph.copy_from_slice(&msg.x3dh_ephemeral);
            let ratchet = respond_session(&self.identity, &self.local_prekey, &their_id, &eph);
            self.install_session(peer, &ratchet);
        }

        let state = self.backend.load_session(peer).ok_or(EngineError::NoSession)?;
        let mut ratchet = Ratchet::deserialize(&state).map_err(EngineError::Crypto)?;

        let header = Header::from_bytes(&msg.ratchet_header).map_err(EngineError::Crypto)?;
        let plaintext = ratchet
            .decrypt(&header, &msg.ciphertext, &msg.conversation_id)
            .map_err(EngineError::Crypto)?;

        self.backend.save_session(peer, &ratchet.serialize());
        self.pending_x3dh.remove(peer);
        Ok(plaintext)
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Mutable access to the backend (e.g. to add a contact before establishing a session).
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }
}

fn random16() -> Vec<u8> {
    let mut id = [0u8; 16];
    ep2pc_crypto::fill_random(&mut id);
    id.to_vec()
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ep2pc_crypto::{Identity, SignedPreKey};

    struct Peer {
        engine: Engine<MemBackend>,
        peer_id: Vec<u8>,
        bundle: PreKeyBundle,
    }

    fn make_peer() -> (Identity, SignedPreKey) {
        let id = Identity::generate();
        let spk = SignedPreKey::generate(&id);
        (id, spk)
    }

    /// Two peers who each have the other in their contact list (as after a QR exchange),
    /// but with NO session yet — the handshake must happen over the wire.
    fn two_contacts() -> (Peer, Peer) {
        let (alice_id, alice_spk) = make_peer();
        let (bob_id, bob_spk) = make_peer();
        let alice_peer = alice_id.peer_id_bytes().to_vec();
        let bob_peer = bob_id.peer_id_bytes().to_vec();
        let alice_pub = alice_id.public();
        let bob_pub = bob_id.public();
        let alice_bundle = alice_spk.bundle(&alice_id);
        let bob_bundle = bob_spk.bundle(&bob_id);

        let mut alice_backend = MemBackend::default();
        alice_backend.add_contact(&bob_peer, bob_pub);
        let mut bob_backend = MemBackend::default();
        bob_backend.add_contact(&alice_peer, alice_pub);

        let alice = Peer {
            engine: Engine::new(alice_id, alice_backend, alice_spk),
            peer_id: alice_peer,
            bundle: alice_bundle,
        };
        let bob = Peer {
            engine: Engine::new(bob_id, bob_backend, bob_spk),
            peer_id: bob_peer,
            bundle: bob_bundle,
        };
        (alice, bob)
    }

    #[test]
    fn full_handshake_over_the_wire() {
        let (mut alice, mut bob) = two_contacts();

        // Alice starts a session from Bob's QR bundle, then sends the first message.
        alice
            .engine
            .establish_outbound(&bob.peer_id, &bob.bundle)
            .unwrap();
        let w1 = alice
            .engine
            .encrypt(&bob.peer_id, &bob.peer_id, b"hello bob")
            .unwrap();

        // Bob has NO prior session — he completes the handshake from the wire and decrypts.
        let got = bob.engine.decrypt(&alice.peer_id, &w1).unwrap();
        assert_eq!(got, b"hello bob");

        // Bob replies; Alice decrypts (initiator side).
        let w2 = bob
            .engine
            .encrypt(&alice.peer_id, &alice.peer_id, b"hi alice")
            .unwrap();
        assert_eq!(alice.engine.decrypt(&bob.peer_id, &w2).unwrap(), b"hi alice");
    }

    #[test]
    fn bundle_qr_roundtrip() {
        let (_, bob) = two_contacts();
        let bytes = bob.bundle.to_bytes();
        let parsed = PreKeyBundle::from_bytes(&bytes).unwrap();
        // Re-establish from the parsed bundle works identically.
        let (mut alice, _) = two_contacts();
        assert!(alice.engine.establish_outbound(&bob.peer_id, &parsed).is_ok());
    }

    #[test]
    fn first_message_from_unknown_contact_is_rejected() {
        let (mut alice, mut bob) = two_contacts();
        // Bob forgets Alice (fresh backend, no contacts) -> can't complete the handshake.
        bob.engine = Engine::new(
            Identity::from_secret_bytes(
                &bob.engine.identity().ed25519_secret_bytes(),
                &bob.engine.identity().x25519_secret_bytes(),
            ),
            MemBackend::default(),
            SignedPreKey::from_secret_bytes(bob.engine.identity(), &[9u8; 32]),
        );

        alice
            .engine
            .establish_outbound(&bob.peer_id, &bob.bundle)
            .unwrap();
        let w1 = alice
            .engine
            .encrypt(&bob.peer_id, &bob.peer_id, b"hi")
            .unwrap();
        assert!(matches!(
            bob.engine.decrypt(&alice.peer_id, &w1),
            Err(EngineError::UnknownContact)
        ));
    }

    #[test]
    fn tampered_bundle_signature_is_rejected() {
        let (_, bob) = two_contacts();
        let mut bytes = bob.bundle.to_bytes();
        bytes[100] ^= 0x01; // flip a byte in the signature region
        assert!(PreKeyBundle::from_bytes(&bytes).is_err());
    }

    #[test]
    fn out_of_order_after_handshake() {
        let (mut alice, mut bob) = two_contacts();
        alice
            .engine
            .establish_outbound(&bob.peer_id, &bob.bundle)
            .unwrap();

        let a = alice.engine.encrypt(&bob.peer_id, &bob.peer_id, b"1").unwrap();
        let b = alice.engine.encrypt(&bob.peer_id, &bob.peer_id, b"2").unwrap();
        let c = alice.engine.encrypt(&bob.peer_id, &bob.peer_id, b"3").unwrap();

        // Deliver first (establishes session), then out of order.
        assert_eq!(bob.engine.decrypt(&alice.peer_id, &a).unwrap(), b"1");
        assert_eq!(bob.engine.decrypt(&alice.peer_id, &c).unwrap(), b"3");
        assert_eq!(bob.engine.decrypt(&alice.peer_id, &b).unwrap(), b"2");
    }
}
