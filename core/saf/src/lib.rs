//! Store-and-forward for offline delivery (EP2PC-003 §3.7).
//!
//! When a recipient is offline, the sender asks a small set of **storage peers** to hold an
//! already-encrypted message blob and forward it when the recipient reconnects. Storage
//! peers are untrusted: they only ever see ciphertext + metadata (EP2PC-003 §3.7.2), and
//! the guarantees here are about *availability and metadata hardening*, not confidentiality
//! (which the Double Ratchet already provides, EP2PC-004).
//!
//! This crate is pure logic (no libp2p), so it is unit-testable:
//!   * [`select_storage_peers`] — Sybil-resistant peer selection (§3.7.3),
//!   * [`SafRecord`] / [`SafStore`] — the TTL lifecycle a storage peer runs (§3.7.4),
//!   * [`sign_ack`] / [`verify_ack`] — the signed delete-on-delivery ACK (§3.7.4).

use std::collections::HashMap;

use ep2pc_crypto::{fill_random, sha256, verify_signature};

/// Max time a storage peer keeps an undelivered message before auto-deleting (§3.7.3).
/// 48h is the upper bound; callers may pass a shorter TTL.
pub const DEFAULT_TTL_MS: i64 = 48 * 60 * 60 * 1000;

/// How many independent storage peers hold each message (redundancy, §3.7.3). 3–5 range.
pub const DEFAULT_REDUNDANCY: usize = 4;

/// Domain-separation label for the ACK signature so it can't be replayed as another message.
const ACK_LABEL: &[u8] = b"ep2pc-saf-ack-v1";

/// A peer identifier (libp2p PeerId bytes). Kept as raw bytes so this crate stays free of
/// any networking dependency.
pub type PeerKey = Vec<u8>;

/// Select up to `n` storage peers for a message addressed to `target`.
///
/// Selection deliberately combines **XOR-closeness** (so lookups are efficient and peers are
/// well-distributed) with **randomization** (so an attacker can't cheaply position Sybil
/// nodes to become the *only* holders of a target's traffic, EP2PC-003 §3.7.3):
///
///   1. Hash `target` and each candidate to 32 bytes (uniform width for XOR).
///   2. Rank candidates by XOR distance to the target.
///   3. Take the closest `2n` as a pool, then randomly pick `n` from that pool.
///
/// The recipient itself is never chosen as its own storage peer.
pub fn select_storage_peers(target: &[u8], candidates: &[PeerKey], n: usize) -> Vec<PeerKey> {
    if n == 0 {
        return Vec::new();
    }
    let t = sha256(target);
    let mut ranked: Vec<(&PeerKey, [u8; 32])> = candidates
        .iter()
        .filter(|c| c.as_slice() != target)
        .map(|c| (c, xor(&t, &sha256(c))))
        .collect();
    ranked.sort_by(|a, b| a.1.cmp(&b.1));

    let pool_size = (2 * n).min(ranked.len());
    let mut pool: Vec<PeerKey> = ranked[..pool_size].iter().map(|(c, _)| (*c).clone()).collect();

    // Randomly pick n from the closest-2n pool (partial Fisher–Yates).
    let take = n.min(pool.len());
    for i in 0..take {
        let j = i + (rand_usize() % (pool.len() - i));
        pool.swap(i, j);
    }
    pool.truncate(take);
    pool
}

fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn rand_usize() -> usize {
    let mut b = [0u8; 8];
    fill_random(&mut b);
    usize::from_le_bytes(b)
}

/// A stored, encrypted message a storage peer holds on behalf of an offline recipient.
/// The `blob` is an already-encrypted `EncryptedMessage` (EP2PC-004 §4.8) — opaque here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafRecord {
    pub message_id: Vec<u8>,
    pub recipient: PeerKey,
    pub sender: PeerKey,
    pub blob: Vec<u8>,
    pub stored_at_ms: i64,
    pub ttl_ms: i64,
}

impl SafRecord {
    pub fn new(message_id: Vec<u8>, recipient: PeerKey, sender: PeerKey, blob: Vec<u8>, now_ms: i64) -> Self {
        Self {
            message_id,
            recipient,
            sender,
            blob,
            stored_at_ms: now_ms,
            ttl_ms: DEFAULT_TTL_MS,
        }
    }

    pub fn with_ttl(mut self, ttl_ms: i64) -> Self {
        self.ttl_ms = ttl_ms;
        self
    }

    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms.saturating_sub(self.stored_at_ms) >= self.ttl_ms
    }
}

/// The lifecycle a node runs *when acting as a storage peer* for others (§3.7.4).
#[derive(Default)]
pub struct SafStore {
    by_id: HashMap<Vec<u8>, SafRecord>,
}

impl SafStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a message to hold. Ignored if already expired.
    pub fn store(&mut self, rec: SafRecord, now_ms: i64) {
        if !rec.is_expired(now_ms) {
            self.by_id.insert(rec.message_id.clone(), rec);
        }
    }

    /// Non-expired records addressed to `recipient` — returned when they reconnect and fetch.
    /// Records are *not* removed here; they wait for a signed ACK (or TTL expiry) so a lost
    /// delivery can be retried.
    pub fn records_for(&self, recipient: &[u8], now_ms: i64) -> Vec<SafRecord> {
        self.by_id
            .values()
            .filter(|r| r.recipient == recipient && !r.is_expired(now_ms))
            .cloned()
            .collect()
    }

    /// Delete a record after a valid, signed delivery ACK from the recipient (§3.7.4).
    /// Returns true if a record was removed.
    pub fn ack(&mut self, message_id: &[u8], recipient_ed25519: &[u8; 32], signature: &[u8; 64]) -> bool {
        let Some(rec) = self.by_id.get(message_id) else {
            return false;
        };
        // Only the addressed recipient can clear a record, and only with a valid signature.
        if rec.recipient.as_slice() != recipient_ed25519.as_slice() {
            return false;
        }
        if !verify_ack(recipient_ed25519, message_id, signature) {
            return false;
        }
        self.by_id.remove(message_id).is_some()
    }

    /// Drop all expired records; returns how many were removed. Runs on a rare maintenance
    /// tick, never as polling (EP2PC-001 §1.4, EP2PC-007 §7.7).
    pub fn gc(&mut self, now_ms: i64) -> usize {
        let before = self.by_id.len();
        self.by_id.retain(|_, r| !r.is_expired(now_ms));
        before - self.by_id.len()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

/// The recipient signs the message id (domain-separated) so storage peers can verify that a
/// delete request truly comes from the addressee (§3.7.4). `sign` takes any Ed25519 signer;
/// callers pass `identity.sign` from `ep2pc-crypto`.
pub fn ack_signing_input(message_id: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(ACK_LABEL.len() + message_id.len());
    v.extend_from_slice(ACK_LABEL);
    v.extend_from_slice(message_id);
    v
}

/// Verify a recipient's ACK signature over a message id.
pub fn verify_ack(recipient_ed25519: &[u8; 32], message_id: &[u8], signature: &[u8; 64]) -> bool {
    verify_signature(recipient_ed25519, &ack_signing_input(message_id), signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ep2pc_crypto::Identity;

    fn peer(byte: u8) -> PeerKey {
        vec![byte; 32]
    }

    #[test]
    fn selection_size_and_membership() {
        let target = peer(0);
        let candidates: Vec<PeerKey> = (1..=20).map(peer).collect();
        let chosen = select_storage_peers(&target, &candidates, DEFAULT_REDUNDANCY);
        assert_eq!(chosen.len(), DEFAULT_REDUNDANCY);
        for c in &chosen {
            assert!(candidates.contains(c));
            assert_ne!(c, &target);
        }
    }

    #[test]
    fn selection_never_picks_recipient_or_exceeds_candidates() {
        let target = peer(5);
        // Only two candidates, one of which is the target itself.
        let candidates = vec![peer(5), peer(9)];
        let chosen = select_storage_peers(&target, &candidates, 4);
        assert_eq!(chosen, vec![peer(9)]); // target filtered out, only one remains
    }

    #[test]
    fn selection_draws_only_from_closest_pool() {
        // With n=1, pool = closest 2 by XOR(sha256). A candidate that is never in the
        // closest-2 across many runs must never be selected. We assert the selected peer is
        // always among the two closest.
        let target = peer(200);
        let candidates: Vec<PeerKey> = (0..12).map(peer).collect();

        let t = sha256(&target);
        let mut ranked: Vec<(PeerKey, [u8; 32])> = candidates
            .iter()
            .filter(|c| c.as_slice() != target.as_slice())
            .map(|c| (c.clone(), xor(&t, &sha256(c))))
            .collect();
        ranked.sort_by(|a, b| a.1.cmp(&b.1));
        let closest_two: Vec<PeerKey> = ranked[..2].iter().map(|(c, _)| c.clone()).collect();

        for _ in 0..200 {
            let chosen = select_storage_peers(&target, &candidates, 1);
            assert_eq!(chosen.len(), 1);
            assert!(closest_two.contains(&chosen[0]));
        }
    }

    #[test]
    fn ttl_expiry_and_gc() {
        let mut store = SafStore::new();
        let rec = SafRecord::new(vec![1], peer(2), peer(3), vec![9, 9, 9], 1_000).with_ttl(500);
        store.store(rec, 1_000);
        assert_eq!(store.len(), 1);

        // Not yet expired.
        assert_eq!(store.records_for(&peer(2), 1_400).len(), 1);
        // Expired at stored_at + ttl.
        assert!(store.records_for(&peer(2), 1_500).is_empty());
        assert_eq!(store.gc(1_500), 1);
        assert!(store.is_empty());
    }

    #[test]
    fn signed_ack_deletes_record() {
        let recipient = Identity::generate();
        let recipient_pub = recipient.peer_id_bytes();

        let mut store = SafStore::new();
        let mid = vec![0xAB; 16];
        let rec = SafRecord::new(mid.clone(), recipient_pub.to_vec(), peer(3), vec![1, 2, 3], 0);
        store.store(rec, 0);

        // A valid ACK from the recipient removes the record.
        let sig = recipient.sign(&ack_signing_input(&mid));
        assert!(store.ack(&mid, &recipient_pub, &sig));
        assert!(store.is_empty());
    }

    #[test]
    fn forged_or_wrong_ack_is_rejected() {
        let recipient = Identity::generate();
        let attacker = Identity::generate();
        let recipient_pub = recipient.peer_id_bytes();

        let mut store = SafStore::new();
        let mid = vec![0xCD; 16];
        store.store(
            SafRecord::new(mid.clone(), recipient_pub.to_vec(), peer(3), vec![1], 0),
            0,
        );

        // Attacker signs with their own key -> rejected, record stays.
        let bad_sig = attacker.sign(&ack_signing_input(&mid));
        assert!(!store.ack(&mid, &recipient_pub, &bad_sig));
        assert_eq!(store.len(), 1);

        // Right signer but signature over a different id -> rejected.
        let wrong = recipient.sign(&ack_signing_input(b"other-id"));
        assert!(!store.ack(&mid, &recipient_pub, &wrong));
        assert_eq!(store.len(), 1);
    }
}
