//! Ed25519 ⇄ libp2p PeerId conversion (EP2PC-003 §3.2).
//!
//! Across EP2PC the **single** peer identifier is the 32-byte Ed25519 public key: it keys
//! contacts, Double Ratchet sessions, and group membership/signatures. libp2p, however,
//! addresses peers by `PeerId`. For Ed25519 keys, a libp2p `PeerId` is deterministically a
//! CIDv0-style **identity multihash** wrapping the protobuf-encoded public key, so the two
//! forms convert losslessly without any network round-trip.
//!
//! This crate implements that byte format directly (no libp2p dependency) so it can be used
//! and unit-tested in pure code; the `net` layer wraps it at the libp2p boundary.
//!
//! Layout of the PeerId bytes for an Ed25519 key:
//! ```text
//! 00 24  08 01  12 20  <32-byte ed25519 pubkey>
//! │  │   │  │   │  │
//! │  │   │  │   │  └─ Data length = 32
//! │  │   │  │   └──── Data field tag (field 2, len-delimited)
//! │  │   │  └─────── KeyType value = 1 (Ed25519)
//! │  │   └────────── KeyType field tag (field 1, varint)
//! │  └────────────── multihash digest length = 36
//! └───────────────── multihash code = 0x00 (identity)
//! ```
//! Total: 38 bytes. Base58btc-encoded these render as the familiar `12D3KooW…` PeerIds.

/// Protobuf-encoded Ed25519 `PublicKey` (libp2p keys.proto): `08 01 12 20 <key>` = 36 bytes.
const PK_PROTO_PREFIX: [u8; 4] = [0x08, 0x01, 0x12, 0x20];
const PK_PROTO_LEN: usize = 36;
/// Full identity-multihash PeerId length for an Ed25519 key.
const PEER_ID_LEN: usize = 38;

/// Encode a 32-byte Ed25519 public key as libp2p PeerId bytes.
pub fn peer_id_bytes_from_ed25519(ed25519_pub: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PEER_ID_LEN);
    out.push(0x00); // multihash code: identity
    out.push(PK_PROTO_LEN as u8); // digest length = 36 (varint, single byte)
    out.extend_from_slice(&PK_PROTO_PREFIX);
    out.extend_from_slice(ed25519_pub);
    out
}

/// Decode libp2p PeerId bytes back to the 32-byte Ed25519 public key.
///
/// Returns `None` if the bytes aren't an Ed25519 identity-multihash PeerId (e.g. an RSA or
/// hashed PeerId) — EP2PC only ever uses Ed25519 identities, so a `None` here signals a peer
/// that isn't a valid EP2PC identity.
pub fn ed25519_from_peer_id_bytes(peer_id: &[u8]) -> Option<[u8; 32]> {
    if peer_id.len() != PEER_ID_LEN {
        return None;
    }
    if peer_id[0] != 0x00 || peer_id[1] != PK_PROTO_LEN as u8 {
        return None; // not an identity multihash of the expected size
    }
    if peer_id[2..6] != PK_PROTO_PREFIX {
        return None; // not an Ed25519 PublicKey protobuf
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&peer_id[6..PEER_ID_LEN]);
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }
        let pid = peer_id_bytes_from_ed25519(&key);
        assert_eq!(pid.len(), PEER_ID_LEN);
        assert_eq!(ed25519_from_peer_id_bytes(&pid), Some(key));
    }

    #[test]
    fn structure_matches_libp2p_format() {
        let key = [0xABu8; 32];
        let pid = peer_id_bytes_from_ed25519(&key);
        // identity multihash header + protobuf PublicKey header.
        assert_eq!(&pid[0..6], &[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]);
        assert_eq!(&pid[6..], &key);
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(ed25519_from_peer_id_bytes(&[]), None);
        assert_eq!(ed25519_from_peer_id_bytes(&[0u8; 38]), None); // wrong protobuf header
        let mut pid = peer_id_bytes_from_ed25519(&[1u8; 32]);
        pid[0] = 0x12; // not an identity multihash
        assert_eq!(ed25519_from_peer_id_bytes(&pid), None);
        pid = peer_id_bytes_from_ed25519(&[1u8; 32]);
        pid.truncate(37); // wrong length
        assert_eq!(ed25519_from_peer_id_bytes(&pid), None);
    }
}
