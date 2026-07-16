//! Group orchestration (EP2PC-006 §6.4–6.8).
//!
//! Ties together the two tested cores:
//!   * `ep2pc-group`  — the group state machine (membership, admin auth, key rotation),
//!   * `ep2pc-engine` — 1:1 Double Ratchet sessions used to *deliver* the group key to each
//!     member (EP2PC-006 §6.6: the group key never travels on the group topic, only over
//!     each member's private session).
//!
//! Responsibilities:
//!   * turn an admin action into (a) a signed control to broadcast on the group's GossipSub
//!     topic, and (b) per-recipient encrypted key-delivery messages sent over 1:1 sessions;
//!   * on the receiving side, decrypt an incoming key delivery, (re)build/rotate the local
//!     group state, and apply broadcast controls;
//!   * encrypt/decrypt actual group messages with the current epoch key.
//!
//! The transport itself (GossipSub publish/subscribe, sending the 1:1 wires to peers) is the
//! net/ffi layer's job — this crate produces the bytes and consumes them, so the whole flow
//! is unit-testable without libp2p.

use std::collections::HashMap;

use ep2pc_engine::{ContactResolver, Engine, EngineError, SessionStore};
use ep2pc_group::{GroupChange, GroupCiphertext, GroupError, GroupState, Member, PeerKey};
use ep2pc_proto::{GroupAction, GroupControlPayload};

/// Something the manager produces for the net layer to send.
pub struct GroupOutput {
    /// Signed control to broadcast on the group's GossipSub topic (EP2PC-006 §6.4).
    pub control: GroupControlPayload,
    /// (recipient peer, encrypted 1:1 wire) key-delivery messages (EP2PC-006 §6.6).
    pub key_deliveries: Vec<(PeerKey, Vec<u8>)>,
}

/// Classification of a decrypted incoming 1:1 message.
pub enum Incoming1to1 {
    /// A group key delivery that was absorbed into local state; nothing to show the user.
    GroupKey { group_id: Vec<u8> },
    /// An ordinary chat plaintext (application `Envelope`) for the UI.
    Chat { plaintext: Vec<u8> },
}

/// A parsed GossipSub group broadcast (EP2PC-006 §6.4).
pub enum GroupBroadcast {
    Control(GroupControlPayload),
    Message { group_id: Vec<u8>, ciphertext: Vec<u8> },
}

#[derive(Debug)]
pub enum GroupMgrError {
    UnknownGroup,
    Engine(EngineError),
    Group(GroupError),
    Malformed,
}
impl std::fmt::Display for GroupMgrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for GroupMgrError {}

pub struct GroupManager<B: SessionStore + ContactResolver> {
    engine: Engine<B>,
    my_peer: PeerKey,
    groups: HashMap<Vec<u8>, GroupState>,
    /// Group keys received via 1:1 delivery, awaiting the matching broadcast control.
    pending: HashMap<(Vec<u8>, u32), [u8; 32]>,
}

impl<B: SessionStore + ContactResolver> GroupManager<B> {
    pub fn new(engine: Engine<B>, my_peer: PeerKey) -> Self {
        Self { engine, my_peer, groups: HashMap::new(), pending: HashMap::new() }
    }

    pub fn engine_mut(&mut self) -> &mut Engine<B> {
        &mut self.engine
    }

    /// Our long-term identity (for signing group controls / ACKs).
    pub fn identity(&self) -> &ep2pc_crypto::Identity {
        self.engine.identity()
    }

    /// Leave a group we're a member of. Remaining members rotate; we drop our local state.
    pub fn leave_group(&mut self, group_id: &[u8]) -> Result<GroupOutput, GroupMgrError> {
        let change = {
            let g = self.groups.get_mut(group_id).ok_or(GroupMgrError::UnknownGroup)?;
            g.propose_leave(self.engine.identity()).map_err(GroupMgrError::Group)?
        };
        let out = self.deliver(group_id, change)?;
        self.groups.remove(group_id); // we've left; forget the group
        Ok(out)
    }

    pub fn has_group(&self, group_id: &[u8]) -> bool {
        self.groups.contains_key(group_id)
    }

    pub fn group(&self, group_id: &[u8]) -> Option<&GroupState> {
        self.groups.get(group_id)
    }

    /// Create a group; we become the sole admin (EP2PC-006 §6.5).
    pub fn create_group(&mut self, group_id: Vec<u8>, name: impl Into<String>) {
        let g = GroupState::create(group_id.clone(), self.my_peer.clone(), name);
        self.groups.insert(group_id, g);
    }

    /// Admin: add a member. Produces the broadcast control plus per-recipient key deliveries
    /// (each encrypted over that recipient's 1:1 session). Requires an existing 1:1 session
    /// with every current member (they were added as contacts first).
    pub fn add_member(&mut self, group_id: &[u8], new_member: PeerKey) -> Result<GroupOutput, GroupMgrError> {
        // Borrow groups mutably + engine.identity() immutably (disjoint fields) to mutate state.
        let change = {
            let g = self.groups.get_mut(group_id).ok_or(GroupMgrError::UnknownGroup)?;
            g.propose_add(self.engine.identity(), new_member)
                .map_err(GroupMgrError::Group)?
        };
        self.deliver(group_id, change)
    }

    /// Admin: remove a member. Mandatory rotation; the removed peer is not a recipient.
    pub fn remove_member(&mut self, group_id: &[u8], target: &[u8]) -> Result<GroupOutput, GroupMgrError> {
        let change = {
            let g = self.groups.get_mut(group_id).ok_or(GroupMgrError::UnknownGroup)?;
            g.propose_remove(self.engine.identity(), target)
                .map_err(GroupMgrError::Group)?
        };
        self.deliver(group_id, change)
    }

    /// Encrypt the rotated key to each recipient over their 1:1 session (EP2PC-006 §6.6).
    fn deliver(&mut self, group_id: &[u8], change: GroupChange) -> Result<GroupOutput, GroupMgrError> {
        let mut key_deliveries = Vec::new();
        if let Some(key) = change.new_key {
            // Read snapshot fields from `g` (shared borrow of self.groups) while calling
            // self.engine.encrypt (mut borrow of self.engine) — disjoint fields.
            let plaintext = {
                let g = self.groups.get(group_id).ok_or(GroupMgrError::UnknownGroup)?;
                encode_delivery(group_id, &g.display_name, change.control.key_epoch, &key, g.members())
            };
            for r in &change.key_recipients {
                match self.engine.encrypt(r, group_id, &plaintext) {
                    Ok(wire) => key_deliveries.push((r.clone(), wire)),
                    // A recipient without a 1:1 session can't receive the key yet; skip it.
                    Err(EngineError::NoSession) => continue,
                    Err(e) => return Err(GroupMgrError::Engine(e)),
                }
            }
        }
        Ok(GroupOutput { control: change.control, key_deliveries })
    }

    /// Encrypt a group message with the current epoch key (EP2PC-006 §6.4).
    pub fn encrypt_group(&self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, GroupMgrError> {
        let g = self.groups.get(group_id).ok_or(GroupMgrError::UnknownGroup)?;
        Ok(encode_ciphertext(&g.encrypt(plaintext)))
    }

    /// Decrypt a group message. Fails if we no longer hold that epoch's key (e.g. we were
    /// removed and others rotated past us, EP2PC-006 §6.8).
    pub fn decrypt_group(&self, group_id: &[u8], wire: &[u8]) -> Result<Vec<u8>, GroupMgrError> {
        let g = self.groups.get(group_id).ok_or(GroupMgrError::UnknownGroup)?;
        let ct = decode_ciphertext(wire).ok_or(GroupMgrError::Malformed)?;
        g.decrypt(&ct).map_err(GroupMgrError::Group)
    }

    /// Build the GossipSub payload for a group *message* (kind 0): `0x00 | group_id | ct`.
    pub fn group_message_payload(&self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, GroupMgrError> {
        let ct = self.encrypt_group(group_id, plaintext)?;
        let mut v = vec![0u8];
        put_field(&mut v, group_id);
        v.extend_from_slice(&ct);
        Ok(v)
    }

    /// Build the GossipSub payload for a group *control* (kind 1): `0x01 | proto(control)`.
    pub fn control_payload(control: &GroupControlPayload) -> Vec<u8> {
        let mut v = vec![1u8];
        v.extend_from_slice(&ep2pc_proto::encode(control));
        v
    }

    /// Parse a GossipSub group broadcast payload into a control or a message.
    pub fn parse_broadcast(payload: &[u8]) -> Option<GroupBroadcast> {
        let (kind, rest) = payload.split_first()?;
        match kind {
            0 => {
                let mut c = Cursor { b: rest, pos: 0 };
                let gid = c.field()?.to_vec();
                let ciphertext = rest[c.pos..].to_vec();
                Some(GroupBroadcast::Message { group_id: gid, ciphertext })
            }
            1 => {
                let control: GroupControlPayload = ep2pc_proto::decode(rest).ok()?;
                Some(GroupBroadcast::Control(control))
            }
            _ => None,
        }
    }

    /// Apply a parsed broadcast: control -> local state; message -> decrypted plaintext.
    pub fn apply_broadcast(&mut self, b: GroupBroadcast) -> Result<Option<(Vec<u8>, Vec<u8>)>, GroupMgrError> {
        match b {
            GroupBroadcast::Control(c) => {
                self.handle_control(&c)?;
                Ok(None)
            }
            GroupBroadcast::Message { group_id, ciphertext } => {
                let pt = self.decrypt_group(&group_id, &ciphertext)?;
                Ok(Some((group_id, pt)))
            }
        }
    }

    /// Result of decrypting an incoming 1:1 message: either it was a group key delivery
    /// (consumed internally) or an ordinary chat plaintext for the UI.
    pub fn handle_1to1(&mut self, from: &[u8], wire: &[u8]) -> Result<Incoming1to1, GroupMgrError> {
        // Decrypt exactly once (advancing the ratchet), then decide what it was.
        let plaintext = self.engine.decrypt(from, wire).map_err(GroupMgrError::Engine)?;
        match decode_delivery(&plaintext) {
            Some(d) => {
                let gid = self.absorb_delivery(d);
                Ok(Incoming1to1::GroupKey { group_id: gid })
            }
            None => Ok(Incoming1to1::Chat { plaintext }),
        }
    }

    /// Absorb a decoded key delivery into local state (join if new, else buffer the rotated
    /// key for the matching control). Returns the group id.
    fn absorb_delivery(&mut self, d: Delivery) -> Vec<u8> {
        if let Some(existing) = self.groups.get(&d.group_id) {
            if d.epoch > existing.key_epoch() {
                self.pending.insert((d.group_id.clone(), d.epoch), d.key);
            }
            d.group_id
        } else {
            let gid = d.group_id.clone();
            let g = GroupState::join(d.group_id, d.name, d.epoch, d.key, d.members);
            self.groups.insert(gid.clone(), g);
            gid
        }
    }

    /// Apply a broadcast control (EP2PC-006 §6.4). Uses a buffered key for membership changes.
    pub fn handle_control(&mut self, control: &GroupControlPayload) -> Result<(), GroupMgrError> {
        // If this INVITE targets us and we already joined via key delivery, ignore it.
        if control.action == GroupAction::Invite as u32 && control.target_peer_id == self.my_peer {
            return Ok(());
        }
        let g = self
            .groups
            .get_mut(&control.group_id)
            .ok_or(GroupMgrError::UnknownGroup)?;
        let key = self.pending.remove(&(control.group_id.clone(), control.key_epoch));
        g.apply(control, key).map_err(GroupMgrError::Group)
    }
}

// --- key-delivery wire format (an INVITE-style snapshot) ---
// group_id | name | epoch | key(32) | members[ peer | is_admin(1) | joined_epoch(4) ]

struct Delivery {
    group_id: Vec<u8>,
    name: String,
    epoch: u32,
    key: [u8; 32],
    members: HashMap<PeerKey, Member>,
}

fn encode_delivery(
    group_id: &[u8],
    name: &str,
    epoch: u32,
    key: &[u8; 32],
    members: &HashMap<PeerKey, Member>,
) -> Vec<u8> {
    let mut v = Vec::new();
    put_field(&mut v, group_id);
    put_field(&mut v, name.as_bytes());
    v.extend_from_slice(&epoch.to_be_bytes());
    v.extend_from_slice(key);
    v.extend_from_slice(&(members.len() as u32).to_be_bytes());
    for (peer, m) in members {
        put_field(&mut v, peer);
        v.push(if m.is_admin { 1 } else { 0 });
        v.extend_from_slice(&m.joined_epoch.to_be_bytes());
    }
    v
}

fn decode_delivery(b: &[u8]) -> Option<Delivery> {
    let mut c = Cursor { b, pos: 0 };
    let group_id = c.field()?.to_vec();
    let name = String::from_utf8(c.field()?.to_vec()).ok()?;
    let epoch = c.u32()?;
    let key: [u8; 32] = c.take(32)?.try_into().ok()?;
    let count = c.u32()?;
    let mut members = HashMap::new();
    for _ in 0..count {
        let peer = c.field()?.to_vec();
        let is_admin = c.take(1)?[0] != 0;
        let joined_epoch = c.u32()?;
        members.insert(peer, Member { is_admin, joined_epoch });
    }
    Some(Delivery { group_id, name, epoch, key, members })
}

fn encode_ciphertext(ct: &GroupCiphertext) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + ct.ciphertext.len());
    v.extend_from_slice(&ct.epoch.to_be_bytes());
    v.extend_from_slice(&ct.nonce);
    v.extend_from_slice(&ct.ciphertext);
    v
}

fn decode_ciphertext(b: &[u8]) -> Option<GroupCiphertext> {
    if b.len() < 16 {
        return None;
    }
    let epoch = u32::from_be_bytes(b[0..4].try_into().ok()?);
    let nonce: [u8; 12] = b[4..16].try_into().ok()?;
    Some(GroupCiphertext { epoch, nonce, ciphertext: b[16..].to_vec() })
}

fn put_field(v: &mut Vec<u8>, f: &[u8]) {
    v.extend_from_slice(&(f.len() as u32).to_be_bytes());
    v.extend_from_slice(f);
}

struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.b.len() {
            return None;
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn field(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ep2pc_crypto::{Identity, PreKeyBundle, SignedPreKey};
    use ep2pc_engine::MemBackend;

    struct Node {
        mgr: GroupManager<MemBackend>,
        peer: PeerKey,
        bundle: PreKeyBundle,
    }

    fn node() -> (Identity, SignedPreKey, PeerKey) {
        let id = Identity::generate();
        let spk = SignedPreKey::generate(&id);
        let peer = id.peer_id_bytes().to_vec();
        (id, spk, peer)
    }

    /// Build N nodes that all know each other as contacts (post-QR), with 1:1 sessions ready.
    fn mesh(n: usize) -> Vec<Node> {
        let mut raw: Vec<(Identity, SignedPreKey, PeerKey)> = (0..n).map(|_| node()).collect();
        let pubs: Vec<_> = raw.iter().map(|(id, _, p)| (id.public(), p.clone())).collect();
        let bundles: Vec<PreKeyBundle> =
            raw.iter().map(|(id, spk, _)| spk.bundle(id)).collect();

        let mut nodes = Vec::new();
        for (i, (id, spk, peer)) in raw.drain(..).enumerate() {
            let mut backend = MemBackend::default();
            for (j, (pubk, pj)) in pubs.iter().enumerate() {
                if i != j {
                    backend.add_contact(pj, pubk.clone());
                }
            }
            let engine = Engine::new(id, backend, spk);
            nodes.push(Node {
                mgr: GroupManager::new(engine, peer.clone()),
                peer,
                bundle: bundles[i].clone(),
            });
        }
        nodes
    }

    /// Establish a 1:1 session initiator->responder so key delivery can flow.
    fn establish(a: &mut Node, b: &Node) {
        a.mgr
            .engine_mut()
            .establish_outbound(&b.peer, &b.bundle)
            .unwrap();
    }

    #[test]
    fn create_add_and_message() {
        let mut nodes = mesh(2);
        let (mut alice, bob) = (nodes.remove(0), nodes.remove(0));
        establish(&mut alice, &bob);

        let gid = vec![42u8; 16];
        alice.mgr.create_group(gid.clone(), "team");

        // Alice adds Bob -> control + one key delivery addressed to Bob.
        let out = alice.mgr.add_member(&gid, bob.peer.clone()).unwrap();
        assert_eq!(out.key_deliveries.len(), 1);
        assert_eq!(out.key_deliveries[0].0, bob.peer);

        // Bob receives the key delivery as a 1:1 message -> routed as GroupKey, not chat.
        let mut bob = bob;
        let (_rp, wire) = out.key_deliveries.into_iter().next().unwrap();
        match bob.mgr.handle_1to1(&alice.peer, &wire).unwrap() {
            Incoming1to1::GroupKey { group_id } => assert_eq!(group_id, gid),
            Incoming1to1::Chat { .. } => panic!("delivery misrouted as chat"),
        }
        assert!(bob.mgr.has_group(&gid));

        // Alice broadcasts a group message via GossipSub framing; Bob parses + decrypts.
        let payload = alice.mgr.group_message_payload(&gid, b"hello team").unwrap();
        let b = GroupManager::<MemBackend>::parse_broadcast(&payload).unwrap();
        let (g2, pt) = bob.mgr.apply_broadcast(b).unwrap().unwrap();
        assert_eq!(g2, gid);
        assert_eq!(pt, b"hello team");
    }

    #[test]
    fn ordinary_chat_is_not_misrouted() {
        // A plain 1:1 chat message must come back as Chat, not a group key.
        let mut nodes = mesh(2);
        let (mut alice, mut bob) = (nodes.remove(0), nodes.remove(0));
        establish(&mut alice, &bob);
        // Alice sends Bob a normal chat plaintext through the engine directly.
        let wire = alice
            .mgr
            .engine_mut()
            .encrypt(&bob.peer, &bob.peer, b"just a chat")
            .unwrap();
        match bob.mgr.handle_1to1(&alice.peer, &wire).unwrap() {
            Incoming1to1::Chat { plaintext } => assert_eq!(plaintext, b"just a chat"),
            Incoming1to1::GroupKey { .. } => panic!("chat misrouted as group key"),
        }
    }

    #[test]
    fn control_broadcast_roundtrip() {
        let mut nodes = mesh(2);
        let (mut alice, mut bob) = (nodes.remove(0), nodes.remove(0));
        establish(&mut alice, &bob);
        let gid = vec![5u8; 16];
        alice.mgr.create_group(gid.clone(), "team");
        let out = alice.mgr.add_member(&gid, bob.peer.clone()).unwrap();
        let (_p, wire) = out.key_deliveries.into_iter().next().unwrap();
        bob.mgr.handle_1to1(&alice.peer, &wire).unwrap();

        // The control travels as a kind-1 broadcast; Bob parses + applies it.
        let payload = GroupManager::<MemBackend>::control_payload(&out.control);
        let parsed = GroupManager::<MemBackend>::parse_broadcast(&payload).unwrap();
        assert!(bob.mgr.apply_broadcast(parsed).unwrap().is_none());
    }

    #[test]
    fn removed_member_cannot_read_new_messages() {
        let mut nodes = mesh(2);
        let (mut alice, mut bob) = (nodes.remove(0), nodes.remove(0));
        establish(&mut alice, &bob);

        let gid = vec![7u8; 16];
        alice.mgr.create_group(gid.clone(), "team");
        let out = alice.mgr.add_member(&gid, bob.peer.clone()).unwrap();
        let (_r, wire) = out.key_deliveries.into_iter().next().unwrap();
        bob.mgr.handle_1to1(&alice.peer, &wire).unwrap();

        // Shared-epoch message is readable.
        let p1 = alice.mgr.group_message_payload(&gid, b"before").unwrap();
        let b1 = GroupManager::<MemBackend>::parse_broadcast(&p1).unwrap();
        assert_eq!(bob.mgr.apply_broadcast(b1).unwrap().unwrap().1, b"before");

        // Alice removes Bob -> rotation; Bob receives no new key.
        let out = alice.mgr.remove_member(&gid, &bob.peer).unwrap();
        assert!(out.key_deliveries.is_empty());

        let p2 = alice.mgr.group_message_payload(&gid, b"after - secret").unwrap();
        let b2 = GroupManager::<MemBackend>::parse_broadcast(&p2).unwrap();
        assert!(bob.mgr.apply_broadcast(b2).is_err());
    }

    #[test]
    fn three_members_converge() {
        let mut nodes = mesh(3);
        let mut carol = nodes.remove(2);
        let mut bob = nodes.remove(1);
        let mut alice = nodes.remove(0);
        establish(&mut alice, &bob);
        establish(&mut alice, &carol);

        let gid = vec![9u8; 16];
        alice.mgr.create_group(gid.clone(), "team");

        // Add Bob.
        let out_b = alice.mgr.add_member(&gid, bob.peer.clone()).unwrap();
        let wire_b = out_b.key_deliveries.iter().find(|(p, _)| *p == bob.peer).map(|(_, w)| w.clone()).unwrap();
        bob.mgr.handle_1to1(&alice.peer, &wire_b).unwrap();

        // Add Carol; Bob also gets the new key and applies the control broadcast.
        let out_c = alice.mgr.add_member(&gid, carol.peer.clone()).unwrap();
        for (p, w) in &out_c.key_deliveries {
            if *p == bob.peer {
                bob.mgr.handle_1to1(&alice.peer, w).unwrap();
            } else if *p == carol.peer {
                carol.mgr.handle_1to1(&alice.peer, w).unwrap();
            }
        }
        let ctrl_payload = GroupManager::<MemBackend>::control_payload(&out_c.control);
        let parsed = GroupManager::<MemBackend>::parse_broadcast(&ctrl_payload).unwrap();
        bob.mgr.apply_broadcast(parsed).unwrap();

        // All three share the epoch key.
        let payload = alice.mgr.group_message_payload(&gid, b"gm all").unwrap();
        let pb = GroupManager::<MemBackend>::parse_broadcast(&payload).unwrap();
        let pc = GroupManager::<MemBackend>::parse_broadcast(&payload).unwrap();
        assert_eq!(bob.mgr.apply_broadcast(pb).unwrap().unwrap().1, b"gm all");
        assert_eq!(carol.mgr.apply_broadcast(pc).unwrap().unwrap().1, b"gm all");
    }

    #[test]
    fn leaving_member_drops_group_and_rotates() {
        let mut nodes = mesh(2);
        let (mut alice, mut bob) = (nodes.remove(0), nodes.remove(0));
        establish(&mut alice, &bob);

        let gid = vec![11u8; 16];
        alice.mgr.create_group(gid.clone(), "team");
        let out = alice.mgr.add_member(&gid, bob.peer.clone()).unwrap();
        let (_p, wire) = out.key_deliveries.into_iter().next().unwrap();
        // Processing Alice's delivery establishes Bob's (responder) session to Alice, which
        // he can then use to send his own leave-rotation key back to her.
        bob.mgr.handle_1to1(&alice.peer, &wire).unwrap();

        // Bob leaves: he drops the group; Alice (remaining) is a recipient of the new key.
        let out = bob.mgr.leave_group(&gid).unwrap();
        assert!(!bob.mgr.has_group(&gid));
        assert!(out.key_deliveries.iter().any(|(p, _)| *p == alice.peer));
    }
}
