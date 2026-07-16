//! Group protocol state machine (EP2PC-006).
//!
//! A group is **not** a server-side entity: every member keeps the group state locally and
//! evolves it by applying signed `GROUP_CONTROL` events (EP2PC-006 §6.1). This crate models
//! that state machine and its invariants:
//!
//!   * **Authorization** — only admins may invite/remove/grant/revoke/rename; every control
//!     is signed by the actor's Ed25519 key and rejected unless the signer was an admin at
//!     the time (EP2PC-006 §6.3).
//!   * **Mandatory key rotation** — any membership change bumps the `key_epoch` and installs
//!     a fresh group key; a removed member (holding only the old key) can no longer read new
//!     messages (EP2PC-006 §6.7–6.8, EP2PC-004 §4.9).
//!
//! Key *distribution* (handing the new key to each remaining member over their 1:1 E2EE
//! session, EP2PC-006 §6.6) is the caller's job — this crate produces the control event and
//! the new key; the engine sends the key over the existing ratchet sessions.
//!
//! This crate is pure logic (crypto + proto only), so the invariants above are unit-tested.

use std::collections::HashMap;

use ep2pc_crypto::{aead, fill_random, verify_signature, Identity};
use ep2pc_proto::{GroupAction, GroupControlPayload};

/// Ed25519 peer id of a group participant (the signer identity, EP2PC-006 §6.3).
pub type PeerKey = Vec<u8>;

const SIG_LABEL: &[u8] = b"ep2pc-group-control-v1";
const GROUP_AAD: &[u8] = b"ep2pc-group-msg-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub is_admin: bool,
    pub joined_epoch: u32,
}

#[derive(Debug)]
pub enum GroupError {
    /// The actor isn't an admin (or isn't a member at all).
    NotAdmin,
    /// The control event's signature didn't verify against the actor's key.
    BadSignature,
    /// The control targets a different group.
    WrongGroup,
    /// The target of a remove/grant/revoke isn't a member.
    TargetNotMember,
    /// A membership change arrived without the new group key it must install.
    MissingKey,
    /// A group message was encrypted under a different key epoch than we hold.
    EpochMismatch,
    /// AEAD open failed.
    Crypto,
    /// Malformed control (bad field length, unknown action).
    Malformed,
}

impl std::fmt::Display for GroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for GroupError {}

/// A signed control event ready for distribution, plus (for membership changes) the fresh
/// group key that must be delivered to the members in `key_recipients` over their 1:1
/// sessions (EP2PC-006 §6.6). `new_key` is `None` for non-rotating actions (grant/revoke/
/// rename).
pub struct GroupChange {
    pub control: GroupControlPayload,
    pub new_key: Option<[u8; 32]>,
    pub key_recipients: Vec<PeerKey>,
}

/// Local view of a group. Every member holds one of these.
#[derive(Clone)]
pub struct GroupState {
    pub group_id: Vec<u8>,
    pub display_name: String,
    pub key_epoch: u32,
    group_key: [u8; 32],
    members: HashMap<PeerKey, Member>,
}

impl GroupState {
    /// Create a new group; `creator` becomes the sole admin at epoch 0 with a fresh key.
    pub fn create(group_id: Vec<u8>, creator: PeerKey, display_name: impl Into<String>) -> Self {
        let mut members = HashMap::new();
        members.insert(creator, Member { is_admin: true, joined_epoch: 0 });
        let mut group_key = [0u8; 32];
        fill_random(&mut group_key);
        Self {
            group_id,
            display_name: display_name.into(),
            key_epoch: 0,
            group_key,
            members,
        }
    }

    /// Reconstruct the group on the invitee's side from the data carried in an INVITE
    /// (metadata + current members + the current group key delivered over 1:1, §6.6).
    pub fn join(
        group_id: Vec<u8>,
        display_name: impl Into<String>,
        key_epoch: u32,
        group_key: [u8; 32],
        members: HashMap<PeerKey, Member>,
    ) -> Self {
        Self { group_id, display_name: display_name.into(), key_epoch, group_key, members }
    }

    pub fn is_member(&self, peer: &[u8]) -> bool {
        self.members.contains_key(peer)
    }
    pub fn is_admin(&self, peer: &[u8]) -> bool {
        self.members.get(peer).map(|m| m.is_admin).unwrap_or(false)
    }
    pub fn member_count(&self) -> usize {
        self.members.len()
    }
    pub fn members(&self) -> &HashMap<PeerKey, Member> {
        &self.members
    }
    pub fn key_epoch(&self) -> u32 {
        self.key_epoch
    }

    // --- admin/member proposers: mutate local state and emit a signed control ---

    /// Admin adds a member. Rotates the key so the new member starts at the new epoch and
    /// can't read prior-epoch history (EP2PC-006 §6.8).
    pub fn propose_add(&mut self, admin: &Identity, new_member: PeerKey) -> Result<GroupChange, GroupError> {
        let actor = admin.peer_id_bytes().to_vec();
        self.require_admin(&actor)?;
        let new_epoch = self.key_epoch + 1;
        self.rotate_key(new_epoch);
        self.members
            .insert(new_member.clone(), Member { is_admin: false, joined_epoch: new_epoch });
        let recipients = self.other_members(&actor);
        Ok(self.change(admin, GroupAction::Invite, &new_member, new_epoch, Some(self.group_key), recipients))
    }

    /// Admin removes a member. Mandatory rotation; the removed peer does NOT receive the new
    /// key, so it can't decrypt anything from the new epoch on (EP2PC-006 §6.7–6.8).
    pub fn propose_remove(&mut self, admin: &Identity, target: &[u8]) -> Result<GroupChange, GroupError> {
        let actor = admin.peer_id_bytes().to_vec();
        self.require_admin(&actor)?;
        if !self.members.contains_key(target) {
            return Err(GroupError::TargetNotMember);
        }
        self.members.remove(target);
        let new_epoch = self.key_epoch + 1;
        self.rotate_key(new_epoch);
        let recipients = self.other_members(&actor); // target already removed -> excluded
        Ok(self.change(admin, GroupAction::Remove, target, new_epoch, Some(self.group_key), recipients))
    }

    /// A member leaves voluntarily. Remaining members rotate (the leaver won't get the key).
    pub fn propose_leave(&mut self, member: &Identity) -> Result<GroupChange, GroupError> {
        let actor = member.peer_id_bytes().to_vec();
        if !self.members.contains_key(&actor) {
            return Err(GroupError::NotAdmin); // not a member
        }
        self.members.remove(&actor);
        let new_epoch = self.key_epoch + 1;
        self.rotate_key(new_epoch);
        let recipients = self.members.keys().cloned().collect();
        Ok(self.change(member, GroupAction::Leave, &actor, new_epoch, Some(self.group_key), recipients))
    }

    /// Admin grants admin rights to a member (no key rotation).
    pub fn propose_grant(&mut self, admin: &Identity, target: &[u8]) -> Result<GroupChange, GroupError> {
        self.set_admin(admin, target, true, GroupAction::GrantAdmin)
    }
    /// Admin revokes admin rights (no key rotation).
    pub fn propose_revoke(&mut self, admin: &Identity, target: &[u8]) -> Result<GroupChange, GroupError> {
        self.set_admin(admin, target, false, GroupAction::RevokeAdmin)
    }

    /// Admin renames the group (no key rotation); the new name travels in `aux`.
    pub fn propose_rename(&mut self, admin: &Identity, new_name: impl Into<String>) -> Result<GroupChange, GroupError> {
        let actor = admin.peer_id_bytes().to_vec();
        self.require_admin(&actor)?;
        let name = new_name.into();
        self.display_name = name.clone();
        let mut control = self.base_control(GroupAction::Rename, &[], self.key_epoch, &actor);
        control.aux = name.into_bytes();
        control.signature = admin.sign(&signing_input(&control)).to_vec();
        Ok(GroupChange { control, new_key: None, key_recipients: Vec::new() })
    }

    // --- applying an incoming control on another member's state ---

    /// Verify and apply an incoming signed control. For membership changes, `new_key` must be
    /// supplied (the key this member received over its 1:1 session, §6.6).
    pub fn apply(&mut self, control: &GroupControlPayload, new_key: Option<[u8; 32]>) -> Result<(), GroupError> {
        if control.group_id != self.group_id {
            return Err(GroupError::WrongGroup);
        }
        let actor: [u8; 32] = control
            .actor
            .as_slice()
            .try_into()
            .map_err(|_| GroupError::Malformed)?;
        let sig: [u8; 64] = control
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| GroupError::Malformed)?;
        if !verify_signature(&actor, &signing_input(control), &sig) {
            return Err(GroupError::BadSignature);
        }
        let action = action_from(control.action)?;
        let actor_vec = actor.to_vec();

        match action {
            GroupAction::Invite => {
                self.require_admin(&actor_vec)?;
                let key = new_key.ok_or(GroupError::MissingKey)?;
                self.rotate_to(control.key_epoch, key);
                self.members.insert(
                    control.target_peer_id.clone(),
                    Member { is_admin: false, joined_epoch: control.key_epoch },
                );
            }
            GroupAction::Remove => {
                self.require_admin(&actor_vec)?;
                self.members.remove(&control.target_peer_id);
                let key = new_key.ok_or(GroupError::MissingKey)?;
                self.rotate_to(control.key_epoch, key);
            }
            GroupAction::Leave => {
                // The actor removes themselves; any member may sign their own leave.
                self.members.remove(&actor_vec);
                let key = new_key.ok_or(GroupError::MissingKey)?;
                self.rotate_to(control.key_epoch, key);
            }
            GroupAction::GrantAdmin => {
                self.require_admin(&actor_vec)?;
                self.set_member_admin(&control.target_peer_id, true)?;
            }
            GroupAction::RevokeAdmin => {
                self.require_admin(&actor_vec)?;
                self.set_member_admin(&control.target_peer_id, false)?;
            }
            GroupAction::Rename => {
                self.require_admin(&actor_vec)?;
                self.display_name = String::from_utf8_lossy(&control.aux).into_owned();
            }
            GroupAction::JoinAck | GroupAction::KeyRotation => { /* informational here */ }
        }
        Ok(())
    }

    // --- group message crypto (keyed by the current epoch key) ---

    /// Encrypt a group message with the current epoch key. The output carries the epoch so a
    /// receiver can detect (and reject) messages from an epoch it no longer holds.
    pub fn encrypt(&self, plaintext: &[u8]) -> GroupCiphertext {
        let mut nonce = [0u8; 12];
        fill_random(&mut nonce);
        let ct = aead::seal(&self.group_key, &nonce, plaintext, GROUP_AAD).expect("aead seal");
        GroupCiphertext { epoch: self.key_epoch, nonce, ciphertext: ct }
    }

    /// Decrypt a group message. Fails with `EpochMismatch` if it was encrypted under a
    /// different key epoch than we currently hold — which is exactly what a removed member
    /// hits when others have rotated past them (EP2PC-006 §6.8).
    pub fn decrypt(&self, msg: &GroupCiphertext) -> Result<Vec<u8>, GroupError> {
        if msg.epoch != self.key_epoch {
            return Err(GroupError::EpochMismatch);
        }
        aead::open(&self.group_key, &msg.nonce, &msg.ciphertext, GROUP_AAD).map_err(|_| GroupError::Crypto)
    }

    // --- internals ---

    fn require_admin(&self, actor: &[u8]) -> Result<(), GroupError> {
        if self.is_admin(actor) {
            Ok(())
        } else {
            Err(GroupError::NotAdmin)
        }
    }

    fn set_admin(&mut self, admin: &Identity, target: &[u8], value: bool, action: GroupAction) -> Result<GroupChange, GroupError> {
        let actor = admin.peer_id_bytes().to_vec();
        self.require_admin(&actor)?;
        self.set_member_admin(target, value)?;
        Ok(self.change(admin, action, target, self.key_epoch, None, Vec::new()))
    }

    fn set_member_admin(&mut self, target: &[u8], value: bool) -> Result<(), GroupError> {
        match self.members.get_mut(target) {
            Some(m) => {
                m.is_admin = value;
                Ok(())
            }
            None => Err(GroupError::TargetNotMember),
        }
    }

    fn rotate_key(&mut self, new_epoch: u32) {
        let mut k = [0u8; 32];
        fill_random(&mut k);
        self.group_key = k;
        self.key_epoch = new_epoch;
    }

    fn rotate_to(&mut self, epoch: u32, key: [u8; 32]) {
        self.group_key = key;
        self.key_epoch = epoch;
    }

    fn other_members(&self, exclude: &[u8]) -> Vec<PeerKey> {
        self.members.keys().filter(|p| p.as_slice() != exclude).cloned().collect()
    }

    fn base_control(&self, action: GroupAction, target: &[u8], epoch: u32, actor: &[u8]) -> GroupControlPayload {
        GroupControlPayload {
            action: action as u32,
            target_peer_id: target.to_vec(),
            group_id: self.group_id.clone(),
            key_epoch: epoch,
            signature: Vec::new(),
            aux: Vec::new(),
            actor: actor.to_vec(),
        }
    }

    fn change(
        &self,
        signer: &Identity,
        action: GroupAction,
        target: &[u8],
        epoch: u32,
        new_key: Option<[u8; 32]>,
        recipients: Vec<PeerKey>,
    ) -> GroupChange {
        let actor = signer.peer_id_bytes().to_vec();
        let mut control = self.base_control(action, target, epoch, &actor);
        control.signature = signer.sign(&signing_input(&control)).to_vec();
        GroupChange { control, new_key, key_recipients: recipients }
    }
}

/// A group message on the wire: the epoch tag lets receivers reject stale-epoch ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupCiphertext {
    pub epoch: u32,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Canonical bytes signed for a control event (everything except the signature itself).
fn signing_input(c: &GroupControlPayload) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(SIG_LABEL);
    v.extend_from_slice(&c.action.to_be_bytes());
    push_field(&mut v, &c.group_id);
    push_field(&mut v, &c.target_peer_id);
    v.extend_from_slice(&c.key_epoch.to_be_bytes());
    push_field(&mut v, &c.actor);
    push_field(&mut v, &c.aux);
    v
}

fn push_field(v: &mut Vec<u8>, field: &[u8]) {
    v.extend_from_slice(&(field.len() as u32).to_be_bytes());
    v.extend_from_slice(field);
}

fn action_from(v: u32) -> Result<GroupAction, GroupError> {
    match v {
        0 => Ok(GroupAction::Invite),
        1 => Ok(GroupAction::JoinAck),
        2 => Ok(GroupAction::Leave),
        3 => Ok(GroupAction::Remove),
        4 => Ok(GroupAction::GrantAdmin),
        5 => Ok(GroupAction::RevokeAdmin),
        6 => Ok(GroupAction::Rename),
        7 => Ok(GroupAction::KeyRotation),
        _ => Err(GroupError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ep2pc_crypto::Identity;

    fn ident() -> (Identity, PeerKey) {
        let id = Identity::generate();
        let pk = id.peer_id_bytes().to_vec();
        (id, pk)
    }

    /// Apply a change to a member's state, delivering the new key (as the 1:1 layer would).
    fn deliver(state: &mut GroupState, change: &GroupChange) -> Result<(), GroupError> {
        state.apply(&change.control, change.new_key)
    }

    #[test]
    fn create_makes_creator_admin() {
        let (_, alice) = ident();
        let g = GroupState::create(vec![1; 16], alice.clone(), "team");
        assert!(g.is_admin(&alice));
        assert_eq!(g.member_count(), 1);
        assert_eq!(g.key_epoch(), 0);
    }

    #[test]
    fn add_member_rotates_and_grows() {
        let (alice_id, alice) = ident();
        let (_, bob) = ident();
        let mut g = GroupState::create(vec![1; 16], alice.clone(), "team");
        let ch = g.propose_add(&alice_id, bob.clone()).unwrap();
        assert_eq!(g.key_epoch(), 1);
        assert!(g.is_member(&bob));
        assert!(ch.new_key.is_some());
        let _ = alice;
    }

    #[test]
    fn non_admin_cannot_remove() {
        let (alice_id, alice) = ident();
        let (bob_id, bob) = ident();
        let mut g = GroupState::create(vec![1; 16], alice.clone(), "team");
        let _add = g.propose_add(&alice_id, bob.clone()).unwrap();
        // Bob (non-admin) tries to remove Alice -> rejected.
        let mut bob_state = g.clone();
        assert!(matches!(bob_state.propose_remove(&bob_id, &alice), Err(GroupError::NotAdmin)));
    }

    #[test]
    fn forged_signature_is_rejected() {
        let (alice_id, alice) = ident();
        let (_, bob) = ident();
        let mut g = GroupState::create(vec![1; 16], alice.clone(), "team");
        let mut ch = g.propose_add(&alice_id, bob).unwrap();
        // Tamper with the signed body after signing.
        ch.control.key_epoch = 99;
        let mut other = GroupState::create(vec![1; 16], alice, "team");
        assert!(matches!(other.apply(&ch.control, ch.new_key), Err(GroupError::BadSignature)));
    }

    #[test]
    fn removed_member_cannot_read_new_epoch() {
        let (alice_id, alice) = ident();
        let (_bob_id, bob) = ident();

        // Alice creates, adds Bob. Bob mirrors the state via the delivered control+key.
        let mut alice_g = GroupState::create(vec![7; 16], alice.clone(), "team");
        let add = alice_g.propose_add(&alice_id, bob.clone()).unwrap();
        let bob_g = GroupState::join(
            vec![7; 16],
            "team",
            add.control.key_epoch,
            add.new_key.unwrap(),
            alice_g.members().clone(),
        );
        assert_eq!(alice_g.key_epoch(), bob_g.key_epoch());

        // A message at the shared epoch is readable by Bob.
        let m1 = alice_g.encrypt(b"before removal");
        assert_eq!(bob_g.decrypt(&m1).unwrap(), b"before removal");

        // Alice removes Bob -> mandatory rotation. Bob is NOT a recipient of the new key.
        let rm = alice_g.propose_remove(&alice_id, &bob).unwrap();
        assert!(!rm.key_recipients.contains(&bob));
        assert_eq!(alice_g.key_epoch(), 2);

        // New-epoch message: Bob still holds the old epoch key -> can't read it.
        let m2 = alice_g.encrypt(b"after removal - secret");
        assert!(matches!(bob_g.decrypt(&m2), Err(GroupError::EpochMismatch)));
    }

    #[test]
    fn grant_admin_lets_new_admin_act() {
        let (alice_id, alice) = ident();
        let (bob_id, bob) = ident();
        let (_, carol) = ident();

        let mut g = GroupState::create(vec![1; 16], alice.clone(), "team");
        deliver_add(&mut g, &alice_id, &bob);
        // Bob can't remove yet.
        assert!(!g.is_admin(&bob));
        // Alice grants Bob admin.
        let grant = g.propose_grant(&alice_id, &bob).unwrap();
        assert!(g.is_admin(&bob));
        assert!(grant.new_key.is_none());
        // Now Bob (admin) can add Carol.
        assert!(g.propose_add(&bob_id, carol.clone()).is_ok());
        assert!(g.is_member(&carol));
        let _ = alice;
    }

    #[test]
    fn apply_roundtrip_between_two_members() {
        // Two members converge by applying the same signed controls.
        let (alice_id, alice) = ident();
        let (_, bob) = ident();
        let (_, carol) = ident();

        let mut alice_g = GroupState::create(vec![3; 16], alice.clone(), "team");
        let add_bob = alice_g.propose_add(&alice_id, bob.clone()).unwrap();
        let mut bob_g = GroupState::join(
            vec![3; 16],
            "team",
            add_bob.control.key_epoch,
            add_bob.new_key.unwrap(),
            alice_g.members().clone(),
        );

        // Alice adds Carol; Bob applies the same control+key and stays in sync.
        let add_carol = alice_g.propose_add(&alice_id, carol.clone()).unwrap();
        deliver(&mut bob_g, &add_carol).unwrap();
        assert_eq!(alice_g.key_epoch(), bob_g.key_epoch());
        assert!(bob_g.is_member(&carol));

        // A message Alice sends at the new epoch is readable by Bob.
        let m = alice_g.encrypt(b"hi everyone");
        assert_eq!(bob_g.decrypt(&m).unwrap(), b"hi everyone");
    }

    fn deliver_add(g: &mut GroupState, admin: &Identity, member: &[u8]) {
        let _ = g.propose_add(admin, member.to_vec()).unwrap();
    }
}
