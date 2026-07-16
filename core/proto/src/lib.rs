//! EP2PC wire types (EP2PC-005, EP2PC-006).
//!
//! These structs mirror `proto/ep2pc.proto` and use `prost` derive macros so the crate
//! builds without a `protoc` toolchain. Encoding/decoding is byte-compatible with code
//! generated from the `.proto` for other languages.

/// EP2PC-005 §5.3 message type codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MessageType {
    Unknown = 0,
    Text = 1,
    Edit = 2,
    Delete = 3,
    Attachment = 4,
    Voice = 5,
    ReadReceipt = 6,
    DeliveryAck = 7,
    GroupControl = 8,
    Typing = 9,
}

impl From<MessageType> for u32 {
    fn from(t: MessageType) -> u32 {
        t as u32
    }
}

impl From<u32> for MessageType {
    fn from(v: u32) -> Self {
        match v {
            1 => Self::Text,
            2 => Self::Edit,
            3 => Self::Delete,
            4 => Self::Attachment,
            5 => Self::Voice,
            6 => Self::ReadReceipt,
            7 => Self::DeliveryAck,
            8 => Self::GroupControl,
            9 => Self::Typing,
            _ => Self::Unknown,
        }
    }
}

/// EP2PC-004 §4.8 encrypted envelope carried on the wire.
#[derive(Clone, PartialEq, prost::Message)]
pub struct EncryptedMessage {
    #[prost(bytes = "vec", tag = "1")]
    pub message_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub sender_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub conversation_id: Vec<u8>,
    #[prost(int64, tag = "4")]
    pub timestamp: i64,
    #[prost(bytes = "vec", tag = "5")]
    pub ratchet_header: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub ciphertext: Vec<u8>,
    #[prost(uint32, tag = "7")]
    pub cipher_suite: u32,
    /// Present only on the first message(s) of a session: the initiator's X3DH ephemeral
    /// public key, letting the responder complete the handshake (EP2PC-004 §4.4). Empty
    /// once the session is established.
    #[prost(bytes = "vec", tag = "8")]
    pub x3dh_ephemeral: Vec<u8>,
}

/// Decrypted envelope (EP2PC-005 §5.4).
#[derive(Clone, PartialEq, prost::Message)]
pub struct Envelope {
    #[prost(bytes = "vec", tag = "1")]
    pub message_id: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub r#type: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub conversation_id: Vec<u8>,
    #[prost(int64, tag = "4")]
    pub timestamp: i64,
    #[prost(bytes = "vec", tag = "5")]
    pub payload: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub reply_to: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct TextPayload {
    #[prost(string, tag = "1")]
    pub body: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct EditPayload {
    #[prost(bytes = "vec", tag = "1")]
    pub target_message_id: Vec<u8>,
    #[prost(string, tag = "2")]
    pub new_body: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct DeletePayload {
    #[prost(bytes = "vec", tag = "1")]
    pub target_message_id: Vec<u8>,
    #[prost(bool, tag = "2")]
    pub delete_for_everyone: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct AttachmentPayload {
    #[prost(string, tag = "1")]
    pub filename: String,
    #[prost(string, tag = "2")]
    pub mime_type: String,
    #[prost(uint64, tag = "3")]
    pub total_size: u64,
    #[prost(uint32, tag = "4")]
    pub chunk_count: u32,
    #[prost(bytes = "vec", tag = "5")]
    pub sha256: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ChunkPayload {
    #[prost(bytes = "vec", tag = "1")]
    pub attachment_id: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub index: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GroupControlPayload {
    #[prost(uint32, tag = "1")]
    pub action: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub target_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub group_id: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub key_epoch: u32,
    #[prost(bytes = "vec", tag = "5")]
    pub signature: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub aux: Vec<u8>,
    /// The Ed25519 peer id of the admin/member who signed this control (EP2PC-006 §6.3).
    #[prost(bytes = "vec", tag = "7")]
    pub actor: Vec<u8>,
}

/// Group control actions (EP2PC-006 §6.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum GroupAction {
    Invite = 0,
    JoinAck = 1,
    Leave = 2,
    Remove = 3,
    GrantAdmin = 4,
    RevokeAdmin = 5,
    Rename = 6,
    KeyRotation = 7,
}

// --- helpers ---

pub fn encode<M: prost::Message>(m: &M) -> Vec<u8> {
    m.encode_to_vec()
}

pub fn decode<M: prost::Message + Default>(buf: &[u8]) -> Result<M, prost::DecodeError> {
    M::decode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn envelope_roundtrip() {
        let text = TextPayload {
            body: "szia EP2PC 👋".into(),
        };
        let env = Envelope {
            message_id: vec![1, 2, 3, 4],
            r#type: MessageType::Text.into(),
            conversation_id: vec![9, 9, 9],
            timestamp: 1_700_000_000,
            payload: text.encode_to_vec(),
            reply_to: vec![],
        };
        let bytes = env.encode_to_vec();
        let back: Envelope = Envelope::decode(&bytes[..]).unwrap();
        assert_eq!(back, env);
        let inner: TextPayload = TextPayload::decode(&back.payload[..]).unwrap();
        assert_eq!(inner.body, "szia EP2PC 👋");
        assert_eq!(MessageType::from(back.r#type), MessageType::Text);
    }

    #[test]
    fn encrypted_message_roundtrip() {
        let em = EncryptedMessage {
            message_id: vec![0xAA; 16],
            sender_id: vec![0xBB; 32],
            conversation_id: vec![0xCC; 16],
            timestamp: 42,
            ratchet_header: vec![0u8; 40],
            ciphertext: vec![1, 2, 3, 4, 5],
            cipher_suite: 0,
            x3dh_ephemeral: vec![0x11; 32],
        };
        let bytes = em.encode_to_vec();
        assert_eq!(EncryptedMessage::decode(&bytes[..]).unwrap(), em);
    }

    #[test]
    fn group_control_roundtrip() {
        let gc = GroupControlPayload {
            action: GroupAction::Remove as u32,
            target_peer_id: vec![7; 32],
            group_id: vec![3; 16],
            key_epoch: 5,
            signature: vec![9; 64],
            aux: vec![],
            actor: vec![4; 32],
        };
        let bytes = gc.encode_to_vec();
        assert_eq!(GroupControlPayload::decode(&bytes[..]).unwrap(), gc);
    }
}
