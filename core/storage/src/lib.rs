//! Local encrypted storage (EP2PC-007).
//!
//! Opens a SQLCipher database with a key supplied by the caller (from Android Keystore,
//! EP2PC-007 §7.2/§7.4) and provides the schema plus a minimal API for messages, the
//! outbound retry queue, sessions and groups. Attachments are stored on the filesystem,
//! only referenced here (§7.6).

use rusqlite::{params, Connection};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, StorageError>;

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS contacts (
  peer_id       BLOB PRIMARY KEY,
  display_name  TEXT,
  public_key    BLOB NOT NULL,
  added_at      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS conversations (
  conversation_id BLOB PRIMARY KEY,
  is_group        INTEGER NOT NULL,
  group_id        BLOB,
  last_activity_at INTEGER
);
CREATE TABLE IF NOT EXISTS messages (
  message_id      BLOB PRIMARY KEY,
  conversation_id BLOB NOT NULL REFERENCES conversations(conversation_id),
  sender_peer_id  BLOB NOT NULL,
  type            INTEGER NOT NULL,
  body            TEXT,
  attachment_ref  BLOB,
  edited          INTEGER DEFAULT 0,
  deleted         INTEGER DEFAULT 0,
  sent_at         INTEGER NOT NULL,
  delivered_at    INTEGER,
  read_at         INTEGER
);
CREATE TABLE IF NOT EXISTS groups (
  group_id     BLOB PRIMARY KEY,
  display_name TEXT,
  key_epoch    INTEGER NOT NULL,
  created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members (
  group_id     BLOB NOT NULL REFERENCES groups(group_id),
  peer_id      BLOB NOT NULL,
  is_admin     INTEGER NOT NULL,
  joined_epoch INTEGER NOT NULL,
  PRIMARY KEY (group_id, peer_id)
);
CREATE TABLE IF NOT EXISTS sessions (
  peer_id       BLOB PRIMARY KEY,
  ratchet_state BLOB NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS outbound_queue (
  message_id      BLOB PRIMARY KEY,
  conversation_id BLOB NOT NULL,
  payload         BLOB NOT NULL,
  retry_count     INTEGER DEFAULT 0,
  next_retry_at   INTEGER,
  created_at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_conversation_ts ON messages(conversation_id, sent_at);
CREATE INDEX IF NOT EXISTS idx_outbound_next_retry ON outbound_queue(next_retry_at);
CREATE TABLE IF NOT EXISTS local_secrets (
  name   TEXT PRIMARY KEY,
  secret BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS group_keys (
  group_id BLOB NOT NULL,
  epoch    INTEGER NOT NULL,
  key      BLOB NOT NULL,
  PRIMARY KEY (group_id, epoch)
);
"#;

pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (or create) the encrypted database. `key` is the 32-byte SQLCipher key.
    pub fn open(path: &str, key: &[u8]) -> Result<Self> {
        let conn = Connection::open(path)?;
        // Apply the SQLCipher key as a raw hex key (no KDF salt round-trip surprises).
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        conn.pragma_update(None, "key", format!("x'{hex}'"))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn insert_message(
        &self,
        message_id: &[u8],
        conversation_id: &[u8],
        sender: &[u8],
        msg_type: u32,
        body: Option<&str>,
        sent_at: i64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO messages
             (message_id, conversation_id, sender_peer_id, type, body, sent_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![message_id, conversation_id, sender, msg_type, body, sent_at],
        )?;
        Ok(())
    }

    pub fn enqueue_outbound(
        &self,
        message_id: &[u8],
        conversation_id: &[u8],
        payload: &[u8],
        created_at: i64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO outbound_queue
             (message_id, conversation_id, payload, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![message_id, conversation_id, payload, created_at],
        )?;
        Ok(())
    }

    pub fn dequeue_outbound(&self, message_id: &[u8]) -> Result<()> {
        self.conn
            .execute("DELETE FROM outbound_queue WHERE message_id = ?1", params![message_id])?;
        Ok(())
    }

    /// All queued outbound (message_id, payload) for a conversation — used to hand messages
    /// to store-and-forward when a direct send fails (EP2PC-003 §3.7).
    pub fn outbound_for_conversation(&self, conversation_id: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT message_id, payload FROM outbound_queue WHERE conversation_id = ?1",
        )?;
        let rows = stmt.query_map(params![conversation_id], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn save_session(&self, peer_id: &[u8], ratchet_state: &[u8], updated_at: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions (peer_id, ratchet_state, updated_at)
             VALUES (?1, ?2, ?3)",
            params![peer_id, ratchet_state, updated_at],
        )?;
        Ok(())
    }

    pub fn load_session(&self, peer_id: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT ratchet_state FROM sessions WHERE peer_id = ?1")?;
        let mut rows = stmt.query(params![peer_id])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }

    /// Insert/update a contact's public identity (64 bytes: ed25519 || x25519), obtained via
    /// the QR exchange (EP2PC-003 §3.3).
    pub fn upsert_contact(
        &self,
        peer_id: &[u8],
        identity_public: &[u8],
        display_name: Option<&str>,
        added_at: i64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO contacts (peer_id, display_name, public_key, added_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![peer_id, display_name, identity_public, added_at],
        )?;
        Ok(())
    }

    /// Raw 64-byte public identity of a contact, if known.
    pub fn contact_identity_bytes(&self, peer_id: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT public_key FROM contacts WHERE peer_id = ?1")?;
        let mut rows = stmt.query(params![peer_id])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }

    /// Persist a named local secret (e.g. the signed-prekey secret). The DB itself is
    /// SQLCipher-encrypted, so this is encrypted at rest (EP2PC-007 §7.4).
    pub fn save_local_secret(&self, name: &str, secret: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO local_secrets (name, secret) VALUES (?1, ?2)",
            params![name, secret],
        )?;
        Ok(())
    }

    pub fn load_local_secret(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT secret FROM local_secrets WHERE name = ?1")?;
        let mut rows = stmt.query(params![name])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }

    // --- group persistence (EP2PC-006, EP2PC-007) ---

    pub fn upsert_group(&self, group_id: &[u8], display_name: &str, key_epoch: i64, created_at: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO groups (group_id, display_name, key_epoch, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![group_id, display_name, key_epoch, created_at],
        )?;
        Ok(())
    }

    pub fn set_group_member(&self, group_id: &[u8], peer_id: &[u8], is_admin: bool, joined_epoch: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO group_members (group_id, peer_id, is_admin, joined_epoch)
             VALUES (?1, ?2, ?3, ?4)",
            params![group_id, peer_id, is_admin as i64, joined_epoch],
        )?;
        Ok(())
    }

    pub fn remove_group_member(&self, group_id: &[u8], peer_id: &[u8]) -> Result<()> {
        self.conn.execute(
            "DELETE FROM group_members WHERE group_id = ?1 AND peer_id = ?2",
            params![group_id, peer_id],
        )?;
        Ok(())
    }

    /// Persist a group key for an epoch. Old-epoch keys are kept briefly so not-yet-read
    /// prior messages remain decryptable, then pruned (EP2PC-004 §4.9, EP2PC-006 §6.8).
    pub fn save_group_key(&self, group_id: &[u8], epoch: i64, key: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO group_keys (group_id, epoch, key) VALUES (?1, ?2, ?3)",
            params![group_id, epoch, key],
        )?;
        Ok(())
    }

    pub fn load_group_key(&self, group_id: &[u8], epoch: i64) -> Result<Option<Vec<u8>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key FROM group_keys WHERE group_id = ?1 AND epoch = ?2")?;
        let mut rows = stmt.query(params![group_id, epoch])?;
        Ok(match rows.next()? {
            Some(row) => Some(row.get(0)?),
            None => None,
        })
    }

    /// Drop group keys older than `keep_from_epoch` (forward secrecy pruning).
    pub fn prune_group_keys(&self, group_id: &[u8], keep_from_epoch: i64) -> Result<usize> {
        let n = self.conn.execute(
            "DELETE FROM group_keys WHERE group_id = ?1 AND epoch < ?2",
            params![group_id, keep_from_epoch],
        )?;
        Ok(n)
    }
}

/// Bridge to the message engine's persistence boundary (EP2PC-007 §7.4). The engine calls
/// these to load/save the serialized Double Ratchet state per peer.
impl ep2pc_engine::SessionStore for Store {
    fn load_session(&self, peer: &[u8]) -> Option<Vec<u8>> {
        // Fully-qualified call to the inherent method (avoids trait/inherent name clash).
        Store::load_session(self, peer).ok().flatten()
    }

    fn save_session(&mut self, peer: &[u8], state: &[u8]) {
        let now = now_millis();
        if let Err(e) = Store::save_session(self, peer, state, now) {
            eprintln!("session persist failed: {e}");
        }
    }
}

/// Bridge to the engine's contact lookup: parse the stored 64-byte identity into the
/// crypto type used to complete an incoming handshake (EP2PC-004 §4.4).
impl ep2pc_engine::ContactResolver for Store {
    fn identity_of(&self, peer: &[u8]) -> Option<ep2pc_crypto::IdentityPublic> {
        let bytes = Store::contact_identity_bytes(self, peer).ok().flatten()?;
        ep2pc_crypto::IdentityPublic::from_bytes(&bytes).ok()
    }
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
