//! Chunked media transfer (EP2PC-005 §5.9–5.10).
//!
//! Large content (file, image, video, Opus voice note) is never sent in one blob. Instead:
//!
//!   1. A random 32-byte **transfer key** is generated and the content is split into 64 KB
//!      chunks. Each chunk is AEAD-encrypted **independently** with a fresh nonce, so a
//!      corrupted or tampered chunk is rejected on its own without restarting the whole
//!      transfer (§5.9). The AEAD associated data binds `transfer_id || index`, so a chunk
//!      can't be replayed at a different position or spliced into another transfer.
//!   2. A [`Manifest`] describes the transfer (size, chunk count, content hash, mime,
//!      filename) and carries the transfer key. The manifest is sent inside a normal E2EE
//!      `Envelope` (ATTACHMENT/VOICE type), so the transfer key is protected by the Double
//!      Ratchet — the chunks themselves can then travel over any stream.
//!   3. The receiver adds chunks in any order, tracks which are missing (for selective
//!      retry, §5.11), and on completion verifies the whole-content SHA-256 before handing
//!      the bytes up.
//!
//! Opus (voice) uses the exact same mechanism with a `VOICE` marker; the audio codec lives
//! in the app layer, the transport is identical.
//!
//! This crate is pure (crypto only), so the chunking, integrity, and ordering logic is
//! fully unit-tested.

use std::collections::HashMap;

use ep2pc_crypto::{aead, fill_random, sha256};

/// Chunk size on the wire (EP2PC-005 §5.9).
pub const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaError {
    /// A chunk failed AEAD verification (corrupt/tampered/wrong position).
    ChunkAuth,
    /// A chunk index was outside the manifest's range.
    BadIndex,
    /// finish() called before all chunks arrived.
    Incomplete,
    /// Reassembled content didn't match the manifest's SHA-256.
    HashMismatch,
    /// Malformed manifest/chunk bytes.
    Malformed,
}

impl std::fmt::Display for MediaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for MediaError {}

/// Transfer metadata, sent inside an E2EE envelope (so `key` is ratchet-protected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub transfer_id: [u8; 16],
    pub key: [u8; 32],
    pub total_size: u64,
    pub chunk_count: u32,
    pub content_hash: [u8; 32],
    pub mime: String,
    pub filename: String,
}

/// One encrypted chunk on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkWire {
    pub transfer_id: [u8; 16],
    pub index: u32,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

fn chunk_aad(transfer_id: &[u8; 16], index: u32) -> [u8; 20] {
    let mut aad = [0u8; 20];
    aad[..16].copy_from_slice(transfer_id);
    aad[16..].copy_from_slice(&index.to_be_bytes());
    aad
}

/// Split `data` into an encrypted transfer: returns the manifest (with the fresh transfer
/// key) and the encrypted chunks.
pub fn split(data: &[u8], mime: impl Into<String>, filename: impl Into<String>) -> (Manifest, Vec<ChunkWire>) {
    let mut transfer_id = [0u8; 16];
    fill_random(&mut transfer_id);
    let mut key = [0u8; 32];
    fill_random(&mut key);

    let mut chunks = Vec::new();
    // A zero-length payload still produces zero chunks; chunk_count reflects reality.
    for (i, part) in data.chunks(CHUNK_SIZE).enumerate() {
        let index = i as u32;
        let mut nonce = [0u8; 12];
        fill_random(&mut nonce);
        let ciphertext = aead::seal(&key, &nonce, part, &chunk_aad(&transfer_id, index))
            .expect("aead seal");
        chunks.push(ChunkWire { transfer_id, index, nonce, ciphertext });
    }

    let manifest = Manifest {
        transfer_id,
        key,
        total_size: data.len() as u64,
        chunk_count: chunks.len() as u32,
        content_hash: sha256(data),
        mime: mime.into(),
        filename: filename.into(),
    };
    (manifest, chunks)
}

/// Receiver-side reassembly. Decrypts and verifies each chunk as it arrives, tolerates
/// out-of-order and duplicate delivery, and reports what's still missing for retry.
pub struct Reassembler {
    manifest: Manifest,
    chunks: HashMap<u32, Vec<u8>>,
}

impl Reassembler {
    pub fn new(manifest: Manifest) -> Self {
        Self { manifest, chunks: HashMap::new() }
    }

    /// Decrypt, verify and store a chunk. Wrong-transfer chunks are ignored; a tampered or
    /// misindexed chunk returns `ChunkAuth`.
    pub fn add_chunk(&mut self, chunk: &ChunkWire) -> Result<(), MediaError> {
        if chunk.transfer_id != self.manifest.transfer_id {
            return Ok(()); // not ours; ignore
        }
        if chunk.index >= self.manifest.chunk_count {
            return Err(MediaError::BadIndex);
        }
        let plaintext = aead::open(
            &self.manifest.key,
            &chunk.nonce,
            &chunk.ciphertext,
            &chunk_aad(&chunk.transfer_id, chunk.index),
        )
        .map_err(|_| MediaError::ChunkAuth)?;
        self.chunks.insert(chunk.index, plaintext);
        Ok(())
    }

    /// Indices not yet received (for selective retry, EP2PC-005 §5.11).
    pub fn missing(&self) -> Vec<u32> {
        (0..self.manifest.chunk_count).filter(|i| !self.chunks.contains_key(i)).collect()
    }

    pub fn is_complete(&self) -> bool {
        self.chunks.len() as u32 == self.manifest.chunk_count
    }

    pub fn progress(&self) -> (u32, u32) {
        (self.chunks.len() as u32, self.manifest.chunk_count)
    }

    /// Concatenate the chunks in order and verify the whole-content hash (§5.9).
    pub fn finish(self) -> Result<Vec<u8>, MediaError> {
        if !self.is_complete() {
            return Err(MediaError::Incomplete);
        }
        let mut out = Vec::with_capacity(self.manifest.total_size as usize);
        for i in 0..self.manifest.chunk_count {
            out.extend_from_slice(self.chunks.get(&i).ok_or(MediaError::Incomplete)?);
        }
        if sha256(&out) != self.manifest.content_hash {
            return Err(MediaError::HashMismatch);
        }
        Ok(out)
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
}

// --- wire serialization (manual, to stay dependency-light) ---

impl Manifest {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.transfer_id);
        v.extend_from_slice(&self.key);
        v.extend_from_slice(&self.total_size.to_be_bytes());
        v.extend_from_slice(&self.chunk_count.to_be_bytes());
        v.extend_from_slice(&self.content_hash);
        put_str(&mut v, &self.mime);
        put_str(&mut v, &self.filename);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, MediaError> {
        let mut c = Cursor { b, pos: 0 };
        let transfer_id: [u8; 16] = c.take(16).ok_or(MediaError::Malformed)?.try_into().unwrap();
        let key: [u8; 32] = c.take(32).ok_or(MediaError::Malformed)?.try_into().unwrap();
        let total_size = u64::from_be_bytes(c.take(8).ok_or(MediaError::Malformed)?.try_into().unwrap());
        let chunk_count = u32::from_be_bytes(c.take(4).ok_or(MediaError::Malformed)?.try_into().unwrap());
        let content_hash: [u8; 32] = c.take(32).ok_or(MediaError::Malformed)?.try_into().unwrap();
        let mime = c.string().ok_or(MediaError::Malformed)?;
        let filename = c.string().ok_or(MediaError::Malformed)?;
        Ok(Manifest { transfer_id, key, total_size, chunk_count, content_hash, mime, filename })
    }
}

impl ChunkWire {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16 + 4 + 12 + self.ciphertext.len());
        v.extend_from_slice(&self.transfer_id);
        v.extend_from_slice(&self.index.to_be_bytes());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.ciphertext);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, MediaError> {
        if b.len() < 32 {
            return Err(MediaError::Malformed);
        }
        let transfer_id: [u8; 16] = b[0..16].try_into().unwrap();
        let index = u32::from_be_bytes(b[16..20].try_into().unwrap());
        let nonce: [u8; 12] = b[20..32].try_into().unwrap();
        let ciphertext = b[32..].to_vec();
        Ok(ChunkWire { transfer_id, index, nonce, ciphertext })
    }
}

fn put_str(v: &mut Vec<u8>, s: &str) {
    v.extend_from_slice(&(s.len() as u32).to_be_bytes());
    v.extend_from_slice(s.as_bytes());
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
    fn string(&mut self) -> Option<String> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize;
        Some(String::from_utf8_lossy(self.take(len)?).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reassemble(manifest: Manifest, chunks: Vec<ChunkWire>) -> Result<Vec<u8>, MediaError> {
        let mut r = Reassembler::new(manifest);
        for c in &chunks {
            r.add_chunk(c)?;
        }
        r.finish()
    }

    #[test]
    fn roundtrip_multi_chunk() {
        let data: Vec<u8> = (0..(CHUNK_SIZE * 2 + 123)).map(|i| (i % 251) as u8).collect();
        let (m, chunks) = split(&data, "application/octet-stream", "blob.bin");
        assert_eq!(m.chunk_count, 3);
        assert_eq!(reassemble(m, chunks).unwrap(), data);
    }

    #[test]
    fn boundary_sizes() {
        for size in [0usize, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1] {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let (m, chunks) = split(&data, "x", "f");
            let expect_chunks = if size == 0 { 0 } else { (size + CHUNK_SIZE - 1) / CHUNK_SIZE };
            assert_eq!(m.chunk_count as usize, expect_chunks, "size {size}");
            assert_eq!(reassemble(m, chunks).unwrap(), data, "size {size}");
        }
    }

    #[test]
    fn out_of_order_and_duplicate() {
        let data: Vec<u8> = (0..(CHUNK_SIZE * 3)).map(|i| (i % 97) as u8).collect();
        let (m, mut chunks) = split(&data, "x", "f");
        chunks.reverse();
        let mut r = Reassembler::new(m);
        for c in &chunks {
            r.add_chunk(c).unwrap();
            r.add_chunk(c).unwrap(); // duplicate is harmless
        }
        assert!(r.is_complete());
        assert_eq!(r.finish().unwrap(), data);
    }

    #[test]
    fn missing_chunks_reported() {
        let data: Vec<u8> = (0..(CHUNK_SIZE * 3)).map(|i| i as u8).collect();
        let (m, chunks) = split(&data, "x", "f");
        let mut r = Reassembler::new(m);
        r.add_chunk(&chunks[0]).unwrap();
        r.add_chunk(&chunks[2]).unwrap();
        assert_eq!(r.missing(), vec![1]);
        assert!(!r.is_complete());
        assert_eq!(r.progress(), (2, 3));
        assert!(matches!(Reassembler::new(split(&data, "x", "f").0).finish(), Err(MediaError::Incomplete)));
    }

    #[test]
    fn tampered_chunk_rejected() {
        let data: Vec<u8> = (0..(CHUNK_SIZE + 10)).map(|i| i as u8).collect();
        let (m, mut chunks) = split(&data, "x", "f");
        chunks[0].ciphertext[5] ^= 0x01;
        let mut r = Reassembler::new(m);
        assert!(matches!(r.add_chunk(&chunks[0]), Err(MediaError::ChunkAuth)));
    }

    #[test]
    fn chunk_cannot_be_moved_to_other_index() {
        // AAD binds the index: relabelling chunk 0 as chunk 1 must fail auth.
        let data: Vec<u8> = (0..(CHUNK_SIZE * 2)).map(|i| i as u8).collect();
        let (m, chunks) = split(&data, "x", "f");
        let mut moved = chunks[0].clone();
        moved.index = 1;
        let mut r = Reassembler::new(m);
        assert!(matches!(r.add_chunk(&moved), Err(MediaError::ChunkAuth)));
    }

    #[test]
    fn manifest_and_chunk_wire_roundtrip() {
        let data: Vec<u8> = (0..(CHUNK_SIZE + 7)).map(|i| i as u8).collect();
        let (m, chunks) = split(&data, "image/png", "pic.png");
        let m2 = Manifest::from_bytes(&m.to_bytes()).unwrap();
        assert_eq!(m2, m);
        let c2 = ChunkWire::from_bytes(&chunks[0].to_bytes()).unwrap();
        assert_eq!(c2, chunks[0]);
        // full path through serialization
        let rebuilt: Vec<ChunkWire> = chunks.iter().map(|c| ChunkWire::from_bytes(&c.to_bytes()).unwrap()).collect();
        assert_eq!(reassemble(m2, rebuilt).unwrap(), data);
    }
}
