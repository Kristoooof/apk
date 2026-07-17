//! Double Ratchet (EP2PC-004 §4.5), following the Signal specification.
//!
//! Guarantees: every message uses a unique one-time key (forward secrecy), and a DH
//! ratchet step on each round-trip re-injects entropy into the root key
//! (post-compromise security). Out-of-order / skipped messages are handled with a
//! bounded skipped-key store.

use std::collections::HashMap;

use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};
use zeroize::Zeroize;

use crate::aead;
use crate::error::{CryptoError, Result};
use crate::kdf::{kdf_ck, kdf_rk, MessageKey, SymKey};

const MAX_SKIP: u32 = 1000;

/// Per-message ratchet header. Travels (authenticated) with the ciphertext and maps to
/// the `ratchet_header` field of `EncryptedMessage` (EP2PC-004 §4.8).
#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub dh: [u8; 32],
    pub pn: u32,
    pub n: u32,
}

impl Header {
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.dh);
        out[32..36].copy_from_slice(&self.pn.to_be_bytes());
        out[36..40].copy_from_slice(&self.n.to_be_bytes());
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 40 {
            return Err(CryptoError::Malformed("header length"));
        }
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&b[..32]);
        let pn = u32::from_be_bytes(b[32..36].try_into().unwrap());
        let n = u32::from_be_bytes(b[36..40].try_into().unwrap());
        Ok(Header { dh, pn, n })
    }
}

fn gen_dh() -> (XSecret, [u8; 32]) {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let secret = XSecret::from(seed);
    seed.zeroize();
    let public = XPublic::from(&secret).to_bytes();
    (secret, public)
}

fn dh(secret: &XSecret, peer_pub: &[u8; 32]) -> [u8; 32] {
    secret.diffie_hellman(&XPublic::from(*peer_pub)).to_bytes()
}

/// Full Double Ratchet session state (serialized into `sessions.ratchet_state`,
/// EP2PC-007 §7.4).
pub struct Ratchet {
    dhs_secret: XSecret,
    dhs_public: [u8; 32],
    dhr: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: HashMap<([u8; 32], u32), MessageKey>,
}

impl Ratchet {
    /// Initiator side. `sk` comes from X3DH; `their_prekey_pub` is the responder's signed
    /// prekey public, reused as the first DH ratchet key.
    pub fn init_initiator(sk: SymKey, their_prekey_pub: [u8; 32]) -> Self {
        let (dhs_secret, dhs_public) = gen_dh();
        let dh_out = dh(&dhs_secret, &their_prekey_pub);
        let (rk, cks) = kdf_rk(sk.as_bytes(), &dh_out);
        Ratchet {
            dhs_secret,
            dhs_public,
            dhr: Some(their_prekey_pub),
            rk: *rk.as_bytes(),
            cks: Some(*cks.as_bytes()),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    /// Responder side. `spk_secret` is the responder's signed-prekey secret.
    pub fn init_responder(sk: SymKey, spk_secret: XSecret) -> Self {
        let dhs_public = XPublic::from(&spk_secret).to_bytes();
        Ratchet {
            dhs_secret: spk_secret,
            dhs_public,
            dhr: None,
            rk: *sk.as_bytes(),
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8], external_ad: &[u8]) -> Result<(Header, Vec<u8>)> {
        let cks = self.cks.ok_or(CryptoError::Malformed("no sending chain"))?;
        let (next_ck, mk) = kdf_ck(&cks);
        self.cks = Some(*next_ck.as_bytes());
        let header = Header {
            dh: self.dhs_public,
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;
        let aad = Self::aad(external_ad, &header);
        let ct = aead::seal(&mk.key, &mk.nonce, plaintext, &aad)?;
        Ok((header, ct))
    }

    pub fn decrypt(
        &mut self,
        header: &Header,
        ciphertext: &[u8],
        external_ad: &[u8],
    ) -> Result<Vec<u8>> {
        // 1. Was this a message we already computed a skipped key for?
        if let Some(mk) = self.skipped.remove(&(header.dh, header.n)) {
            let aad = Self::aad(external_ad, header);
            return aead::open(&mk.key, &mk.nonce, ciphertext, &aad);
        }

        // 2. New DH ratchet key from the peer? Finish old chain, step the ratchet.
        if self.dhr != Some(header.dh) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header);
        }

        // 3. Skip forward within the current receiving chain if needed.
        self.skip_message_keys(header.n)?;

        let ckr = self.ckr.ok_or(CryptoError::Malformed("no receiving chain"))?;
        let (next_ck, mk) = kdf_ck(&ckr);
        self.ckr = Some(*next_ck.as_bytes());
        self.nr += 1;

        let aad = Self::aad(external_ad, header);
        aead::open(&mk.key, &mk.nonce, ciphertext, &aad)
    }

    fn aad(external_ad: &[u8], header: &Header) -> Vec<u8> {
        let hb = header.to_bytes();
        let mut aad = Vec::with_capacity(external_ad.len() + hb.len());
        aad.extend_from_slice(external_ad);
        aad.extend_from_slice(&hb);
        aad
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        if self.ckr.is_none() {
            return Ok(());
        }
        if self.nr + MAX_SKIP < until {
            return Err(CryptoError::TooManySkipped);
        }
        let dhr = self.dhr.expect("dhr present when ckr present");
        let mut ck = self.ckr.unwrap();
        while self.nr < until {
            let (next, mk) = kdf_ck(&ck);
            self.skipped.insert((dhr, self.nr), mk);
            ck = *next.as_bytes();
            self.nr += 1;
        }
        self.ckr = Some(ck);
        Ok(())
    }

    fn dh_ratchet(&mut self, header: &Header) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.dh);

        let dh_out = dh(&self.dhs_secret, &header.dh);
        let (rk1, ckr) = kdf_rk(&self.rk, &dh_out);
        self.rk = *rk1.as_bytes();
        self.ckr = Some(*ckr.as_bytes());

        let (new_secret, new_pub) = gen_dh();
        self.dhs_secret = new_secret;
        self.dhs_public = new_pub;

        let dh_out2 = dh(&self.dhs_secret, &header.dh);
        let (rk2, cks) = kdf_rk(&self.rk, &dh_out2);
        self.rk = *rk2.as_bytes();
        self.cks = Some(*cks.as_bytes());
    }

    /// Serialize the full ratchet state for persistence in `sessions.ratchet_state`
    /// (EP2PC-007 §7.4). The output is secret key material and must only ever live in the
    /// SQLCipher-encrypted store — never on the wire, never in the Kotlin/UI layer.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.dhs_secret.to_bytes());
        out.extend_from_slice(&self.dhs_public);
        push_opt32(&mut out, &self.dhr);
        out.extend_from_slice(&self.rk);
        push_opt32(&mut out, &self.cks);
        push_opt32(&mut out, &self.ckr);
        out.extend_from_slice(&self.ns.to_be_bytes());
        out.extend_from_slice(&self.nr.to_be_bytes());
        out.extend_from_slice(&self.pn.to_be_bytes());
        out.extend_from_slice(&(self.skipped.len() as u32).to_be_bytes());
        for ((dhr, n), mk) in &self.skipped {
            out.extend_from_slice(dhr);
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(&mk.key);
            out.extend_from_slice(&mk.nonce);
        }
        out
    }

    /// Restore a ratchet previously produced by [`Ratchet::serialize`].
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        let mut c = Cursor { b: bytes, pos: 0 };
        let dhs_secret = XSecret::from(c.take32()?);
        let dhs_public = c.take32()?;
        let dhr = c.take_opt32()?;
        let rk = c.take32()?;
        let cks = c.take_opt32()?;
        let ckr = c.take_opt32()?;
        let ns = c.take_u32()?;
        let nr = c.take_u32()?;
        let pn = c.take_u32()?;
        let count = c.take_u32()?;
        let mut skipped = HashMap::new();
        for _ in 0..count {
            let dhr_key = c.take32()?;
            let n = c.take_u32()?;
            let key = c.take32()?;
            let nonce = c.take12()?;
            skipped.insert((dhr_key, n), MessageKey { key, nonce });
        }
        Ok(Ratchet {
            dhs_secret,
            dhs_public,
            dhr,
            rk,
            cks,
            ckr,
            ns,
            nr,
            pn,
            skipped,
        })
    }
}

fn push_opt32(out: &mut Vec<u8>, v: &Option<[u8; 32]>) {
    match v {
        Some(b) => {
            out.push(1);
            out.extend_from_slice(b);
        }
        None => out.push(0),
    }
}

/// Minimal big-endian byte cursor for deserialization.
struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        if self.pos + n > self.b.len() {
            return Err(CryptoError::Malformed("ratchet state truncated"));
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn take32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn take12(&mut self) -> Result<[u8; 12]> {
        Ok(self.take(12)?.try_into().unwrap())
    }
    fn take_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn take_opt32(&mut self) -> Result<Option<[u8; 32]>> {
        let flag = self.take(1)?[0];
        if flag == 0 {
            Ok(None)
        } else {
            Ok(Some(self.take32()?))
        }
    }
}
