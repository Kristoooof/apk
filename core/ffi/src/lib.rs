//! JNI bridge (EP2PC-008 §8.4).
//!
//! Threading model:
//!   * The Rust core runs a dedicated multi-thread Tokio runtime on its own native
//!     threads — never the Android main thread.
//!   * Kotlin → Rust calls are non-blocking: they push a `Command` onto an async channel.
//!   * Rust → Kotlin events are delivered by calling back into a Java object held as a
//!     `GlobalRef`, from a dedicated dispatch thread that attaches to the JVM.
//!   * ONLY serialized (protobuf) byte arrays cross the boundary — never raw key
//!     material (EP2PC-004 §4.10).

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use jni::objects::{JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jlong};
use jni::{JNIEnv, JavaVM};
use tokio::sync::mpsc;

use ep2pc_engine::{Engine, EngineError};
use ep2pc_groupmgr::{GroupManager, GroupOutput, Incoming1to1};
use ep2pc_net::reexport::PeerId;
use ep2pc_net::{build_swarm, keypair_from_ed25519_secret, Command, NetConfig};
use ep2pc_storage::Store;

/// Name of the persisted signed-prekey secret in the local_secrets table.
const PREKEY_NAME: &str = "signed_prekey_v1";

/// Our own libp2p PeerId, needed as the `sender`/`recipient` in store-and-forward records.
static MY_PEER: OnceLock<PeerId> = OnceLock::new();

/// Global handle to the running core (single instance per process).
struct Core {
    cmd_tx: mpsc::Sender<Command>,
    _runtime: tokio::runtime::Runtime,
}

static CORE: OnceLock<Core> = OnceLock::new();
static JVM: OnceLock<JavaVM> = OnceLock::new();

/// The group manager (wraps the message engine: Double Ratchet + wire + persistent sessions
/// + group state). Shared between the JNI send/group paths and event dispatch, behind a
/// Mutex. Locked sections are short, CPU-bound crypto ops with no `.await` held.
static MGR: OnceLock<Mutex<GroupManager<Store>>> = OnceLock::new();

/// EP2PCEventCallback (Kotlin interface) held across threads.
struct CallbackRef(jni::objects::GlobalRef);
static CALLBACK: OnceLock<CallbackRef> = OnceLock::new();

// Delivery-status codes handed back to Kotlin (EP2PC-005 §5.5).
const STATUS_SEND_FAILED: i32 = 2;

#[cfg(target_os = "android")]
fn init_logging() {
    use android_logger::Config;
    android_logger::init_once(Config::default().with_max_level(log::LevelFilter::Info));
}
#[cfg(not(target_os = "android"))]
fn init_logging() {
    let _ = tracing_subscriber::fmt::try_init();
}

/// `external fun nativeInit(callback: EP2PCEventCallback, dbPath: String, dbKey: ByteArray): Long`
#[no_mangle]
pub extern "system" fn Java_com_ep2pc_core_NativeBridge_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
    callback: JObject,
    db_path: JString,
    db_key: JByteArray,
) -> jlong {
    init_logging();

    // Keep the JVM + callback alive for the process lifetime.
    if let Ok(vm) = env.get_java_vm() {
        let _ = JVM.set(vm);
    }
    if let Ok(global) = env.new_global_ref(callback) {
        let _ = CALLBACK.set(CallbackRef(global));
    }

    let db_path: String = env.get_string(&db_path).map(|s| s.into()).unwrap_or_default();
    let db_key: Vec<u8> = env.convert_byte_array(&db_key).unwrap_or_default();

    // The DB key (from Android Keystore, EP2PC-007 §7.2) is also used to seal the
    // identity secret at rest, so the crown-jewel key never touches disk in the clear.
    let key32: [u8; 32] = match db_key.as_slice().try_into() {
        Ok(k) => k,
        Err(_) => {
            tracing::error!("db key must be 32 bytes");
            return 0;
        }
    };

    // Load or create the long-term identity (EP2PC-004 §4.3), sealed next to the DB.
    let identity = match load_or_create_identity(&db_path, &key32) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("identity init failed: {e}");
            return 0;
        }
    };
    let ed_secret = identity.ed25519_secret_bytes();

    // Derive and cache our own PeerId (from the same Ed25519 identity) for SAF records.
    if let Ok(kp) = keypair_from_ed25519_secret(&ed_secret) {
        let _ = MY_PEER.set(kp.public().to_peer_id());
    }

    // Open the encrypted store and build the message engine. The engine owns the identity
    // and persists per-peer ratchet state through the SQLCipher-backed store (EP2PC-007).
    let store = match Store::open(&db_path, &key32) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("store open failed: {e}");
            return 0;
        }
    };

    // Load or create the long-term signed prekey secret (EP2PC-004 §4.4), stored encrypted
    // in the SQLCipher DB.
    let prekey_secret: [u8; 32] = match store.load_local_secret(PREKEY_NAME) {
        Ok(Some(b)) if b.len() == 32 => b.try_into().unwrap(),
        _ => {
            let mut s = [0u8; 32];
            ep2pc_crypto::fill_random(&mut s);
            let _ = store.save_local_secret(PREKEY_NAME, &s);
            s
        }
    };
    let local_prekey = ep2pc_crypto::SignedPreKey::from_secret_bytes(&identity, &prekey_secret);

    // Our own app-wide peer key is the 32-byte Ed25519 identity (EP2PC-003 §3.2).
    let my_ed = identity.peer_id_bytes().to_vec();
    let engine = Engine::new(identity, store, local_prekey);
    if MGR
        .set(Mutex::new(GroupManager::new(engine, my_ed)))
        .is_err()
    {
        tracing::warn!("group manager already initialized");
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("tokio runtime: {e}");
            return 0;
        }
    };

    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>(256);
    let (evt_tx, mut evt_rx) = mpsc::channel::<ep2pc_net::Event>(256);

    // Spawn the swarm event loop.
    runtime.spawn(async move {
        let keypair = match keypair_from_ed25519_secret(&ed_secret) {
            Ok(kp) => kp,
            Err(e) => {
                tracing::error!("keypair: {e}");
                return;
            }
        };
        // Bootstrap list comes from user settings (EP2PC-003 §3.5.4); empty = LAN/mDNS only
        // until the user adds a node. Wire settings through JNI in a later revision.
        let cfg = NetConfig::default();
        match build_swarm(keypair, &cfg) {
            Ok(swarm) => ep2pc_net::run(swarm, cmd_rx, evt_tx).await,
            Err(e) => tracing::error!("build_swarm: {e}"),
        }
    });

    // Dispatch events back to Kotlin on a task that attaches to the JVM.
    runtime.spawn(async move {
        while let Some(ev) = evt_rx.recv().await {
            dispatch_event(ev);
        }
    });

    if CORE.set(Core { cmd_tx, _runtime: runtime }).is_err() {
        tracing::warn!("core already initialized");
    }
    1 // opaque non-zero handle = success
}

/// `external fun nativeSendMessage(conversationId: ByteArray, plaintextEnvelope: ByteArray)`
///
/// The Kotlin layer passes the *plaintext* application `Envelope` (EP2PC-005 §5.4); all
/// encryption happens here. For a 1:1 conversation, `conversationId` is the peer's 32-byte
/// **Ed25519 public key** (the single app-wide peer key, EP2PC-003 §3.2): the engine
/// encrypts with that peer's ratchet session and the net layer maps the key to a libp2p
/// PeerId for delivery. A 16-byte id is treated as a `group_id`.
#[no_mangle]
pub extern "system" fn Java_com_ep2pc_core_NativeBridge_nativeSendMessage(
    mut env: JNIEnv,
    _class: JClass,
    conversation_id: JByteArray,
    envelope: JByteArray,
) {
    let conv = env.convert_byte_array(&conversation_id).unwrap_or_default();
    let plaintext = env.convert_byte_array(&envelope).unwrap_or_default();
    let Some(core) = CORE.get() else { return };

    let ed25519: Option<[u8; 32]> = conv.as_slice().try_into().ok();
    let cmd = match ed25519.and_then(|k| ep2pc_net::peer_id_from_ed25519_pub(&k)) {
        Some(peer) => {
            // 1:1 — encrypt with the peer's ratchet session (keyed by the Ed25519 key).
            let Some(mgr) = MGR.get() else { return };
            let wire = {
                let mut guard = match mgr.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                match guard.engine_mut().encrypt(&conv, &conv, &plaintext) {
                    Ok(w) => w,
                    Err(EngineError::NoSession) => {
                        tracing::warn!("no session for peer; message not sent");
                        return;
                    }
                    Err(e) => {
                        tracing::error!("encrypt failed: {e}");
                        return;
                    }
                }
            };
            Command::SendDirect { peer, bytes: wire }
        }
        None => {
            // Group message: encrypt with the current group key and frame for GossipSub.
            let Some(mgr) = MGR.get() else { return };
            let payload = match mgr.lock() {
                Ok(g) => match g.group_message_payload(&conv, &plaintext) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!("group encrypt failed: {e}");
                        return;
                    }
                },
                Err(_) => return,
            };
            Command::PublishGroup { group_id: conv.clone(), bytes: payload }
        }
    };
    // For 1:1 sends, persist the encrypted wire to the outbound queue so that if delivery
    // fails (peer offline), we can hand it to store-and-forward (EP2PC-003 §3.7).
    if let Command::SendDirect { ref bytes, .. } = cmd {
        if let Some(mgr) = MGR.get() {
            if let Ok(mut g) = mgr.lock() {
                if let Ok(msg) = ep2pc_proto::decode::<ep2pc_proto::EncryptedMessage>(bytes) {
                    let _ = g
                        .engine_mut()
                        .backend_mut()
                        .enqueue_outbound(&msg.message_id, &conv, bytes, now_millis());
                }
            }
        }
    }
    // Non-blocking hand-off; on failure the runtime emits DirectSendFailed and the app
    // routes via store-and-forward (EP2PC-003 §3.7).
    let _ = core.cmd_tx.try_send(cmd);
}

/// `external fun nativeMyBundle(): ByteArray` — our public prekey bundle (160 bytes) to
/// render as a QR code so a contact can start a session with us (EP2PC-003 §3.3).
#[no_mangle]
pub extern "system" fn Java_com_ep2pc_core_NativeBridge_nativeMyBundle(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    let null = std::ptr::null_mut();
    let Some(mgr) = MGR.get() else { return null };
    let Ok(mut guard) = mgr.lock() else { return null };
    let bytes = guard.engine_mut().own_bundle().to_bytes();
    env.byte_array_from_slice(&bytes)
        .map(|a| a.into_raw())
        .unwrap_or(null)
}

/// `external fun nativeAddContact(bundle: ByteArray): ByteArray`
///
/// Adds a scanned contact and starts an outbound session (EP2PC-004 §4.4). `bundle` is the
/// 160-byte `PreKeyBundle` decoded from the contact's QR code; the PeerId is derived from
/// the Ed25519 identity inside it. Returns the contact's PeerId bytes on success (use it as
/// the conversation id), or an empty array on failure.
#[no_mangle]
pub extern "system" fn Java_com_ep2pc_core_NativeBridge_nativeAddContact(
    mut env: JNIEnv,
    _class: JClass,
    bundle: JByteArray,
) -> jbyteArray {
    let empty = env
        .byte_array_from_slice(&[])
        .map(|a| a.into_raw())
        .unwrap_or(std::ptr::null_mut());

    let bundle_bytes = env.convert_byte_array(&bundle).unwrap_or_default();
    // from_bytes verifies the Ed25519 signature over the prekey (EP2PC-004 §4.4).
    let Ok(bundle) = ep2pc_crypto::PreKeyBundle::from_bytes(&bundle_bytes) else {
        return empty;
    };
    // The app-wide peer key is the 32-byte Ed25519 identity (EP2PC-003 §3.2).
    let peer = bundle.identity.ed25519.to_vec();

    let Some(mgr) = MGR.get() else { return empty };
    let Ok(mut guard) = mgr.lock() else { return empty };

    // Persist the contact identity so the responder path can complete an incoming handshake.
    let id_bytes = bundle.identity.to_bytes();
    let _ = guard
        .engine_mut()
        .backend_mut()
        .upsert_contact(&peer, &id_bytes, None, now_millis());

    match guard.engine_mut().establish_outbound(&peer, &bundle) {
        Ok(()) => env
            .byte_array_from_slice(&peer)
            .map(|a| a.into_raw())
            .unwrap_or(empty),
        Err(e) => {
            tracing::error!("establish_outbound failed: {e}");
            empty
        }
    }
}

/// `external fun nativeCreateGroup(name: String): ByteArray` — create a group and return its
/// 16-byte id (EP2PC-006 §6.5). We become the sole admin and subscribe to its topic.
#[no_mangle]
pub extern "system" fn Java_com_ep2pc_core_NativeBridge_nativeCreateGroup(
    mut env: JNIEnv,
    _class: JClass,
    name: JString,
) -> jbyteArray {
    let empty = env.byte_array_from_slice(&[]).map(|a| a.into_raw()).unwrap_or(std::ptr::null_mut());
    let name: String = env.get_string(&name).map(|s| s.into()).unwrap_or_default();
    let (Some(core), Some(mgr)) = (CORE.get(), MGR.get()) else { return empty };

    let mut gid = [0u8; 16];
    ep2pc_crypto::fill_random(&mut gid);
    let gid = gid.to_vec();
    {
        let Ok(mut g) = mgr.lock() else { return empty };
        g.create_group(gid.clone(), name);
    }
    let _ = core.cmd_tx.try_send(Command::JoinGroup { group_id: gid.clone() });
    env.byte_array_from_slice(&gid).map(|a| a.into_raw()).unwrap_or(empty)
}

/// `external fun nativeGroupAdd(groupId: ByteArray, memberEd25519: ByteArray): Boolean`
/// Admin adds a member: broadcasts the signed control and delivers the rotated key to each
/// current member over their 1:1 session (EP2PC-006 §6.6).
#[no_mangle]
pub extern "system" fn Java_com_ep2pc_core_NativeBridge_nativeGroupAdd(
    mut env: JNIEnv,
    _class: JClass,
    group_id: JByteArray,
    member: JByteArray,
) -> jboolean {
    group_membership_op(&mut env, group_id, member, true)
}

/// `external fun nativeGroupRemove(groupId: ByteArray, memberEd25519: ByteArray): Boolean`
/// Admin removes a member: mandatory key rotation; the removed peer gets no new key.
#[no_mangle]
pub extern "system" fn Java_com_ep2pc_core_NativeBridge_nativeGroupRemove(
    mut env: JNIEnv,
    _class: JClass,
    group_id: JByteArray,
    member: JByteArray,
) -> jboolean {
    group_membership_op(&mut env, group_id, member, false)
}

fn group_membership_op(env: &mut JNIEnv, group_id: JByteArray, member: JByteArray, add: bool) -> jboolean {
    let gid = env.convert_byte_array(&group_id).unwrap_or_default();
    let member = env.convert_byte_array(&member).unwrap_or_default();
    let (Some(core), Some(mgr)) = (CORE.get(), MGR.get()) else { return 0 };

    let out = {
        let Ok(mut g) = mgr.lock() else { return 0 };
        let r = if add { g.add_member(&gid, member) } else { g.remove_member(&gid, &member) };
        match r {
            Ok(o) => o,
            Err(e) => {
                tracing::error!("group membership op failed: {e}");
                return 0;
            }
        }
    };
    dispatch_group_output(core, &gid, out);
    1
}

/// Broadcast a group control on its topic and deliver the rotated key to each recipient
/// over their 1:1 session (EP2PC-006 §6.4–6.6).
fn dispatch_group_output(core: &Core, group_id: &[u8], out: GroupOutput) {
    let control_payload = GroupManager::<Store>::control_payload(&out.control);
    let _ = core.cmd_tx.try_send(Command::PublishGroup {
        group_id: group_id.to_vec(),
        bytes: control_payload,
    });
    for (recipient_ed, wire) in out.key_deliveries {
        if let Ok(ed) = <[u8; 32]>::try_from(recipient_ed.as_slice()) {
            if let Some(peer) = ep2pc_net::peer_id_from_ed25519_pub(&ed) {
                let _ = core.cmd_tx.try_send(Command::SendDirect { peer, bytes: wire });
            }
        }
    }
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Call the Kotlin `onMessageReceived(peerId, envelope)` with the sender peer id and the
/// decrypted plaintext Envelope bytes.
fn deliver_message(env: &mut JNIEnv, cb: &jni::objects::GlobalRef, peer: &[u8], plaintext: &[u8]) {
    if let (Ok(peer_arr), Ok(env_arr)) = (
        env.byte_array_from_slice(peer),
        env.byte_array_from_slice(plaintext),
    ) {
        let _ = env.call_method(
            cb,
            "onMessageReceived",
            "([B[B)V",
            &[
                JValue::Object(&peer_arr.into()),
                JValue::Object(&env_arr.into()),
            ],
        );
    }
}

fn dispatch_event(ev: ep2pc_net::Event) {
    let (Some(vm), Some(cb)) = (JVM.get(), CALLBACK.get()) else {
        return;
    };
    let Ok(mut env) = vm.attach_current_thread_permanently() else {
        return;
    };
    match ev {
        ep2pc_net::Event::MessageReceived { from, bytes, via_group } => {
            let Some(core) = CORE.get() else { return };
            let Some(mgr) = MGR.get() else { return };
            let Ok(mut guard) = mgr.lock() else { return };

            if via_group {
                // GossipSub group traffic: a signed control or an encrypted group message.
                let Some(b) = GroupManager::<Store>::parse_broadcast(&bytes) else { return };
                match guard.apply_broadcast(b) {
                    Ok(Some((group_id, plaintext))) => {
                        drop(guard);
                        deliver_message(&mut env, &cb.0, &group_id, &plaintext);
                    }
                    Ok(None) => { /* control applied; membership/keys updated */ }
                    Err(e) => tracing::warn!("group broadcast from {from}: {e}"),
                }
            } else {
                // 1:1 traffic: either an ordinary chat or a group key delivery (routed
                // internally). This decrypts exactly once (EP2PC-006 §6.6).
                let Some(peer) = ep2pc_net::ed25519_from_peer_id(&from).map(|k| k.to_vec()) else {
                    return;
                };
                match guard.handle_1to1(&peer, &bytes) {
                    Ok(Incoming1to1::Chat { plaintext }) => {
                        drop(guard);
                        deliver_message(&mut env, &cb.0, &peer, &plaintext);
                    }
                    Ok(Incoming1to1::GroupKey { group_id }) => {
                        // We just (re)received a group key; make sure we're subscribed.
                        let _ = core.cmd_tx.try_send(Command::JoinGroup { group_id });
                    }
                    Err(e) => tracing::warn!("decrypt failed from {from}: {e}"),
                }
            }
        }
        ep2pc_net::Event::DirectSendFailed { peer } => {
            let ed = ep2pc_net::ed25519_from_peer_id(&peer);
            if let Some(ed) = &ed {
                if let Ok(arr) = env.byte_array_from_slice(ed) {
                    let _ = env.call_method(
                        &cb.0,
                        "onDeliveryStatusChanged",
                        "([BI)V",
                        &[JValue::Object(&arr.into()), JValue::Int(STATUS_SEND_FAILED)],
                    );
                }
            }
            // Hand any queued messages for this (offline) peer to storage peers (§3.7).
            if let (Some(core), Some(engine), Some(my_peer), Some(conv)) =
                (CORE.get(), MGR.get(), MY_PEER.get(), ed)
            {
                if let Ok(mut g) = engine.lock() {
                    if let Ok(items) = g.0.outbound_for_conversation(&conv) {
                        for (mid, blob) in items {
                            let _ = core.cmd_tx.try_send(Command::StoreForward {
                                recipient: peer.clone(),
                                sender: my_peer.clone(),
                                message_id: mid.clone(),
                                blob,
                                ttl_ms: ep2pc_saf::DEFAULT_TTL_MS,
                            });
                            // Handed off to storage peers; drop the local queue copy.
                            let _ = g.0.dequeue_outbound(&mid);
                        }
                    }
                }
            }
        }
        ep2pc_net::Event::ConnectionChanged { peer, connected } => {
            if let Some(ed) = ep2pc_net::ed25519_from_peer_id(&peer) {
                if let Ok(arr) = env.byte_array_from_slice(&ed) {
                    let _ = env.call_method(
                        &cb.0,
                        "onConnectionStateChanged",
                        "([BZ)V",
                        &[JValue::Object(&arr.into()), JValue::Bool(connected as u8)],
                    );
                }
            }
            // On (re)connect, ask the peer whether it's holding any store-and-forward
            // messages addressed to us (§3.7).
            if connected {
                if let (Some(core), Some(my_peer)) = (CORE.get(), MY_PEER.get()) {
                    let _ = core.cmd_tx.try_send(Command::FetchStored {
                        storage_peer: peer,
                        recipient: my_peer.clone(),
                    });
                }
            }
        }
        ep2pc_net::Event::StoredMessageReceived { from, storage_peer, message_id, bytes } => {
            let Some(peer) = ep2pc_net::ed25519_from_peer_id(&from).map(|k| k.to_vec()) else {
                return;
            };
            // Route like any 1:1 message: ordinary chat -> UI; group key delivery -> absorbed.
            let is_chat = match MGR.get().and_then(|m| m.lock().ok().map(|mut g| g.handle_1to1(&peer, &bytes))) {
                Some(Ok(Incoming1to1::Chat { plaintext })) => {
                    deliver_message(&mut env, &cb.0, &peer, &plaintext);
                    true
                }
                Some(Ok(Incoming1to1::GroupKey { group_id })) => {
                    if let Some(core) = CORE.get() {
                        let _ = core.cmd_tx.try_send(Command::JoinGroup { group_id });
                    }
                    true
                }
                Some(Err(e)) => {
                    tracing::warn!("SAF handle failed from {from}: {e}");
                    false
                }
                None => false,
            };
            // Whether chat or key delivery, ACK so the storage peer can delete its copy.
            if is_chat {
                if let (Some(core), Some(mgr), Some(my_peer)) =
                    (CORE.get(), MGR.get(), MY_PEER.get())
                {
                    if let Ok(g) = mgr.lock() {
                        let sig = g.identity().sign(&ep2pc_saf::ack_signing_input(&message_id));
                        let _ = core.cmd_tx.try_send(Command::SendSafAck {
                            storage_peer,
                            message_id,
                            recipient: my_peer.clone(),
                            signature: sig.to_vec(),
                        });
                    }
                }
            }
        }
        ep2pc_net::Event::PeerDiscovered { .. } => {}
    }
}

/// Load the identity secret from `<db_dir>/identity.bin`, sealed with the Keystore-derived
/// key; create and persist a fresh one on first run.
fn load_or_create_identity(
    db_path: &str,
    key32: &[u8; 32],
) -> Result<ep2pc_crypto::Identity, String> {
    const AAD: &[u8] = b"ep2pc-identity-v1";
    let path = identity_path(db_path);

    if let Ok(blob) = std::fs::read(&path) {
        if blob.len() > 12 {
            let (nonce, ct) = blob.split_at(12);
            let nonce: [u8; 12] = nonce.try_into().map_err(|_| "bad nonce".to_string())?;
            let plain = ep2pc_crypto::aead::open(key32, &nonce, ct, AAD)
                .map_err(|_| "identity decrypt failed".to_string())?;
            if plain.len() == 64 {
                let ed: [u8; 32] = plain[..32].try_into().unwrap();
                let x: [u8; 32] = plain[32..].try_into().unwrap();
                return Ok(ep2pc_crypto::Identity::from_secret_bytes(&ed, &x));
            }
        }
        return Err("corrupt identity file".to_string());
    }

    // First run: generate, seal, persist.
    let id = ep2pc_crypto::Identity::generate();
    let mut plain = Vec::with_capacity(64);
    plain.extend_from_slice(&id.ed25519_secret_bytes());
    plain.extend_from_slice(&id.x25519_secret_bytes());

    let nonce = random_nonce();
    let ct = ep2pc_crypto::aead::seal(key32, &nonce, &plain, AAD)
        .map_err(|_| "identity encrypt failed".to_string())?;
    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    std::fs::write(&path, blob).map_err(|e| e.to_string())?;
    Ok(id)
}

fn identity_path(db_path: &str) -> PathBuf {
    let mut p = PathBuf::from(db_path);
    p.set_file_name("identity.bin");
    p
}

fn random_nonce() -> [u8; 12] {
    let mut n = [0u8; 12];
    ep2pc_crypto::fill_random(&mut n);
    n
}
