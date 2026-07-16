//! EP2PC networking layer (EP2PC-003).
//!
//! Composes a libp2p `Swarm` with:
//!   - TCP + Noise + Yamux (default transport, EP2PC-003 §3.1) and optional QUIC
//!   - Kademlia DHT for WAN peer discovery (§3.4.2)
//!   - mDNS for LAN discovery (§3.4.1) — tried first, cheapest path
//!   - Identify (address exchange), Ping (adaptive keep-alive, §3.8)
//!   - AutoNAT + DCUtR (hole punching) + Relay client (§3.6 fallback chain)
//!   - GossipSub for group message propagation (§3.9, EP2PC-006)
//!
//! The swarm runs on its own dedicated Tokio runtime thread (EP2PC-008 §8.4) and is
//! driven by an event loop. The rest of the app talks to it via an async command
//! channel; incoming events are pushed out through an event channel. No polling: the
//! loop parks on `select!` until a socket event or a command arrives — this is what
//! delivers the "0% CPU at rest" requirement (EP2PC-001 §1.4).

use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    autonat, dcutr, gossipsub, identify, kad,
    kad::store::MemoryStore,
    mdns, noise, ping, relay, request_response,
    request_response::ProtocolSupport,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
};
use tokio::sync::mpsc;

pub mod command;
pub mod event;

/// Selected libp2p types re-exported for the FFI layer.
pub mod reexport {
    pub use libp2p::{identity::Keypair, Multiaddr, PeerId};
}

pub use command::Command;
pub use event::Event;

const KAD_PROTO: StreamProtocol = StreamProtocol::new("/ep2pc/kad/1.0.0");
const GOSSIP_MSG_PROTO: &str = "/ep2pc/gossip/1.0.0";
const IDENTIFY_PROTO: &str = "/ep2pc/id/1.0.0";
/// 1:1 direct encrypted-envelope protocol (EP2PC-005 §5.5).
pub const DIRECT_MSG_PROTO: StreamProtocol = StreamProtocol::new("/ep2pc/msg/1.0.0");

/// Request/response payloads for the direct-message protocol.
///
/// The request carries an already-encrypted `EncryptedMessage` envelope (EP2PC-004 §4.8);
/// the network layer never sees plaintext. The response is a lightweight transport-level
/// delivery marker — the *application-level* `DELIVERY_ACK` (EP2PC-005 §5.3) is a separate
/// signed message that triggers store-and-forward cleanup (EP2PC-003 §3.7.4).
pub type DirectRequest = Vec<u8>;
pub type DirectResponse = Vec<u8>;

/// The CBOR-framed request-response behaviour for 1:1 messages.
pub type DirectBehaviour = request_response::cbor::Behaviour<DirectRequest, DirectResponse>;

/// Store-and-forward protocol (EP2PC-003 §3.7). Runs over its own request-response stream
/// so a node can act as a storage peer for others without conflating with direct delivery.
pub const SAF_PROTO: StreamProtocol = StreamProtocol::new("/ep2pc/saf/1.0.0");

/// A store-and-forward record on the wire (the `blob` is an already-encrypted
/// `EncryptedMessage`; storage peers can't read it, EP2PC-003 §3.7.2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SafRecordWire {
    pub message_id: Vec<u8>,
    pub recipient: Vec<u8>,
    pub sender: Vec<u8>,
    pub blob: Vec<u8>,
    pub stored_at_ms: i64,
    pub ttl_ms: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SafRequest {
    /// Ask a storage peer to hold a message for an offline recipient.
    Store(SafRecordWire),
    /// On reconnect, ask a storage peer for any messages addressed to `recipient`.
    Fetch { recipient: Vec<u8> },
    /// After delivery, tell the storage peer to delete a record (signed by the recipient).
    Ack { message_id: Vec<u8>, recipient: Vec<u8>, signature: Vec<u8> },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SafResponse {
    Stored,
    Records(Vec<SafRecordWire>),
    Acked,
}

/// The CBOR-framed request-response behaviour for store-and-forward.
pub type SafBehaviour = request_response::cbor::Behaviour<SafRequest, SafResponse>;

/// Composed behaviour. `#[derive(NetworkBehaviour)]` generates the combined event enum.
#[derive(NetworkBehaviour)]
pub struct Ep2pcBehaviour {
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub ping: ping::Behaviour,
    pub autonat: autonat::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub relay_client: relay::client::Behaviour,
    /// 1:1 direct encrypted messages (EP2PC-005 §5.5).
    pub direct: DirectBehaviour,
    /// Store-and-forward for offline delivery (EP2PC-003 §3.7).
    pub saf: SafBehaviour,
}

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("transport/build error: {0}")]
    Build(String),
    #[error("swarm error: {0}")]
    Swarm(String),
}

/// Configuration passed in from the app layer / user settings (EP2PC-008 §8.7).
pub struct NetConfig {
    /// Bootstrap peers to dial on startup (EP2PC-003 §3.5). User-editable.
    pub bootstrap: Vec<Multiaddr>,
    /// Adaptive keep-alive interval in seconds (EP2PC-003 §3.8).
    pub keepalive_secs: u64,
    /// Enable QUIC in addition to TCP (EP2PC-003 §3.1, off by default).
    pub enable_quic: bool,
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            bootstrap: Vec::new(),
            keepalive_secs: 300, // 5 min baseline for mobile NAT (§3.8)
            enable_quic: false,
        }
    }
}

/// Build the swarm. The libp2p identity keypair should be derived from the EP2PC
/// Ed25519 identity (EP2PC-004 §4.3) so the PeerID equals the user's identity.
pub fn build_swarm(
    keypair: libp2p::identity::Keypair,
    cfg: &NetConfig,
) -> Result<Swarm<Ep2pcBehaviour>, NetError> {
    let local_peer_id = PeerId::from(keypair.public());

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| NetError::Build(e.to_string()))?
        .with_quic()
        .with_dns()
        .map_err(|e| NetError::Build(e.to_string()))?
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| NetError::Build(e.to_string()))?
        .with_behaviour(|key, relay_client| {
            // Kademlia (server mode enabled only on bootstrap nodes; clients stay in
            // client mode to save battery — EP2PC-003 §3.5.3).
            let mut kad_cfg = kad::Config::new(KAD_PROTO);
            kad_cfg.set_query_timeout(Duration::from_secs(10));
            let kademlia = kad::Behaviour::with_config(
                local_peer_id,
                MemoryStore::new(local_peer_id),
                kad_cfg,
            );

            // GossipSub with signed messages (author = Ed25519 identity).
            let gossip_cfg = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .protocol_id_prefix(GOSSIP_MSG_PROTO)
                .build()
                .expect("valid gossipsub config");
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossip_cfg,
            )
            .expect("valid gossipsub behaviour");

            let identify = identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTO.into(),
                key.public(),
            ));

            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                local_peer_id,
            )
            .expect("mdns");

            let ping = ping::Behaviour::new(
                ping::Config::new().with_interval(Duration::from_secs(cfg.keepalive_secs)),
            );

            let autonat = autonat::Behaviour::new(local_peer_id, autonat::Config::default());
            let dcutr = dcutr::Behaviour::new(local_peer_id);

            // 1:1 direct-message protocol (CBOR-framed, encrypted payload).
            let direct = request_response::cbor::Behaviour::<DirectRequest, DirectResponse>::new(
                [(DIRECT_MSG_PROTO, ProtocolSupport::Full)],
                request_response::Config::default(),
            );

            // Store-and-forward protocol.
            let saf = request_response::cbor::Behaviour::<SafRequest, SafResponse>::new(
                [(SAF_PROTO, ProtocolSupport::Full)],
                request_response::Config::default(),
            );

            Ep2pcBehaviour {
                kademlia,
                gossipsub,
                identify,
                mdns,
                ping,
                autonat,
                dcutr,
                relay_client,
                direct,
                saf,
            }
        })
        .map_err(|e| NetError::Build(e.to_string()))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // Listen on all interfaces, ephemeral port (no manual port opening — §3.6).
    swarm
        .listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap())
        .map_err(|e| NetError::Swarm(e.to_string()))?;
    if cfg.enable_quic {
        let _ = swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap());
    }

    // Seed the DHT with bootstrap peers.
    for addr in &cfg.bootstrap {
        if let Some(peer) = extract_peer_id(addr) {
            swarm.behaviour_mut().kademlia.add_address(&peer, addr.clone());
        }
    }
    let _ = swarm.behaviour_mut().kademlia.bootstrap();

    Ok(swarm)
}

fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
        _ => None,
    })
}

/// Build a libp2p keypair from the EP2PC Ed25519 identity secret (EP2PC-004 §4.3), so the
/// libp2p PeerID equals the user's cryptographic identity (EP2PC-003 §3.2).
pub fn keypair_from_ed25519_secret(secret: &[u8; 32]) -> Result<libp2p::identity::Keypair, NetError> {
    let mut bytes = *secret;
    libp2p::identity::Keypair::ed25519_from_bytes(&mut bytes)
        .map_err(|e| NetError::Build(e.to_string()))
}

/// Parse a libp2p `PeerId` from its raw wire (multihash) bytes.
pub fn peer_id_from_bytes(bytes: &[u8]) -> Option<PeerId> {
    PeerId::from_bytes(bytes).ok()
}

/// Derive a libp2p `PeerId` from a raw 32-byte Ed25519 public key. Used to turn a scanned
/// contact bundle (which carries the Ed25519 identity) into the PeerId that keys sessions
/// and addresses (EP2PC-003 §3.2).
pub fn peer_id_from_ed25519_pub(ed_pub: &[u8; 32]) -> Option<PeerId> {
    let pk = libp2p::identity::ed25519::PublicKey::try_from_bytes(ed_pub).ok()?;
    Some(libp2p::identity::PublicKey::from(pk).to_peer_id())
}

/// The reverse of [`peer_id_from_ed25519_pub`]: recover the 32-byte Ed25519 public key from
/// a libp2p `PeerId`. All EP2PC identities are Ed25519, so this is total for our peers; a
/// `None` means the PeerId isn't a valid EP2PC identity. This is the single translation the
/// net boundary applies so the rest of the app can key everything by Ed25519.
pub fn ed25519_from_peer_id(peer: &PeerId) -> Option<[u8; 32]> {
    ep2pc_peerid::ed25519_from_peer_id_bytes(&peer.to_bytes())
}

/// The event loop. Runs until the command channel closes.
pub async fn run(
    mut swarm: Swarm<Ep2pcBehaviour>,
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
) {
    let mut state = NodeState::default();
    loop {
        tokio::select! {
            // Park here at 0% CPU until something happens.
            maybe_cmd = commands.recv() => match maybe_cmd {
                Some(cmd) => command::handle(&mut swarm, &mut state, cmd).await,
                None => break, // app shutting down
            },
            swarm_event = swarm.select_next_some() => {
                event::handle(&mut swarm, &mut state, swarm_event, &events).await;
            }
        }
    }
}

/// Mutable state the event loop keeps alongside the swarm.
#[derive(Default)]
pub struct NodeState {
    /// Locally cached peer → known addresses (from mDNS, Identify, DHT — EP2PC-003 §3.4.2).
    /// Avoids repeat DHT lookups for peers we've already resolved.
    pub addr_book: std::collections::HashMap<PeerId, std::collections::HashSet<Multiaddr>>,
    /// Peers we want to connect to as soon as an address is known (e.g. a queued send).
    pub pending_dial: std::collections::HashSet<PeerId>,
    /// Messages this node is holding *as a storage peer* for others (EP2PC-003 §3.7).
    pub saf_store: ep2pc_saf::SafStore,
}

impl NodeState {
    /// Record an address for a peer; returns true if it was newly learned.
    pub fn remember(&mut self, peer: PeerId, addr: Multiaddr) -> bool {
        self.addr_book.entry(peer).or_default().insert(addr)
    }
}

/// Hash a `group_id` into a GossipSub topic (EP2PC-006 §6.2 — hashed topic).
///
/// Uses domain-separated SHA-256 from `ep2pc-crypto` so the raw `group_id` never appears
/// on the wire, defending against topic-name correlation (EP2PC-006 §6.2).
pub fn group_topic(group_id: &[u8]) -> gossipsub::IdentTopic {
    let digest = ep2pc_crypto::sha256_labeled(b"ep2pc-group-topic", group_id);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    gossipsub::IdentTopic::new(format!("/ep2pc/group/{hex}"))
}

type _SwarmEventAlias = SwarmEvent<Ep2pcBehaviourEvent>;
