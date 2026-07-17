//! Commands the app layer sends into the swarm event loop (EP2PC-008 §8.4, Kotlin→Rust).

use libp2p::{Multiaddr, PeerId, Swarm};

use crate::{group_topic, Ep2pcBehaviour, NodeState, SafRecordWire, SafRequest};

pub enum Command {
    /// Dial a known peer address (e.g. after a DHT lookup or from cache, EP2PC-003 §3.4.2).
    Dial { addr: Multiaddr },
    /// Connect to a peer by id: use cached addresses if known, else start a DHT lookup and
    /// dial automatically once an address is discovered.
    ConnectPeer { peer: PeerId },
    /// Look up a peer's current addresses in the DHT.
    FindPeer { peer: PeerId },
    /// Send an already-encrypted 1:1 message to a peer over the direct stream.
    SendDirect { peer: PeerId, bytes: Vec<u8> },
    /// Join a group's gossip topic.
    JoinGroup { group_id: Vec<u8> },
    /// Publish an encrypted group message.
    PublishGroup { group_id: Vec<u8>, bytes: Vec<u8> },
    /// Leave a group's gossip topic.
    LeaveGroup { group_id: Vec<u8> },
    /// Recipient offline: hand the encrypted blob to a few storage peers (EP2PC-003 §3.7).
    StoreForward {
        recipient: PeerId,
        sender: PeerId,
        message_id: Vec<u8>,
        blob: Vec<u8>,
        ttl_ms: i64,
    },
    /// On reconnect, ask a storage peer for any messages held for us.
    FetchStored { storage_peer: PeerId, recipient: PeerId },
    /// After a stored message is delivered, tell the storage peer to delete it (signed ACK).
    SendSafAck {
        storage_peer: PeerId,
        message_id: Vec<u8>,
        recipient: PeerId,
        signature: Vec<u8>,
    },
}

pub async fn handle(swarm: &mut Swarm<Ep2pcBehaviour>, state: &mut NodeState, cmd: Command) {
    match cmd {
        Command::Dial { addr } => {
            if let Err(e) = swarm.dial(addr) {
                tracing::warn!("dial failed: {e}");
            }
        }
        Command::ConnectPeer { peer } => connect_peer(swarm, state, peer),
        Command::FindPeer { peer } => {
            // Kicks off an XOR-distance-routed lookup; results arrive as Kademlia
            // RoutingUpdated / OutboundQueryProgressed events and get cached (§3.4.2).
            swarm.behaviour_mut().kademlia.get_closest_peers(peer);
        }
        Command::SendDirect { peer, bytes } => {
            // request_response auto-dials the peer if a valid address is in the swarm's
            // address book; we also proactively ensure we have one cached. If the peer is
            // unreachable, libp2p emits OutboundFailure -> DirectSendFailed -> the app
            // routes via store-and-forward (EP2PC-003 §3.7). See event.rs.
            if !swarm.is_connected(&peer) {
                connect_peer(swarm, state, peer);
            }
            let request_id = swarm.behaviour_mut().direct.send_request(&peer, bytes);
            tracing::debug!("SendDirect -> {peer} (req {request_id:?})");
        }
        Command::JoinGroup { group_id } => {
            let topic = group_topic(&group_id);
            if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                tracing::warn!("group subscribe failed: {e}");
            }
        }
        Command::PublishGroup { group_id, bytes } => {
            let topic = group_topic(&group_id);
            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, bytes) {
                // NotEnoughPeers is normal right after joining; the message can be retried.
                tracing::debug!("group publish deferred: {e}");
            }
        }
        Command::LeaveGroup { group_id } => {
            let topic = group_topic(&group_id);
            let _ = swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
        }

        Command::StoreForward { recipient, sender, message_id, blob, ttl_ms } => {
            // Choose storage peers from the peers we currently know, mixing XOR-closeness
            // with randomization to resist Sybil positioning (EP2PC-003 §3.7.3).
            let candidates: Vec<Vec<u8>> = state
                .addr_book
                .keys()
                .filter(|p| **p != recipient)
                .map(|p| p.to_bytes())
                .collect();
            let chosen = ep2pc_saf::select_storage_peers(
                &recipient.to_bytes(),
                &candidates,
                ep2pc_saf::DEFAULT_REDUNDANCY,
            );
            let record = SafRecordWire {
                message_id,
                recipient: recipient.to_bytes(),
                sender: sender.to_bytes(),
                blob,
                stored_at_ms: now_millis(),
                ttl_ms,
            };
            for peer_bytes in chosen {
                if let Ok(peer) = PeerId::from_bytes(&peer_bytes) {
                    if !swarm.is_connected(&peer) {
                        connect_peer(swarm, state, peer);
                    }
                    swarm
                        .behaviour_mut()
                        .saf
                        .send_request(&peer, SafRequest::Store(record.clone()));
                }
            }
        }
        Command::FetchStored { storage_peer, recipient } => {
            swarm.behaviour_mut().saf.send_request(
                &storage_peer,
                SafRequest::Fetch { recipient: recipient.to_bytes() },
            );
        }
        Command::SendSafAck { storage_peer, message_id, recipient, signature } => {
            swarm.behaviour_mut().saf.send_request(
                &storage_peer,
                SafRequest::Ack { message_id, recipient: recipient.to_bytes(), signature },
            );
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

/// Dial a peer using cached addresses; if none are known yet, start a DHT lookup and mark
/// the peer as pending so the event loop dials it automatically once an address arrives.
fn connect_peer(swarm: &mut Swarm<Ep2pcBehaviour>, state: &mut NodeState, peer: PeerId) {
    if let Some(addrs) = state.addr_book.get(&peer) {
        if !addrs.is_empty() {
            for addr in addrs.iter().cloned() {
                let _ = swarm.dial(addr);
            }
            return;
        }
    }
    // No direct address (peer is behind NAT). If a relay is configured, reach the peer at
    // `<relay>/p2p-circuit/p2p/<peer>` — we know the peer's id from the QR exchange and the
    // relay from settings, so no lookup is needed (EP2PC-003 §3.6).
    if let Some(relay) = state.relay.clone() {
        let circuit = relay
            .with(libp2p::core::multiaddr::Protocol::P2pCircuit)
            .with(libp2p::core::multiaddr::Protocol::P2p(peer));
        swarm.behaviour_mut().direct.add_address(&peer, circuit.clone());
        swarm.behaviour_mut().saf.add_address(&peer, circuit.clone());
        state.remember(peer, circuit.clone());
        let _ = swarm.dial(circuit);
        return;
    }
    // No relay either — resolve via DHT and remember the intent.
    state.pending_dial.insert(peer);
    swarm.behaviour_mut().kademlia.get_closest_peers(peer);
}
