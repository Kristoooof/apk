//! Swarm events translated into app-level events pushed to the FFI/UI layer.

use libp2p::{
    gossipsub, identify, kad, mdns, request_response,
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use tokio::sync::mpsc;

use crate::{
    Ep2pcBehaviour, Ep2pcBehaviourEvent, NodeState, SafRecordWire, SafRequest, SafResponse,
};

/// App-facing events (become JNI callbacks, EP2PC-008 §8.4, Rust→Kotlin).
#[derive(Debug)]
pub enum Event {
    /// An encrypted message arrived. `via_group` is true for GossipSub (group) traffic,
    /// false for a 1:1 direct message — the app layer decrypts them differently
    /// (per-peer Double Ratchet vs. group key).
    MessageReceived { from: PeerId, bytes: Vec<u8>, via_group: bool },
    /// A store-and-forward message was delivered to us by a storage peer. After decrypting,
    /// the app signs and sends a SAF ACK so the storage peer can delete its copy (§3.7.4).
    StoredMessageReceived {
        from: PeerId,
        storage_peer: PeerId,
        message_id: Vec<u8>,
        bytes: Vec<u8>,
    },
    /// A direct send to `peer` failed (peer offline/unreachable) — the app layer should
    /// fall back to store-and-forward for this message (EP2PC-003 §3.7).
    DirectSendFailed { peer: PeerId },
    /// Connection state to a peer changed (drives online/offline UI).
    ConnectionChanged { peer: PeerId, connected: bool },
    /// A peer's addresses were discovered (LAN mDNS or DHT).
    PeerDiscovered { peer: PeerId },
}

pub async fn handle(
    swarm: &mut Swarm<Ep2pcBehaviour>,
    state: &mut NodeState,
    ev: SwarmEvent<Ep2pcBehaviourEvent>,
    out: &mpsc::Sender<Event>,
) {
    match ev {
        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            state.pending_dial.remove(&peer_id);
            let _ = out
                .send(Event::ConnectionChanged { peer: peer_id, connected: true })
                .await;
        }
        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            let _ = out
                .send(Event::ConnectionChanged { peer: peer_id, connected: false })
                .await;
        }

        // --- LAN discovery (EP2PC-003 §3.4.1) ---
        SwarmEvent::Behaviour(Ep2pcBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
            for (peer, addr) in list {
                learn_address(swarm, state, peer, addr);
                let _ = out.send(Event::PeerDiscovered { peer }).await;
                // Eagerly connect to freshly discovered LAN peers so 1:1 messages flow (and
                // the UI shows them online) immediately — not only when a send is pending.
                if !swarm.is_connected(&peer) {
                    let _ = swarm.dial(peer);
                }
                maybe_dial_pending(swarm, state, peer);
            }
        }

        // --- Identify: authoritative listen addresses for a peer (EP2PC-003 §3.4.2) ---
        SwarmEvent::Behaviour(Ep2pcBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
        })) => {
            for addr in info.listen_addrs {
                learn_address(swarm, state, peer_id, addr);
            }
            maybe_dial_pending(swarm, state, peer_id);
        }

        // --- 1:1 direct messages (EP2PC-005 §5.5) ---
        SwarmEvent::Behaviour(Ep2pcBehaviourEvent::Direct(request_response::Event::Message {
            peer,
            message,
        })) => match message {
            request_response::Message::Request { request, channel, .. } => {
                let _ = out
                    .send(Event::MessageReceived { from: peer, bytes: request, via_group: false })
                    .await;
                // Transport-level delivery marker (empty body). The signed application
                // DELIVERY_ACK that clears store-and-forward is a separate message
                // (EP2PC-005 §5.3, EP2PC-003 §3.7.4).
                let _ = swarm.behaviour_mut().direct.send_response(channel, Vec::new());
            }
            request_response::Message::Response { .. } => {
                // Transport-level ack received; the message reached the peer's stack.
            }
        },
        SwarmEvent::Behaviour(Ep2pcBehaviourEvent::Direct(
            request_response::Event::OutboundFailure { peer, .. },
        )) => {
            let _ = out.send(Event::DirectSendFailed { peer }).await;
        }

        // --- store-and-forward (EP2PC-003 §3.7) ---
        SwarmEvent::Behaviour(Ep2pcBehaviourEvent::Saf(request_response::Event::Message {
            peer,
            message,
        })) => match message {
            request_response::Message::Request { request, channel, .. } => {
                let response = handle_saf_request(state, request);
                let _ = swarm.behaviour_mut().saf.send_response(channel, response);
            }
            request_response::Message::Response { response, .. } => {
                if let SafResponse::Records(records) = response {
                    // Messages a storage peer held for us: surface each for decryption + ACK.
                    for rec in records {
                        if let Ok(from) = PeerId::from_bytes(&rec.sender) {
                            let _ = out
                                .send(Event::StoredMessageReceived {
                                    from,
                                    storage_peer: peer,
                                    message_id: rec.message_id,
                                    bytes: rec.blob,
                                })
                                .await;
                        }
                    }
                }
            }
        },

        // --- group messages (EP2PC-003 §3.9, EP2PC-006) ---
        SwarmEvent::Behaviour(Ep2pcBehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message,
            ..
        })) => {
            let _ = out
                .send(Event::MessageReceived {
                    from: propagation_source,
                    bytes: message.data,
                    via_group: true,
                })
                .await;
        }

        // --- DHT lookups (EP2PC-003 §3.4.2) ---
        SwarmEvent::Behaviour(Ep2pcBehaviourEvent::Kademlia(kad::Event::RoutingUpdated {
            peer,
            addresses,
            ..
        })) => {
            for addr in addresses.iter().cloned() {
                let _ = state.remember(peer, addr);
            }
            maybe_dial_pending(swarm, state, peer);
        }
        SwarmEvent::Behaviour(Ep2pcBehaviourEvent::Kademlia(
            kad::Event::OutboundQueryProgressed { .. },
        )) => {
            // Query finished; any addresses learned surface via RoutingUpdated above.
        }
        _ => {}
    }
}

/// Cache an address both in our local book and in Kademlia's routing table.
fn learn_address(swarm: &mut Swarm<Ep2pcBehaviour>, state: &mut NodeState, peer: PeerId, addr: Multiaddr) {
    if state.remember(peer, addr.clone()) {
        swarm.behaviour_mut().kademlia.add_address(&peer, addr.clone());
        // request_response keeps its OWN dial address book; without this a `send_request`
        // to a not-yet-connected peer fails with "no addresses" even though mDNS just told
        // us where the peer is. This is required for 1:1 messages and SAF to reach peers.
        swarm.behaviour_mut().direct.add_address(&peer, addr.clone());
        swarm.behaviour_mut().saf.add_address(&peer, addr);
    }
}

/// If we were waiting to reach `peer` and now have an address, dial it.
fn maybe_dial_pending(swarm: &mut Swarm<Ep2pcBehaviour>, state: &mut NodeState, peer: PeerId) {
    if !state.pending_dial.contains(&peer) || swarm.is_connected(&peer) {
        return;
    }
    if let Some(addrs) = state.addr_book.get(&peer) {
        for addr in addrs.iter().cloned() {
            let _ = swarm.dial(addr);
        }
        state.pending_dial.remove(&peer);
    }
}

/// This node acting as a storage peer for others (EP2PC-003 §3.7.4).
fn handle_saf_request(state: &mut NodeState, request: SafRequest) -> SafResponse {
    let now = now_millis();
    match request {
        SafRequest::Store(rec) => {
            state.saf_store.store(
                ep2pc_saf::SafRecord {
                    message_id: rec.message_id,
                    recipient: rec.recipient,
                    sender: rec.sender,
                    blob: rec.blob,
                    stored_at_ms: rec.stored_at_ms,
                    ttl_ms: rec.ttl_ms,
                },
                now,
            );
            SafResponse::Stored
        }
        SafRequest::Fetch { recipient } => {
            let records = state
                .saf_store
                .records_for(&recipient, now)
                .into_iter()
                .map(|r| SafRecordWire {
                    message_id: r.message_id,
                    recipient: r.recipient,
                    sender: r.sender,
                    blob: r.blob,
                    stored_at_ms: r.stored_at_ms,
                    ttl_ms: r.ttl_ms,
                })
                .collect();
            SafResponse::Records(records)
        }
        SafRequest::Ack { message_id, recipient, signature } => {
            // Only delete on a valid signature from the addressed recipient (§3.7.4).
            if let (Ok(rcpt), Ok(sig)) = (
                <[u8; 32]>::try_from(recipient.as_slice()),
                <[u8; 64]>::try_from(signature.as_slice()),
            ) {
                state.saf_store.ack(&message_id, &rcpt, &sig);
            }
            SafResponse::Acked
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
