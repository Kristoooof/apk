package com.ep2pc.core

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

/**
 * Kotlin <-> Rust boundary (EP2PC-008 §8.4).
 *
 * All calls are non-blocking. Incoming events from the Rust core arrive on the
 * [EP2PCEventCallback] (invoked from a native dispatch thread) and are re-published as a
 * [SharedFlow] the UI subscribes to. Only serialized protobuf byte arrays cross the
 * boundary — never raw key material (EP2PC-004 §4.10).
 */
object NativeBridge {

    init {
        System.loadLibrary("ep2pc_ffi")
    }

    /** Events surfaced to the UI layer. */
    sealed interface CoreEvent {
        data class MessageReceived(val peerId: ByteArray, val envelope: ByteArray) : CoreEvent
        data class DeliveryStatus(val messageId: ByteArray, val status: Int) : CoreEvent
        data class ConnectionState(val peerId: ByteArray, val connected: Boolean) : CoreEvent
    }

    private val _events = MutableSharedFlow<CoreEvent>(extraBufferCapacity = 128)
    val events: SharedFlow<CoreEvent> = _events.asSharedFlow()

    private val callback = object : EP2PCEventCallback {
        override fun onMessageReceived(peerId: ByteArray, envelope: ByteArray) {
            _events.tryEmit(CoreEvent.MessageReceived(peerId, envelope))
        }
        override fun onDeliveryStatusChanged(messageId: ByteArray, status: Int) {
            _events.tryEmit(CoreEvent.DeliveryStatus(messageId, status))
        }
        override fun onConnectionStateChanged(peerId: ByteArray, connected: Boolean) {
            _events.tryEmit(CoreEvent.ConnectionState(peerId, connected))
        }
    }

    @Volatile private var started = false

    /** Start the Rust core. [dbKey] comes from the Android Keystore (EP2PC-007 §7.2).
     *  [relayAddr] is the VPS relay/bootstrap multiaddr from Settings (may be empty). */
    fun start(dbPath: String, dbKey: ByteArray, relayAddr: String) {
        if (started) return
        nativeInit(callback, dbPath, dbKey, relayAddr)
        started = true
    }

    fun sendMessage(conversationId: ByteArray, plaintextEnvelope: ByteArray) =
        nativeSendMessage(conversationId, plaintextEnvelope)

    /** Our 160-byte prekey bundle to render as a QR code (EP2PC-003 §3.3). */
    fun myBundle(): ByteArray = nativeMyBundle()

    /**
     * Add a scanned contact and start an outbound session (EP2PC-004 §4.4). [bundle] is the
     * 160-byte payload decoded from their QR code. Returns the contact's PeerId (use it as
     * the conversation id) or null on failure.
     */
    fun addContact(bundle: ByteArray): ByteArray? =
        nativeAddContact(bundle).takeIf { it.isNotEmpty() }

    /** Create a group; returns its 16-byte id (EP2PC-006 §6.5). */
    fun createGroup(name: String): ByteArray? =
        nativeCreateGroup(name).takeIf { it.isNotEmpty() }

    /** Admin: add a member (their 32-byte Ed25519 key) to a group. */
    fun groupAdd(groupId: ByteArray, memberEd25519: ByteArray): Boolean =
        nativeGroupAdd(groupId, memberEd25519)

    /** Admin: remove a member from a group (triggers mandatory key rotation). */
    fun groupRemove(groupId: ByteArray, memberEd25519: ByteArray): Boolean =
        nativeGroupRemove(groupId, memberEd25519)

    // --- native declarations (implemented in core/ffi) ---
    private external fun nativeInit(
        callback: EP2PCEventCallback,
        dbPath: String,
        dbKey: ByteArray,
        relayAddr: String
    ): Long

    // The core encrypts the plaintext Envelope with the peer's Double Ratchet session
    // before it touches the network (EP2PC-002 §2.2, EP2PC-004).
    private external fun nativeSendMessage(conversationId: ByteArray, plaintextEnvelope: ByteArray)

    private external fun nativeMyBundle(): ByteArray
    private external fun nativeAddContact(bundle: ByteArray): ByteArray
    private external fun nativeCreateGroup(name: String): ByteArray
    private external fun nativeGroupAdd(groupId: ByteArray, memberEd25519: ByteArray): Boolean
    private external fun nativeGroupRemove(groupId: ByteArray, memberEd25519: ByteArray): Boolean
}

/** Callback interface invoked by the Rust core (EP2PC-008 §8.4, Rust→Kotlin). */
interface EP2PCEventCallback {
    fun onMessageReceived(peerId: ByteArray, envelope: ByteArray)
    fun onDeliveryStatusChanged(messageId: ByteArray, status: Int)
    fun onConnectionStateChanged(peerId: ByteArray, connected: Boolean)
}
