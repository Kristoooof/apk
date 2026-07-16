package com.ep2pc.ui

import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.runtime.snapshots.SnapshotStateMap
import androidx.compose.runtime.toMutableStateList
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.ep2pc.core.MessageCodec
import com.ep2pc.core.NativeBridge
import kotlinx.coroutines.launch

data class Conversation(
    val id: String,
    val name: String,
    val lastMessage: String,
    val online: Boolean = false,
    val isGroup: Boolean = false
)
data class ChatMessage(val body: String, val mine: Boolean)

/**
 * Bridges the core event stream (`NativeBridge.events`) to observable UI state and turns UI
 * actions into core calls. Conversations are keyed by the peer's id (hex) — the same key the
 * core delivers on `onMessageReceived(peerId, …)` and expects on `sendMessage(peerId, …)`,
 * so a conversation is the other party's identity in both directions.
 */
class ChatViewModel : ViewModel() {

    val conversations: SnapshotStateList<Conversation> = mutableStateListOfConversations()
    private val messages: SnapshotStateMap<String, SnapshotStateList<ChatMessage>> = mutableStateMapOf()

    init {
        viewModelScope.launch {
            NativeBridge.events.collect { ev ->
                when (ev) {
                    is NativeBridge.CoreEvent.MessageReceived -> onIncoming(ev.peerId.toHex(), ev.envelope)
                    is NativeBridge.CoreEvent.ConnectionState -> onConnection(ev.peerId.toHex(), ev.connected)
                    is NativeBridge.CoreEvent.DeliveryStatus -> { /* map to per-message status later */ }
                }
            }
        }
    }

    fun messagesFor(conversationId: String): SnapshotStateList<ChatMessage> =
        messages.getOrPut(conversationId) { mutableStateListOfMessages() }

    /** Add (or surface) a conversation for a freshly scanned contact. */
    fun addContact(peerId: ByteArray, name: String): String {
        val id = peerId.toHex()
        if (conversations.none { it.id == id }) {
            conversations.add(0, Conversation(id, name, "Új kontakt – session létrehozva", isGroup = false))
        }
        return id
    }

    /** 1:1 contacts (32-byte ids), available to add to a group. */
    fun contacts(): List<Conversation> = conversations.filter { !it.isGroup }

    /** Create a group and surface it as a conversation. Returns its id (hex) or null. */
    fun createGroup(name: String): String? {
        val gid = NativeBridge.createGroup(name) ?: return null
        val id = gid.toHex()
        if (conversations.none { it.id == id }) {
            conversations.add(0, Conversation(id, name, "Csoport létrehozva", isGroup = true))
        }
        return id
    }

    /** Admin: add a 1:1 contact (by conversation id hex) to a group. */
    fun addMember(groupIdHex: String, memberIdHex: String): Boolean =
        NativeBridge.groupAdd(groupIdHex.hexToBytes(), memberIdHex.hexToBytes())

    fun send(conversationId: String, text: String) {
        if (text.isBlank()) return
        val id = conversationId.hexToBytes()
        val envelope = MessageCodec.encodeText(id, text)
        NativeBridge.sendMessage(id, envelope)
        messagesFor(conversationId).add(ChatMessage(text, mine = true))
        updateLast(conversationId, text)
    }

    private fun onIncoming(convId: String, envelope: ByteArray) {
        val decoded = MessageCodec.decode(envelope)
        val body = decoded.text ?: return // only text handled in the UI for now
        ensureConversation(convId)
        messagesFor(convId).add(ChatMessage(body, mine = false))
        updateLast(convId, body)
    }

    private fun onConnection(convId: String, connected: Boolean) {
        val i = conversations.indexOfFirst { it.id == convId }
        if (i >= 0) conversations[i] = conversations[i].copy(online = connected)
    }

    private fun ensureConversation(convId: String) {
        if (conversations.none { it.id == convId }) {
            // 16-byte (32 hex) ids are groups; 32-byte (64 hex) ids are 1:1 peers.
            val group = convId.length == 32
            val name = if (group) "Csoport " + convId.take(8) else "Peer " + convId.take(8)
            conversations.add(0, Conversation(convId, name, "", isGroup = group))
        }
    }

    private fun updateLast(convId: String, last: String) {
        val i = conversations.indexOfFirst { it.id == convId }
        if (i >= 0) conversations[i] = conversations[i].copy(lastMessage = last)
    }

    private fun mutableStateListOfConversations(): SnapshotStateList<Conversation> =
        ArrayList<Conversation>().toMutableStateList()

    private fun mutableStateListOfMessages(): SnapshotStateList<ChatMessage> =
        ArrayList<ChatMessage>().toMutableStateList()
}

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

internal fun String.hexToBytes(): ByteArray = try {
    check(length % 2 == 0)
    ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }
} catch (e: Exception) {
    ByteArray(0)
}
