package com.ep2pc.core

import java.security.SecureRandom

/**
 * Builds and parses the plaintext application `Envelope` (EP2PC-005 §5.4) that the UI hands
 * to / receives from the core. The core encrypts/decrypts these bytes with the Double
 * Ratchet; it never inspects them, so this codec is the sole owner of the plaintext shape.
 *
 * Envelope fields (must match ep2pc-proto): 1=message_id(bytes), 2=type(varint),
 * 3=conversation_id(bytes), 4=timestamp(varint), 5=payload(bytes).
 * TextPayload: 1=body(string). MessageType.Text = 1.
 */
object MessageCodec {

    private const val TYPE_TEXT = 1L
    private val rng = SecureRandom()

    data class Incoming(val type: Int, val text: String?)

    /** Encode a text message as an Envelope wrapping a TextPayload. */
    fun encodeText(conversationId: ByteArray, body: String): ByteArray {
        val payload = ProtoWire.Writer()
            .stringField(1, body)
            .toByteArray()
        val messageId = ByteArray(16).also { rng.nextBytes(it) }
        return ProtoWire.Writer()
            .bytesField(1, messageId)
            .varintField(2, TYPE_TEXT)
            .bytesField(3, conversationId)
            .varintField(4, System.currentTimeMillis())
            .bytesField(5, payload)
            .toByteArray()
    }

    /** Parse an incoming Envelope; returns the message type and (for TEXT) the body. */
    fun decode(envelope: ByteArray): Incoming {
        var type = 0
        var payload: ByteArray? = null
        for (f in ProtoWire.Reader(envelope).fields()) {
            when (f.number) {
                2 -> type = f.varint.toInt()
                5 -> payload = f.bytes
            }
        }
        val text = if (type == TYPE_TEXT.toInt() && payload != null) {
            var body: String? = null
            for (f in ProtoWire.Reader(payload).fields()) {
                if (f.number == 1 && f.bytes != null) body = String(f.bytes, Charsets.UTF_8)
            }
            body
        } else null
        return Incoming(type, text)
    }
}
