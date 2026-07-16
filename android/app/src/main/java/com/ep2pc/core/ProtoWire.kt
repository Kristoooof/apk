package com.ep2pc.core

import java.io.ByteArrayOutputStream

/**
 * A tiny protobuf (proto3) writer/reader — just enough for the EP2PC `Envelope` and
 * `TextPayload` messages (EP2PC-005 §5.4). This produces bytes that are wire-compatible with
 * the Rust `ep2pc-proto` structs, so the plaintext the UI hands to the core is a real
 * application Envelope. Keeping it hand-rolled avoids pulling a protoc toolchain into the
 * Android build for two message shapes.
 *
 * Wire types used: 0 = varint, 2 = length-delimited (bytes/string).
 */
object ProtoWire {

    class Writer {
        private val out = ByteArrayOutputStream()

        fun varintField(field: Int, value: Long): Writer {
            writeTag(field, 0)
            writeVarint(value)
            return this
        }

        fun bytesField(field: Int, value: ByteArray): Writer {
            if (value.isEmpty()) return this // proto3 omits empty
            writeTag(field, 2)
            writeVarint(value.size.toLong())
            out.write(value)
            return this
        }

        fun stringField(field: Int, value: String): Writer =
            bytesField(field, value.toByteArray(Charsets.UTF_8))

        fun toByteArray(): ByteArray = out.toByteArray()

        private fun writeTag(field: Int, wireType: Int) = writeVarint(((field shl 3) or wireType).toLong())

        private fun writeVarint(v: Long) {
            var value = v
            while (true) {
                val b = (value and 0x7F).toInt()
                value = value ushr 7
                if (value == 0L) {
                    out.write(b)
                    break
                } else {
                    out.write(b or 0x80)
                }
            }
        }
    }

    /** A decoded field: either a varint or a length-delimited byte slice. */
    class Reader(private val buf: ByteArray) {
        private var pos = 0

        data class Field(val number: Int, val wireType: Int, val varint: Long, val bytes: ByteArray?)

        fun fields(): List<Field> {
            val result = ArrayList<Field>()
            while (pos < buf.size) {
                val tag = readVarint()
                val number = (tag ushr 3).toInt()
                val wireType = (tag and 0x7).toInt()
                when (wireType) {
                    0 -> result.add(Field(number, 0, readVarint(), null))
                    2 -> {
                        val len = readVarint().toInt()
                        val slice = buf.copyOfRange(pos, pos + len)
                        pos += len
                        result.add(Field(number, 2, 0, slice))
                    }
                    5 -> { pos += 4; result.add(Field(number, 5, 0, null)) } // fixed32 (unused)
                    1 -> { pos += 8; result.add(Field(number, 1, 0, null)) } // fixed64 (unused)
                    else -> break
                }
            }
            return result
        }

        private fun readVarint(): Long {
            var shift = 0
            var result = 0L
            while (true) {
                val b = buf[pos++].toInt() and 0xFF
                result = result or ((b and 0x7F).toLong() shl shift)
                if (b and 0x80 == 0) break
                shift += 7
            }
            return result
        }
    }
}
