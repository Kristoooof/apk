package com.ep2pc.ui

import android.graphics.Bitmap
import android.graphics.Color
import android.util.Base64
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/**
 * QR helpers for contact exchange (EP2PC-003 §3.3).
 *
 * The QR carries the 160-byte prekey bundle, Base64 (URL-safe, no wrap) encoded so it fits
 * in a QR payload. Scanning reverses it, then [NativeBridge.addContact] derives the PeerId
 * and starts the session. Nothing secret is in the QR — only public identity + signed
 * prekey; the signature is verified inside the core before a session is created.
 */
object QrCodec {

    private const val B64 = Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING

    fun encodeBundle(bundle: ByteArray): String = Base64.encodeToString(bundle, B64)

    fun decodeBundle(text: String): ByteArray? = try {
        Base64.decode(text.trim(), B64).takeIf { it.size == 160 }
    } catch (e: IllegalArgumentException) {
        null
    }

    /** Render [text] as a square QR [Bitmap] of [size] px. */
    fun qrBitmap(text: String, size: Int = 720): Bitmap {
        val hints = mapOf(
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
            EncodeHintType.MARGIN to 1
        )
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
        val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.RGB_565)
        for (x in 0 until size) {
            for (y in 0 until size) {
                bmp.setPixel(x, y, if (matrix[x, y]) Color.BLACK else Color.WHITE)
            }
        }
        return bmp
    }
}
