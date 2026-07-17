package com.ep2pc.service

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Derives the 32-byte SQLCipher database key from a hardware-backed AES key held in the
 * Android Keystore (EP2PC-007 §7.2, §7.4). The raw key never leaves the secure element;
 * we use it via an HMAC to derive a stable DB key.
 */
object KeystoreKeys {
    private const val KEY_ALIAS = "ep2pc_master"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    fun getOrCreateDbKey(context: Context): ByteArray {
        val secret = getOrCreateMasterKey()
        // HMAC over a fixed label -> deterministic 32-byte DB key.
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(secret)
        return mac.doFinal("ep2pc.db.key.v1".toByteArray())
    }

    private fun getOrCreateMasterKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .build()
        )
        return generator.generateKey()
    }
}
