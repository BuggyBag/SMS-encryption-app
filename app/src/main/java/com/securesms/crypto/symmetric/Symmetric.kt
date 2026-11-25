package com.securesms.crypto.symmetric

import com.securesms.crypto.CryptoException
import com.securesms.crypto.Rng
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** RFC 5869 HKDF-SHA-256 built on the platform HMAC (no hand-written primitives). */
object Hkdf {
    fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
        parts.forEach { mac.update(it) }
        return mac.doFinal()
    }

    fun derive(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * 32)
        val prk = hmac(salt, ikm)
        val out = java.io.ByteArrayOutputStream()
        var t = ByteArray(0)
        var i = 1
        while (out.size() < length) {
            t = hmac(prk, t, info, byteArrayOf(i.toByte()))
            out.write(t); i++
        }
        return out.toByteArray().copyOf(length)
    }
}

class AesResult(val nonce: ByteArray, val ct: ByteArray, val tag: ByteArray)

/** AES-256-GCM, 96-bit random nonce, 128-bit tag. The same code is used by RSA and ECC modes. */
object AesGcm {
    const val NONCE = 12
    const val TAG = 16

    fun encrypt(key: ByteArray, plaintext: ByteArray, aad: ByteArray): AesResult {
        if (key.size != 32) throw CryptoException("AES key must be 256 bits")
        try {
            val nonce = Rng.bytes(NONCE)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG * 8, nonce))
            c.updateAAD(aad)
            val out = c.doFinal(plaintext)
            return AesResult(nonce, out.copyOfRange(0, out.size - TAG), out.copyOfRange(out.size - TAG, out.size))
        } catch (e: GeneralSecurityException) {
            throw CryptoException("AES-GCM encryption failed", e)
        }
    }

    fun decrypt(key: ByteArray, nonce: ByteArray, ct: ByteArray, tag: ByteArray, aad: ByteArray): ByteArray {
        if (key.size != 32 || nonce.size != NONCE || tag.size != TAG) throw CryptoException("bad AES-GCM parameters")
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG * 8, nonce))
            c.updateAAD(aad)
            return c.doFinal(ct + tag)
        } catch (e: GeneralSecurityException) {
            throw CryptoException("authentication failed (bad tag or modified data)", e)
        }
    }
}
