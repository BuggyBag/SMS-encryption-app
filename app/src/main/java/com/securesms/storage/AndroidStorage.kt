package com.securesms.storage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * AES-256-GCM key generated inside the Android Keystore (hardware-backed where the device supports it).
 * It encrypts the serialized application state, which is where the identity private keys live.
 * (Identity keys themselves are software JCA keys because Keystore RSA-OAEP with SHA-256 MGF1 and
 *  Keystore ECDH-as-static-key are not uniformly supported on API 26-33; see README.)
 */
class AndroidVault : Vault {
    private val alias = "securesms_vault_v1"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return kg.generateKey()
    }

    override fun seal(plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        return c.iv + c.doFinal(plain)
    }

    override fun open(blob: ByteArray): ByteArray {
        require(blob.size >= 28) { "Encrypted blob is too short" }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
        return c.doFinal(blob, 12, blob.size - 12)
    }
}

class FileBlob(private val file: File) : Blob {
    override fun read(): ByteArray? = if (file.exists()) file.readBytes() else null
    override fun write(data: ByteArray) {
        val parent = file.parentFile
        if (parent != null && !parent.exists()) parent.mkdirs()
        val tmp = File(parent, file.name + ".tmp")
        tmp.writeBytes(data)
        if (file.exists()) {
            val backup = File(parent, file.name + ".bak")
            file.renameTo(backup)
            if (tmp.renameTo(file)) {
                backup.delete()
            } else {
                backup.renameTo(file)
                throw IllegalStateException("Could not replace state file")
            }
        } else {
            check(tmp.renameTo(file)) { "Could not write state file" }
        }
    }
}
