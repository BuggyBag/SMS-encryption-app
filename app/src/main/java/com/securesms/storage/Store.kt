package com.securesms.storage

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

/** Encrypts/decrypts the persisted blob. Android: AES-256-GCM key held in Android Keystore. */
interface Vault {
    fun seal(plain: ByteArray): ByteArray
    fun open(blob: ByteArray): ByteArray
}

interface Blob {
    fun read(): ByteArray?
    fun write(data: ByteArray)
}

/**
 * The whole application state (identity keys, sessions, messages, measurements) is one object graph,
 * serialized and encrypted+authenticated by the [Vault] before it touches disk.
 * If an existing file cannot be decrypted we refuse to overwrite it (loadError != null).
 */
class Store(private val vault: Vault, private val blob: Blob) {
    var state = State()
        private set
    var loadError: String? = null
        private set

    init {
        val raw = blob.read()
        if (raw != null) {
            try {
                ObjectInputStream(ByteArrayInputStream(vault.open(raw))).use { state = it.readObject() as State }
            } catch (e: Exception) {
                loadError = "Stored data could not be decrypted: ${e.message}"
            }
        }
    }

    @Synchronized
    fun save() {
        check(loadError == null) { loadError!! }
        val bos = ByteArrayOutputStream()
        ObjectOutputStream(bos).use { it.writeObject(state) }
        blob.write(vault.seal(bos.toByteArray()))
    }
}
