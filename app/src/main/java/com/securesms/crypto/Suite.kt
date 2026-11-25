package com.securesms.crypto

import java.io.Serializable

class Identity(val pub: ByteArray, val priv: ByteArray) : Serializable {
    companion object {
        private const val serialVersionUID = 1L
    }
}

/** Per-message hybrid-encryption output. [kem] = RSA-OAEP(K) for RSA mode, ephemeral EC point for ECC mode. */
class Sealed(val kem: ByteArray, val nonce: ByteArray, val ct: ByteArray, val tag: ByteArray)

class HsResponse(val extra: ByteArray, val secret: ByteArray)
class HsEphemeral(val pub: ByteArray?, val priv: ByteArray?)

class Sample(
    val ts: Long, val source: String, val mode: Mode, val side: String, val op: String,
    val nanos: Long, val msgBytes: Int, val iteration: Int, val device: String,
) : Serializable {
    companion object {
        private const val serialVersionUID = 1L
    }
}

/** Records elapsed time with the monotonic System.nanoTime() clock. */
class Timings {
    val ns = LinkedHashMap<String, Long>()
    inline fun <T> t(name: String, block: () -> T): T {
        val s = System.nanoTime()
        try {
            return block()
        } finally {
            ns[name] = (ns[name] ?: 0L) + (System.nanoTime() - s)
        }
    }
}

inline fun <T> guard(block: () -> T): T = try {
    block()
} catch (e: CryptoException) {
    throw e
} catch (e: java.security.GeneralSecurityException) {
    throw CryptoException(e.message ?: "crypto error", e)
} catch (e: IllegalArgumentException) {
    throw CryptoException(e.message ?: "bad argument", e)
}

interface Suite {
    val mode: Mode
    fun generateIdentity(t: Timings = Timings()): Identity
    fun validatePublic(pub: ByteArray)
    fun sign(priv: ByteArray, data: ByteArray, t: Timings = Timings()): ByteArray
    fun verify(pub: ByteArray, data: ByteArray, sig: ByteArray, t: Timings = Timings()): Boolean

    /** Hybrid encryption of one message to the peer's pinned identity key. */
    fun seal(peerPub: ByteArray, sessionKey: ByteArray, plaintext: ByteArray, aad: ByteArray, t: Timings = Timings()): Sealed
    fun open(myPriv: ByteArray, myPub: ByteArray, sessionKey: ByteArray, s: Sealed, aad: ByteArray, t: Timings = Timings()): ByteArray

    // Handshake secret agreement (KEY_REQUEST / KEY_RESPONSE)
    fun hsRequest(): HsEphemeral
    fun hsRespond(initiatorPub: ByteArray, reqExtra: ByteArray?): HsResponse
    fun hsFinish(myPriv: ByteArray, myEphPriv: ByteArray?, respExtra: ByteArray): ByteArray
}
