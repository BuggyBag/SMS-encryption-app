package com.securesms.protocol

import com.securesms.crypto.*

enum class Type(val code: String) {
    KEY_REQUEST("KQ"), KEY_RESPONSE("KR"), KEY_CONFIRM("KC"),
    SECURE_MESSAGE("SM"), KEY_UPDATE("KU"), ERROR("ER");

    companion object { fun fromCode(c: String) = entries.firstOrNull { it.code == c } }
}

/**
 * Wire format (all ASCII, GSM-7 safe):
 *   SSMS|<version>|<mode R/E>|<type>|<sessionId 16 hex>|<msgId hex>|<base64(fields... , signature)>
 * The signature (last field; absent for ERROR) covers: the header text up to and including the final '|',
 * the packed preceding fields, and any transcript bytes the type adds (see [signedBytes]).
 * For SECURE_MESSAGE the header is also the AES-GCM associated data.
 */
class Frame(
    val mode: Mode, val type: Type, val sessionId: String, val msgId: Long,
    val fields: List<ByteArray>, val sig: ByteArray? = null,
) {
    companion object {
        const val VERSION = 1
        const val MAGIC = "SSMS"
        const val MAX_WIRE = 4000
        private val SID = Regex("[0-9a-f]{16}")

        fun header(mode: Mode, type: Type, sid: String, mid: Long) =
            "$MAGIC|$VERSION|${mode.code}|${type.code}|$sid|${mid.toString(16)}|"

        fun newSessionId() = Hex.enc(Rng.bytes(8))

        fun parse(wire: String): Frame {
            if (wire.length > MAX_WIRE) throw ProtocolException("frame too large")
            val p = wire.split('|', limit = 7)
            if (p.size != 7 || p[0] != MAGIC) throw ProtocolException("not a SecureSMS frame")
            if (p[1] != VERSION.toString()) throw ProtocolException("unsupported version ${p[1]}")
            val mode = p[2].singleOrNull()?.let { Mode.fromCode(it) } ?: throw ProtocolException("unknown mode")
            val type = Type.fromCode(p[3]) ?: throw ProtocolException("unknown type")
            if (!SID.matches(p[4])) throw ProtocolException("bad session id")
            val mid = p[5].takeIf { it.length in 1..15 && it.all { c -> c in '0'..'9' || c in 'a'..'f' } }
                ?.toLong(16) ?: throw ProtocolException("bad message id")
            val all = Fields.unpack(B64.dec(p[6]))
            return if (type == Type.ERROR) Frame(mode, type, p[4], mid, all)
            else {
                if (all.size < 2) throw ProtocolException("missing signature")
                Frame(mode, type, p[4], mid, all.dropLast(1), all.last())
            }
        }
    }

    fun header() = header(mode, type, sessionId, msgId)

    /** Bytes that are signed: header || packed fields || extra transcript (hashes of earlier handshake frames). */
    fun signedBytes(extra: ByteArray = ByteArray(0)): ByteArray = header().toByteArray() + Fields.pack(fields) + extra

    fun signed(sig: ByteArray) = Frame(mode, type, sessionId, msgId, fields, sig)

    fun encode(): String = header() + B64.enc(Fields.pack(if (sig != null) fields + sig else fields))
}
