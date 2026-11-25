package com.securesms.crypto

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom

/** Any cryptographic failure (bad key, bad signature, bad tag...). Always means "fail closed". */
class CryptoException(msg: String, cause: Throwable? = null) : Exception(msg, cause)

/** Malformed or unexpected protocol data. */
class ProtocolException(msg: String) : Exception(msg)

enum class Family { RSA, ECC }

/**
 * One mode = one algorithm family + one key size. [code] is the single character that travels in the frame header
 * (it must be unique and ASCII); [bits] is the RSA modulus size or the EC curve size.
 *
 * `RSA` (2048) and `ECC` (P-256) keep their original names and codes ('R', 'E'), so frames, saved state and tests
 * written for the 2-mode version keep working. The order below is the order shown in the spinners.
 *
 * Rough security equivalence (NIST SP 800-57): RSA-1024 ~ 80 bits (weak, kept only to compare with the papers),
 * RSA-2048 ~ 112, RSA-3072 ~ 128 ~ P-256, P-384 ~ 192, P-521 ~ 256.
 */
enum class Mode(val code: Char, val label: String, val family: Family, val bits: Int) {
    RSA1024('Q', "RSA-1024 (weak)", Family.RSA, 1024),
    RSA('R', "RSA-2048", Family.RSA, 2048),
    RSA3072('S', "RSA-3072", Family.RSA, 3072),
    RSA4096('T', "RSA-4096", Family.RSA, 4096),
    ECC('E', "ECC P-256", Family.ECC, 256),
    ECC384('F', "ECC P-384", Family.ECC, 384),
    ECC521('G', "ECC P-521", Family.ECC, 521);

    companion object {
        fun fromCode(c: Char): Mode? = entries.firstOrNull { it.code == c }
    }
}

object Rng {
    private val sr = SecureRandom()
    fun bytes(n: Int): ByteArray = ByteArray(n).also { sr.nextBytes(it) }
}

object Hex {
    fun enc(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
    fun dec(s: String): ByteArray {
        require(s.length % 2 == 0) { "odd hex length" }
        return ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    }
}

object B64 {
    fun enc(b: ByteArray): String = java.util.Base64.getEncoder().encodeToString(b)
    fun dec(s: String): ByteArray = try {
        java.util.Base64.getDecoder().decode(s)
    } catch (e: IllegalArgumentException) {
        throw ProtocolException("bad base64")
    }
}

object Sha256 {
    fun of(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        parts.forEach { md.update(it) }
        return md.digest()
    }
}

/** Length-prefixed (2 bytes) field list. Strict parser: any inconsistency throws. */
object Fields {
    const val MAX_FIELDS = 8
    fun pack(fields: List<ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        for (f in fields) {
            require(f.size <= 0xFFFF) { "field too large" }
            out.write(f.size shr 8); out.write(f.size and 0xFF); out.write(f)
        }
        return out.toByteArray()
    }

    fun unpack(b: ByteArray): List<ByteArray> {
        val res = ArrayList<ByteArray>()
        var i = 0
        while (i < b.size) {
            if (i + 2 > b.size) throw ProtocolException("truncated field header")
            val len = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
            i += 2
            if (i + len > b.size) throw ProtocolException("truncated field body")
            res.add(b.copyOfRange(i, i + len)); i += len
            if (res.size > MAX_FIELDS) throw ProtocolException("too many fields")
        }
        return res
    }
}

/** Human-comparable fingerprint: SHA-256 over (mode label || public key), grouped in 4-hex blocks. */
object Fingerprint {
    fun of(mode: Mode, pub: ByteArray): String =
        Hex.enc(Sha256.of(mode.label.toByteArray(), pub)).uppercase().chunked(4).joinToString(" ")
}
