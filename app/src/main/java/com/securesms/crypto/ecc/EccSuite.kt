package com.securesms.crypto.ecc

import com.securesms.crypto.*
import com.securesms.crypto.Identity
import com.securesms.crypto.symmetric.AesGcm
import com.securesms.crypto.symmetric.Hkdf
import java.math.BigInteger
import java.security.*
import java.security.interfaces.ECPublicKey
import java.security.spec.*
import javax.crypto.KeyAgreement

/**
 * NIST P-256 / P-384 / P-521 (chosen by the [Mode]). Identity key: ECDSA (signatures) and static ECDH target. Messages use ephemeral-static ECDH:
 * sender makes a fresh ephemeral key, shared secret -> HKDF-SHA-256(salt = session key, info binds both public keys) -> AES-256-GCM.
 * Public keys travel as uncompressed points (1 + 2*coordinate bytes: 65 for P-256, 97 for P-384, 133 for P-521); every received point is validated to lie on the curve.
 */
open class EccSuiteImpl(override val mode: Mode) : Suite {
    private val curveName: String
    private val sigAlg: String          // hash matched to the curve size
    private val coordLen: Int           // bytes per coordinate

    init {
        require(mode.family == Family.ECC) { "not an ECC mode" }
        when (mode.bits) {
            256 -> { curveName = "secp256r1"; sigAlg = "SHA256withECDSA" }
            384 -> { curveName = "secp384r1"; sigAlg = "SHA384withECDSA" }
            521 -> { curveName = "secp521r1"; sigAlg = "SHA512withECDSA" }
            else -> throw IllegalArgumentException("unsupported curve size ${mode.bits}")
        }
        coordLen = (mode.bits + 7) / 8
    }

    private val params: ECParameterSpec by lazy {
        val ap = AlgorithmParameters.getInstance("EC"); ap.init(ECGenParameterSpec(curveName))
        ap.getParameterSpec(ECParameterSpec::class.java)
    }
    private val p get() = (params.curve.field as ECFieldFp).p

    private fun kpg() = KeyPairGenerator.getInstance("EC").also { it.initialize(ECGenParameterSpec(curveName)) }

    private fun fixed(v: BigInteger): ByteArray {
        val b = v.toByteArray()
        val out = ByteArray(coordLen)
        val src = if (b.size > coordLen) b.copyOfRange(b.size - coordLen, b.size) else b
        System.arraycopy(src, 0, out, coordLen - src.size, src.size)
        return out
    }

    fun encodePub(k: ECPublicKey): ByteArray = byteArrayOf(4) + fixed(k.w.affineX) + fixed(k.w.affineY)

    fun decodePub(raw: ByteArray): ECPublicKey = guard {
        if (raw.size != 1 + 2 * coordLen || raw[0] != 4.toByte()) throw CryptoException("bad EC point encoding")
        val x = BigInteger(1, raw.copyOfRange(1, 1 + coordLen)); val y = BigInteger(1, raw.copyOfRange(1 + coordLen, raw.size))
        if (x >= p || y >= p) throw CryptoException("EC coordinate out of range")
        val lhs = y.multiply(y).mod(p)
        val rhs = x.pow(3).add(params.curve.a.multiply(x)).add(params.curve.b).mod(p)
        if (lhs != rhs) throw CryptoException("EC point is not on ${mode.label}")
        KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params)) as ECPublicKey
    }

    private fun priv(b: ByteArray) = guard { KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(b)) }

    private fun ecdh(priv: PrivateKey, pub: ECPublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("ECDH"); ka.init(priv); ka.doPhase(pub, true); return ka.generateSecret()
    }

    private fun info(ephRaw: ByteArray, recipientPub: ByteArray) = "SSMS-v1 msg key ${mode.code}".toByteArray() + ephRaw + recipientPub

    override fun generateIdentity(t: Timings): Identity = guard {
        val kp = t.t("IDENTITY_KEYGEN") { kpg().generateKeyPair() }
        Identity(encodePub(kp.public as ECPublicKey), kp.private.encoded)
    }

    override fun validatePublic(pub: ByteArray) { decodePub(pub) }

    override fun sign(priv: ByteArray, data: ByteArray, t: Timings): ByteArray = guard {
        val k = priv(priv)
        t.t("SIGN") { Signature.getInstance(sigAlg).let { it.initSign(k); it.update(data); it.sign() } }
    }

    override fun verify(pub: ByteArray, data: ByteArray, sig: ByteArray, t: Timings): Boolean = guard {
        val k = decodePub(pub)
        t.t("VERIFY") {
            try { Signature.getInstance(sigAlg).let { it.initVerify(k); it.update(data); it.verify(sig) } }
            catch (e: SignatureException) { false }
        }
    }

    override fun seal(peerPub: ByteArray, sessionKey: ByteArray, plaintext: ByteArray, aad: ByteArray, t: Timings): Sealed = guard {
        val pk = decodePub(peerPub)
        val eph = t.t("KEYGEN_EPHEMERAL") { kpg().generateKeyPair() }
        val ephRaw = encodePub(eph.public as ECPublicKey)
        val secret = t.t("ECDH") { ecdh(eph.private, pk) }
        val key = t.t("HKDF") { Hkdf.derive(secret, sessionKey, info(ephRaw, peerPub), 32) }
        val r = t.t("AES_ENC") { AesGcm.encrypt(key, plaintext, aad) }
        Sealed(ephRaw, r.nonce, r.ct, r.tag)
    }

    override fun open(myPriv: ByteArray, myPub: ByteArray, sessionKey: ByteArray, s: Sealed, aad: ByteArray, t: Timings): ByteArray = guard {
        val ephPk = decodePub(s.kem)
        val sk = priv(myPriv)
        val secret = t.t("ECDH") { ecdh(sk, ephPk) }
        val key = t.t("HKDF") { Hkdf.derive(secret, sessionKey, info(s.kem, myPub), 32) }
        t.t("AES_DEC") { AesGcm.decrypt(key, s.nonce, s.ct, s.tag, aad) }
    }

    // Handshake: ephemeral-ephemeral ECDH (forward secret session key).
    override fun hsRequest(): HsEphemeral = guard {
        val kp = kpg().generateKeyPair(); HsEphemeral(encodePub(kp.public as ECPublicKey), kp.private.encoded)
    }

    override fun hsRespond(initiatorPub: ByteArray, reqExtra: ByteArray?): HsResponse = guard {
        val theirEph = decodePub(reqExtra ?: throw CryptoException("missing ephemeral key"))
        val kp = kpg().generateKeyPair()
        HsResponse(encodePub(kp.public as ECPublicKey), ecdh(kp.private, theirEph))
    }

    override fun hsFinish(myPriv: ByteArray, myEphPriv: ByteArray?, respExtra: ByteArray): ByteArray = guard {
        ecdh(priv(myEphPriv ?: throw CryptoException("missing ephemeral private key")), decodePub(respExtra))
    }
}

/** The original P-256 suite (kept under its old name so existing code and tests still work). */
object EccSuite : EccSuiteImpl(Mode.ECC)
