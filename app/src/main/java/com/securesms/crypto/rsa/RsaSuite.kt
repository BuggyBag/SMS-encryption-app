package com.securesms.crypto.rsa

import com.securesms.crypto.*
import com.securesms.crypto.symmetric.AesGcm
import com.securesms.crypto.symmetric.Hkdf
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * RSA hybrid encryption (any modulus size >= 1024 bits, chosen by the [Mode]): random 256-bit secret K is wrapped with RSA-OAEP (SHA-256, MGF1-SHA-256);
 * the AES-256-GCM key is HKDF(K, salt = session key). Identity signatures are RSA-PSS (SHA-256, 32-byte salt).
 * Public keys travel as X.509 SubjectPublicKeyInfo, private keys as PKCS#8.
 */
open class RsaSuiteImpl(override val mode: Mode) : Suite {
    init { require(mode.family == Family.RSA) { "not an RSA mode" } }
    private val BITS = mode.bits
    private val oaep = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)
    private val pss = PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
    private val info = "SSMS-v1 msg key ${mode.code}".toByteArray()

    private fun pub(b: ByteArray): RSAPublicKey = guard {
        (KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(b)) as? RSAPublicKey)
            ?: throw CryptoException("not an RSA key")
    }

    private fun priv(b: ByteArray) = guard { KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(b)) }

    override fun generateIdentity(t: Timings): Identity = guard {
        val g = KeyPairGenerator.getInstance("RSA"); g.initialize(BITS)
        val kp = t.t("IDENTITY_KEYGEN") { g.generateKeyPair() }
        Identity(kp.public.encoded, kp.private.encoded)
    }

    override fun validatePublic(pub: ByteArray) {
        val k = pub(pub)
        if (k.modulus.bitLength() != BITS) throw CryptoException("RSA modulus must be $BITS bits")
        if (k.publicExponent.bitLength() < 2) throw CryptoException("bad RSA exponent")
    }

    private fun pssSignature(): Signature = try {
        Signature.getInstance("RSASSA-PSS")
    } catch (_: java.security.NoSuchAlgorithmException) {
        Signature.getInstance("SHA256withRSA/PSS") // Android Conscrypt name
    }

    override fun sign(priv: ByteArray, data: ByteArray, t: Timings): ByteArray = guard {
        val k = priv(priv)
        t.t("SIGN") {
            val s = pssSignature()
            s.initSign(k)
            try { s.setParameter(pss) } catch (_: Exception) {}
            s.update(data)
            s.sign()
        }
    }

    override fun verify(pub: ByteArray, data: ByteArray, sig: ByteArray, t: Timings): Boolean = guard {
        val k = pub(pub)
        t.t("VERIFY") {
            try {
                val s = pssSignature()
                s.initVerify(k)
                try { s.setParameter(pss) } catch (_: Exception) {}
                s.update(data)
                s.verify(sig)
            } catch (_: java.security.SignatureException) { false }
        }
    }

    private fun rsaOaepCipher(): Cipher = try {
        Cipher.getInstance("RSA/ECB/OAEPPadding")
    } catch (_: java.security.NoSuchAlgorithmException) {
        Cipher.getInstance("RSA/ECB/OAEPwithSHA-256andMGF1Padding")
    }

    private fun wrap(pk: RSAPublicKey, data: ByteArray): ByteArray {
        val c = rsaOaepCipher()
        c.init(Cipher.ENCRYPT_MODE, pk, oaep)
        return c.doFinal(data)
    }

    private fun unwrap(k: java.security.PrivateKey, data: ByteArray): ByteArray {
        val c = rsaOaepCipher()
        c.init(Cipher.DECRYPT_MODE, k, oaep)
        return c.doFinal(data)
    }

    override fun seal(peerPub: ByteArray, sessionKey: ByteArray, plaintext: ByteArray, aad: ByteArray, t: Timings): Sealed = guard {
        val pk = pub(peerPub)
        val secret = Rng.bytes(32)
        val kem = t.t("RSA_ENCAP") { wrap(pk, secret) }
        val key = t.t("HKDF") { Hkdf.derive(secret, sessionKey, info, 32) }
        val r = t.t("AES_ENC") { AesGcm.encrypt(key, plaintext, aad) }
        Sealed(kem, r.nonce, r.ct, r.tag)
    }

    override fun open(myPriv: ByteArray, myPub: ByteArray, sessionKey: ByteArray, s: Sealed, aad: ByteArray, t: Timings): ByteArray = guard {
        val sk = priv(myPriv)
        val secret = t.t("RSA_DECAP") { try { unwrap(sk, s.kem) } catch (e: java.security.GeneralSecurityException) { throw CryptoException("RSA-OAEP unwrap failed", e) } }
        if (secret.size != 32) throw CryptoException("bad wrapped secret")
        val key = t.t("HKDF") { Hkdf.derive(secret, sessionKey, info, 32) }
        t.t("AES_DEC") { AesGcm.decrypt(key, s.nonce, s.ct, s.tag, aad) }
    }

    // Handshake: responder picks secret, wraps it to the initiator's RSA key.
    override fun hsRequest() = HsEphemeral(null, null)

    override fun hsRespond(initiatorPub: ByteArray, reqExtra: ByteArray?): HsResponse = guard {
        val secret = Rng.bytes(32)
        HsResponse(wrap(pub(initiatorPub), secret), secret)
    }

    override fun hsFinish(myPriv: ByteArray, myEphPriv: ByteArray?, respExtra: ByteArray): ByteArray = guard {
        try { unwrap(priv(myPriv), respExtra) } catch (e: java.security.GeneralSecurityException) { throw CryptoException("handshake unwrap failed", e) }
    }
}

/** The original 2048-bit suite (kept under its old name so existing code and tests still work). */
object RsaSuite : RsaSuiteImpl(Mode.RSA)
