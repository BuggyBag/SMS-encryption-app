package com.securesms

import com.securesms.crypto.*
import com.securesms.crypto.ecc.EccSuite
import com.securesms.crypto.rsa.RsaSuite
import com.securesms.crypto.symmetric.AesGcm
import com.securesms.crypto.symmetric.Hkdf
import com.securesms.protocol.Frame
import com.securesms.protocol.Type
import com.securesms.storage.Session
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator

fun expectFail(block: () -> Unit) {
    try { block() } catch (e: Exception) { return }
    fail("expected an exception")
}

class CryptoTest {
    private val sessionKey = ByteArray(32) { it.toByte() }
    private val aad = "SSMS|1|R|SM|0011223344556677|1|".toByteArray()
    private val pt = "héllo wörld 你好".toByteArray()

    @Test fun hkdfMatchesRfc5869TestCase1() {
        val ikm = Hex.dec("0b".repeat(22)); val salt = Hex.dec("000102030405060708090a0b0c"); val info = Hex.dec("f0f1f2f3f4f5f6f7f8f9")
        val okm = Hkdf.derive(ikm, salt, info, 42)
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", Hex.enc(okm))
    }

    @Test fun aesGcmRoundTripAndTamperDetection() {
        val key = Rng.bytes(32)
        val r = AesGcm.encrypt(key, pt, aad)
        assertArrayEquals(pt, AesGcm.decrypt(key, r.nonce, r.ct, r.tag, aad))
        expectFail { AesGcm.decrypt(key, r.nonce, r.ct, r.tag.also { it[0] = (it[0].toInt() xor 1).toByte() }, aad) }
        val r2 = AesGcm.encrypt(key, pt, aad)
        expectFail { AesGcm.decrypt(key, r2.nonce, r2.ct.also { it[0] = (it[0].toInt() xor 1).toByte() }, r2.tag, aad) }
        val r3 = AesGcm.encrypt(key, pt, aad)
        expectFail { AesGcm.decrypt(key, r3.nonce, r3.ct, r3.tag, "other".toByteArray()) }
        expectFail { AesGcm.decrypt(Rng.bytes(32), r3.nonce, r3.ct, r3.tag, aad) }
    }

    @Test fun rsaKeyGenerationIs2048Bit() {
        val id = RsaSuite.generateIdentity()
        RsaSuite.validatePublic(id.pub)
        val g = KeyPairGenerator.getInstance("RSA"); g.initialize(1024)
        expectFail { RsaSuite.validatePublic(g.generateKeyPair().public.encoded) }
        expectFail { RsaSuite.validatePublic(ByteArray(10)) }
    }

    @Test fun rsaOaepEncapsulationRoundTrip() {
        val id = RsaSuite.generateIdentity(); val other = RsaSuite.generateIdentity()
        val s = RsaSuite.seal(id.pub, sessionKey, pt, aad)
        assertEquals(256, s.kem.size)
        assertArrayEquals(pt, RsaSuite.open(id.priv, id.pub, sessionKey, s, aad))
        expectFail { RsaSuite.open(other.priv, other.pub, sessionKey, s, aad) }
        expectFail { RsaSuite.open(id.priv, id.pub, Rng.bytes(32), s, aad) }          // wrong session key
        expectFail { RsaSuite.open(id.priv, id.pub, sessionKey, Sealed(s.kem.also { it[5] = (it[5].toInt() xor 1).toByte() }, s.nonce, s.ct, s.tag), aad) }
    }

    @Test fun rsaPssSignatures() {
        val id = RsaSuite.generateIdentity(); val data = "transcript".toByteArray()
        val sig = RsaSuite.sign(id.priv, data)
        assertTrue(RsaSuite.verify(id.pub, data, sig))
        assertFalse(RsaSuite.verify(id.pub, "transcripu".toByteArray(), sig))
        assertFalse(RsaSuite.verify(RsaSuite.generateIdentity().pub, data, sig))
        assertFalse(RsaSuite.verify(id.pub, data, sig.also { it[10] = (it[10].toInt() xor 1).toByte() }))
        assertNotEquals(Hex.enc(sig), Hex.enc(RsaSuite.sign(id.priv, data)))        // PSS is randomized
    }

    @Test fun eccKeyGenerationAndPointValidation() {
        val id = EccSuite.generateIdentity()
        assertEquals(65, id.pub.size); EccSuite.validatePublic(id.pub)
        expectFail { EccSuite.validatePublic(id.pub.copyOf().also { it[64] = (it[64].toInt() xor 1).toByte() }) } // off-curve
        expectFail { EccSuite.validatePublic(id.pub.copyOf(64)) }
        expectFail { EccSuite.validatePublic(ByteArray(65)) }
    }

    @Test fun ecdhSharedSecretAgreement() {
        val a = EccSuite.generateIdentity()
        val req = EccSuite.hsRequest()
        val resp = EccSuite.hsRespond(a.pub, req.pub)
        val fin = EccSuite.hsFinish(a.priv, req.priv, resp.extra)
        assertArrayEquals(resp.secret, fin)
        assertEquals(32, fin.size)
    }

    @Test fun rsaHandshakeSecretAgreement() {
        val a = RsaSuite.generateIdentity()
        val resp = RsaSuite.hsRespond(a.pub, null)
        assertArrayEquals(resp.secret, RsaSuite.hsFinish(a.priv, null, resp.extra))
    }

    @Test fun ecdsaSignatures() {
        val id = EccSuite.generateIdentity(); val data = "transcript".toByteArray()
        val sig = EccSuite.sign(id.priv, data)
        assertTrue(EccSuite.verify(id.pub, data, sig))
        assertFalse(EccSuite.verify(id.pub, "x".toByteArray(), sig))
        assertFalse(EccSuite.verify(EccSuite.generateIdentity().pub, data, sig))
        assertFalse(EccSuite.verify(id.pub, data, sig.also { it[sig.size - 1] = (it[sig.size - 1].toInt() xor 1).toByte() }))
    }

    @Test fun eccEphemeralStaticHybridRoundTrip() {
        val id = EccSuite.generateIdentity()
        val s1 = EccSuite.seal(id.pub, sessionKey, pt, aad); val s2 = EccSuite.seal(id.pub, sessionKey, pt, aad)
        assertNotEquals(Hex.enc(s1.kem), Hex.enc(s2.kem))                           // fresh ephemeral each time
        assertArrayEquals(pt, EccSuite.open(id.priv, id.pub, sessionKey, s1, aad))
        expectFail { EccSuite.open(id.priv, id.pub, Rng.bytes(32), s1, aad) }
        expectFail { EccSuite.open(id.priv, id.pub, sessionKey, Sealed(s1.kem, s1.nonce, s1.ct.also { it[0] = (it[0].toInt() xor 1).toByte() }, s1.tag), aad) }
        val other = EccSuite.generateIdentity()
        expectFail { EccSuite.open(other.priv, other.pub, sessionKey, s1, aad) }
    }

    @Test fun timingsAreRecordedPerOperation() {
        val t = Timings(); val id = EccSuite.generateIdentity()
        EccSuite.seal(id.pub, sessionKey, pt, aad, t)
        assertEquals(setOf("KEYGEN_EPHEMERAL", "ECDH", "HKDF", "AES_ENC"), t.ns.keys)
        val t2 = Timings(); val r = RsaSuite.generateIdentity()
        RsaSuite.seal(r.pub, sessionKey, pt, aad, t2)
        assertEquals(setOf("RSA_ENCAP", "HKDF", "AES_ENC"), t2.ns.keys)
        assertTrue(t2.ns.values.all { it > 0 })
    }

    @Test fun fieldsAndFrameParsing() {
        val fields = listOf(ByteArray(0), byteArrayOf(1, 2, 3), ByteArray(300) { 7 })
        val back = Fields.unpack(Fields.pack(fields))
        assertEquals(3, back.size); assertArrayEquals(fields[2], back[2])
        expectFail { Fields.unpack(byteArrayOf(0, 5, 1)) }
        expectFail { Fields.unpack(byteArrayOf(0)) }
        val f = Frame(Mode.ECC, Type.SECURE_MESSAGE, "00112233aabbccdd", 255, listOf(byteArrayOf(9), byteArrayOf(8)), byteArrayOf(5))
        val wire = f.encode()
        assertTrue(wire.startsWith("SSMS|1|E|SM|00112233aabbccdd|ff|"))
        val p = Frame.parse(wire)
        assertEquals(255L, p.msgId); assertEquals(Mode.ECC, p.mode); assertEquals(2, p.fields.size); assertArrayEquals(byteArrayOf(5), p.sig)
        assertArrayEquals(f.signedBytes(), p.signedBytes())
        for (bad in listOf("hello", "SSMS|2|E|SM|00112233aabbccdd|1|AA==", "SSMS|1|X|SM|00112233aabbccdd|1|AA==", "SSMS|1|E|ZZ|00112233aabbccdd|1|AA==",
            "SSMS|1|E|SM|nothex|1|AA==", "SSMS|1|E|SM|00112233aabbccdd|zz|AA==", "SSMS|1|E|SM|00112233aabbccdd|1|@@@", "SSMS|1|E|SM|00112233aabbccdd|1|"))
            expectFail { Frame.parse(bad) }
    }

    @Test fun headerIsCoveredBySignedBytes() {
        val a = Frame(Mode.RSA, Type.SECURE_MESSAGE, "00112233aabbccdd", 1, listOf(byteArrayOf(1)))
        val b = Frame(Mode.ECC, Type.SECURE_MESSAGE, "00112233aabbccdd", 1, listOf(byteArrayOf(1)))
        assertFalse(a.signedBytes().contentEquals(b.signedBytes()))
    }

    @Test fun replayWindow() {
        val s = Session(Mode.RSA, "x", true, 0)
        assertFalse(s.isReplay(1)); s.markSeen(1)
        assertTrue(s.isReplay(1))
        s.markSeen(3); assertFalse(s.isReplay(2)); s.markSeen(2); assertTrue(s.isReplay(2))   // reordering allowed once
        s.markSeen(200); assertTrue(s.isReplay(100)); assertTrue(s.isReplay(136)); assertFalse(s.isReplay(150))
        assertTrue(s.recvSeen.size < 70)
    }
}

class SizesAndSelfTestTest {
    @Test fun selfTestPassesForEveryMode() {
        val lines = ArrayList<String>()
        assertTrue(lines.toString(), com.securesms.crypto.benchmark.SelfTest.run { lines.add(it) })
        assertEquals(Mode.entries.size, lines.size)
    }

    @Test fun sizeReportUsesRealFramesAndEccIsSmaller() {
        val r = com.securesms.crypto.benchmark.Sizes.report()
        fun sms(m: Mode, f: String, n: Int) = r.first { it.mode == m && it.frame == f && it.plainBytes == n }.sms
        assertTrue(sms(Mode.ECC, "SECURE_MESSAGE", 32) < sms(Mode.RSA, "SECURE_MESSAGE", 32))
        assertTrue(sms(Mode.ECC, "KEY_RESPONSE", 0) < sms(Mode.RSA, "KEY_RESPONSE", 0))
        // the two original sizes always fit in the 10-SMS cap; the larger RSA sizes need more (see KeySizesTest)
        assertTrue(r.filter { it.mode == Mode.RSA || it.mode == Mode.ECC }.all { it.chars <= com.securesms.messaging.Messenger.MAX_WIRE })
        assertTrue(r.all { it.chars <= Frame.MAX_WIRE })
        assertEquals(1, com.securesms.crypto.benchmark.SmsMath.segments("a".repeat(160)))
        assertEquals(2, com.securesms.crypto.benchmark.SmsMath.segments("a".repeat(161)))
        assertEquals(2, com.securesms.crypto.benchmark.SmsMath.segments("|".repeat(81)))   // '|' = 2 septets
    }
}
