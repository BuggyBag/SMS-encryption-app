package com.securesms

import com.securesms.crypto.*
import com.securesms.crypto.benchmark.Benchmark
import com.securesms.crypto.benchmark.Csv
import com.securesms.crypto.benchmark.Sizes
import com.securesms.crypto.ecc.EccSuite
import com.securesms.crypto.rsa.RsaSuite
import com.securesms.messaging.Messenger
import com.securesms.protocol.Frame
import com.securesms.protocol.Type
import com.securesms.storage.MsgStatus
import org.junit.Assert.*
import org.junit.Test

/** Tests for the extra key sizes: RSA 1024/2048/3072/4096 and ECC P-256/P-384/P-521. */
class KeySizesTest {
    private val sessionKey = Rng.bytes(32)
    private val aad = "hdr".toByteArray()

    private fun fails(block: () -> Unit) {
        try { block() } catch (e: CryptoException) { return } catch (e: ProtocolException) { return }
        fail("expected a CryptoException / ProtocolException")
    }

    @Test fun modeCodesAreUniqueAndOriginalOnesKept() {
        assertEquals(Mode.entries.size, Mode.entries.map { it.code }.toSet().size)
        assertEquals(Mode.entries.size, Mode.entries.map { it.label }.toSet().size)
        for (m in Mode.entries) assertEquals(m, Mode.fromCode(m.code))
        assertEquals('R', Mode.RSA.code); assertEquals(2048, Mode.RSA.bits)
        assertEquals('E', Mode.ECC.code); assertEquals(256, Mode.ECC.bits)
        assertEquals(listOf(1024, 2048, 3072, 4096), Mode.entries.filter { it.family == Family.RSA }.map { it.bits })
        assertEquals(listOf(256, 384, 521), Mode.entries.filter { it.family == Family.ECC }.map { it.bits })
        assertTrue(Suites.of(Mode.RSA) === RsaSuite); assertTrue(Suites.of(Mode.ECC) === EccSuite)
    }

    @Test fun everySuiteSignsSealsAndHandshakes() {
        for (m in Mode.entries) {
            val su = Suites.of(m); assertEquals(m, su.mode)
            val id = su.generateIdentity(); su.validatePublic(id.pub)
            if (m.family == Family.ECC) assertEquals("$m point size", 1 + 2 * ((m.bits + 7) / 8), id.pub.size)
            val data = "transcript".toByteArray()
            val sig = su.sign(id.priv, data)
            assertTrue("$m verify", su.verify(id.pub, data, sig))
            assertFalse("$m verify other data", su.verify(id.pub, "transcripu".toByteArray(), sig))
            assertFalse("$m verify other key", su.verify(su.generateIdentity().pub, data, sig))
            for (n in intArrayOf(0, 1, 32, 160, 400)) {
                val pt = Benchmark.plaintext(n)
                val s = su.seal(id.pub, sessionKey, pt, aad)
                assertArrayEquals("$m $n bytes", pt, su.open(id.priv, id.pub, sessionKey, s, aad))
            }
            val s = su.seal(id.pub, sessionKey, "abc".toByteArray(), aad)
            fails { su.open(id.priv, id.pub, Rng.bytes(32), s, aad) }                       // wrong session key
            fails { su.open(id.priv, id.pub, sessionKey, Sealed(s.kem, s.nonce, s.ct, s.tag.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }), aad) }
            fails { su.open(id.priv, id.pub, sessionKey, s, "other".toByteArray()) }        // header is authenticated
            val e = su.hsRequest(); val r = su.hsRespond(id.pub, e.pub)
            assertArrayEquals("$m handshake", r.secret, su.hsFinish(id.priv, e.priv, r.extra))
        }
    }

    @Test fun publicKeyOfAnotherSizeIsRejected() {
        // a key must have EXACTLY the size of its mode (no silent downgrade inside a mode)
        val rsa = Mode.entries.filter { it.family == Family.RSA }.associateWith { Suites.of(it).generateIdentity().pub }
        for (a in rsa.keys) for (b in rsa.keys) if (a != b) fails { Suites.of(a).validatePublic(rsa.getValue(b)) }
        val ecc = Mode.entries.filter { it.family == Family.ECC }.associateWith { Suites.of(it).generateIdentity().pub }
        for (a in ecc.keys) for (b in ecc.keys) if (a != b) fails { Suites.of(a).validatePublic(ecc.getValue(b)) }
        fails { Suites.of(Mode.ECC384).validatePublic(rsa.getValue(Mode.RSA)) }              // across families
        fails { Suites.of(Mode.RSA3072).validatePublic(ecc.getValue(Mode.ECC)) }
        // off-curve point on the big curves
        for (m in listOf(Mode.ECC384, Mode.ECC521)) {
            val pub = ecc.getValue(m)
            fails { Suites.of(m).validatePublic(pub.copyOf().also { it[pub.size - 1] = (it[pub.size - 1].toInt() xor 1).toByte() }) }
        }
    }

    @Test fun framesCarryEveryModeCode() {
        for (m in Mode.entries) {
            val f = Frame(m, Type.SECURE_MESSAGE, "00112233aabbccdd", 7, listOf(byteArrayOf(1, 2)), byteArrayOf(3))
            assertEquals(m, Frame.parse(f.encode()).mode)
        }
        val bad = Frame(Mode.RSA, Type.SECURE_MESSAGE, "00112233aabbccdd", 7, listOf(byteArrayOf(1)), byteArrayOf(3)).encode().replaceFirst("|R|", "|Z|")
        fails { Frame.parse(bad) }
    }

    @Test fun realFramesCanBeParsedForEveryMode() {
        val r = Sizes.report()
        assertEquals(Mode.entries.toSet(), r.map { it.mode }.toSet())
        assertTrue(r.all { it.chars <= Frame.MAX_WIRE })            // the receiver accepts every real frame
        fun sms(m: Mode) = r.first { it.mode == m && it.frame == "SECURE_MESSAGE" && it.plainBytes == 140 }.sms
        // bigger key -> more SMS, inside each family; and ECC P-521 still cheaper than RSA-2048
        assertTrue(sms(Mode.RSA1024) <= sms(Mode.RSA) && sms(Mode.RSA) < sms(Mode.RSA3072) && sms(Mode.RSA3072) < sms(Mode.RSA4096))
        assertTrue(sms(Mode.ECC) <= sms(Mode.ECC384) && sms(Mode.ECC384) <= sms(Mode.ECC521))
        assertTrue(sms(Mode.ECC521) < sms(Mode.RSA))
    }

    @Test fun csvHasKeySizeColumnsAndAllModes() {
        val s = Benchmark.run(Benchmark.Config(iterations = 2, warmup = 0, keygenIterations = 1, sizes = listOf(32)), "test")
        val csv = Csv.samples(s).trim().lines()
        val header = csv.first().split(",")
        assertEquals(listOf("mode", "scheme", "family", "key_bits"), header.subList(2, 6))
        val bitsIdx = header.indexOf("key_bits"); val modeIdx = header.indexOf("mode")
        val seen = csv.drop(1).map { it.split(",") }.map { it[modeIdx] to it[bitsIdx].toInt() }.toSet()
        assertEquals(Mode.entries.map { it.name to it.bits }.toSet(), seen)
        // a subset of modes can be benchmarked on its own
        val only = Benchmark.run(Benchmark.Config(iterations = 2, warmup = 0, keygenIterations = 1, sizes = listOf(32), modes = listOf(Mode.ECC384)), "test")
        assertEquals(setOf(Mode.ECC384), only.map { it.mode }.toSet())
    }

    @Test fun twoPhonesTalkInEveryKeySize() {
        for (mode in Mode.entries) {
            val n = Net(); val a = Phone(n, "+52 222 111 1111"); val b = Phone(n, "+52 222 222 2222")
            a.m.send(b.number, mode, "hello in ${mode.label}")
            n.pump()
            assertEquals("$mode waits for trust", MsgStatus.WAITING_TRUST, a.outgoing(b).last().status)
            assertEquals(b.m.myFingerprint(mode), a.m.sessionView(b.key, mode).peerFingerprint)
            a.m.trust(b.key, mode); n.pump()
            b.m.trust(a.key, mode); n.pump()
            val got = b.incoming(a).single { it.mode == mode }
            assertEquals("hello in ${mode.label}", got.text); assertEquals(MsgStatus.RECEIVED, got.status)
            // a second message needs no new handshake and the receiver never chooses the mode
            val kq = n.log.count { Frame.parse(it.wire).type == Type.KEY_REQUEST }
            a.m.send(b.number, mode, "again"); n.pump()
            assertEquals(kq, n.log.count { Frame.parse(it.wire).type == Type.KEY_REQUEST })
            assertEquals(2, b.incoming(a).count { it.mode == mode && it.status == MsgStatus.RECEIVED })
        }
    }

    @Test fun differentKeySizesAreIndependentSessions() {
        val n = Net(); val a = Phone(n, "+52 222 111 1111"); val b = Phone(n, "+52 222 222 2222")
        for (m in listOf(Mode.RSA3072, Mode.ECC384)) {
            a.m.send(b.number, m, "via ${m.label}"); n.pump()
            a.m.trust(b.key, m); n.pump(); b.m.trust(a.key, m); n.pump()
        }
        assertEquals(setOf("via RSA-3072", "via ECC P-384"), b.incoming(a).map { it.text }.toSet())
        assertNotEquals(a.m.myFingerprint(Mode.RSA3072), a.m.myFingerprint(Mode.ECC384))
        assertTrue(a.m.sessionView(b.key, Mode.RSA3072).established && a.m.sessionView(b.key, Mode.ECC384).established)
        assertFalse(a.m.sessionView(b.key, Mode.RSA).exists)     // nothing was started in the other sizes
    }

    @Test fun maxPlaintextIsExactForTheRealFrames() {
        for (m in Mode.entries) {
            val limit = Messenger.maxPlaintext(m)
            assertTrue("$m limit", limit in 1..Messenger.MAX_PLAINTEXT)
            // build the real frame the way Messenger does and measure it
            val su = Suites.of(m); val id = su.generateIdentity()
            fun wire(n: Int): Int {
                val sealed = su.seal(id.pub, sessionKey, Benchmark.plaintext(n), aad)
                val f = Frame(m, Type.SECURE_MESSAGE, Frame.newSessionId(), 1L shl 50, listOf(sealed.kem, sealed.nonce, sealed.ct, sealed.tag))
                return f.signed(su.sign(id.priv, f.signedBytes())).encode().length
            }
            assertTrue("$m: $limit bytes must fit", wire(limit) <= Messenger.MAX_WIRE)
            if (limit < Messenger.MAX_PLAINTEXT) assertTrue("$m: limit is tight", wire(limit + 16) > Messenger.MAX_WIRE)
        }
        assertEquals(Messenger.MAX_PLAINTEXT, Messenger.maxPlaintext(Mode.RSA))      // original sizes keep the old 400-byte limit
        assertEquals(Messenger.MAX_PLAINTEXT, Messenger.maxPlaintext(Mode.ECC))
        assertTrue(Messenger.maxPlaintext(Mode.RSA3072) < Messenger.MAX_PLAINTEXT)
        assertTrue(Messenger.maxPlaintext(Mode.RSA4096) < Messenger.maxPlaintext(Mode.RSA3072))
    }

    @Test fun tooBigMessageIsRefusedUpFrontAndTheLargestOneIsDelivered() {
        for (mode in listOf(Mode.RSA3072, Mode.RSA4096)) {
            val limit = Messenger.maxPlaintext(mode)
            val n = Net(); val a = Phone(n, "+52 222 111 1111"); val b = Phone(n, "+52 222 222 2222")
            try { a.m.send(b.number, mode, "x".repeat(limit + 1)); fail("must be refused") }
            catch (e: IllegalArgumentException) { assertTrue(e.message, e.message!!.startsWith("Message too long")) }
            assertTrue("nothing sent, no key exchange started", n.log.isEmpty())
            val text = "y".repeat(limit)
            a.m.send(b.number, mode, text); n.pump()
            a.m.trust(b.key, mode); n.pump(); b.m.trust(a.key, mode); n.pump()
            assertEquals(text, b.incoming(a).single().text)
            assertEquals(MsgStatus.RECEIVED, b.incoming(a).single().status)
        }
    }
}
