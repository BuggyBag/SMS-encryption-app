package com.securesms

import com.securesms.crypto.*
import com.securesms.crypto.benchmark.Benchmark
import com.securesms.crypto.benchmark.Csv
import com.securesms.crypto.benchmark.Stats
import com.securesms.crypto.symmetric.AesGcm
import com.securesms.messaging.*
import com.securesms.protocol.Frame
import com.securesms.storage.*
import org.junit.Assert.*
import org.junit.Test

class MemBlob : Blob { var data: ByteArray? = null; override fun read() = data; override fun write(data: ByteArray) { this.data = data } }

class TestVault(private val key: ByteArray = Rng.bytes(32)) : Vault {
    override fun seal(plain: ByteArray): ByteArray { val r = AesGcm.encrypt(key, plain, ByteArray(0)); return r.nonce + r.tag + r.ct }
    override fun open(blob: ByteArray) = AesGcm.decrypt(key, blob.copyOfRange(0, 12), blob.copyOfRange(28, blob.size), blob.copyOfRange(12, 28), ByteArray(0))
}

class Net {
    class Pkt(val from: String, val to: String, val wire: String)
    val phones = HashMap<String, Phone>()
    val queue = ArrayList<Pkt>()
    val log = ArrayList<Pkt>()
    var failSecure = false
    fun pump(rewrite: (Pkt) -> Pkt? = { it }) {
        var guard = 0
        while (queue.isNotEmpty() && guard++ < 200) {
            val p = rewrite(queue.removeAt(0)) ?: continue
            phones[Messenger.key(p.to)]?.m?.onSms(p.from, p.wire)
        }
    }
}

class Phone(val net: Net, val number: String, val vault: TestVault = TestVault(), val blob: MemBlob = MemBlob()) {
    val events = ArrayList<Event>()
    lateinit var store: Store
    lateinit var m: Messenger
    init { boot() ; net.phones[Messenger.key(number)] = this }
    fun boot() {
        store = Store(vault, blob)
        m = Messenger(store, object : SmsTransport {
            override fun send(address: String, text: String, tag: Long) {
                if (net.failSecure && tag > 0) throw IllegalStateException("radio off")
                Net.Pkt(number, address, text).also { net.queue.add(it); net.log.add(it) }
            }
        })
        m.onEvent = { events.add(it) }
    }
    val key get() = Messenger.key(number)
    fun incoming(peer: Phone) = m.messages(peer.key).filter { it.dir == Dir.IN && it.info != Messenger.SYSTEM_INFO }
    fun outgoing(peer: Phone) = m.messages(peer.key).filter { it.dir == Dir.OUT }
}

class MessengerTest {
    private val ALICE = "+52 222 111 1111"; private val BOB = "+52 222 222 2222"
    private fun pair(): Triple<Net, Phone, Phone> { val n = Net(); return Triple(n, Phone(n, ALICE), Phone(n, BOB)) }

    /** Full first contact: A -> B, fingerprints compared, both trust. Returns after B has read the message. */
    private fun establish(n: Net, a: Phone, b: Phone, mode: Mode, text: String = "hello bob") {
        val smBefore = n.log.count { Frame.parse(it.wire).let { f -> f.type.code == "SM" && f.mode == mode } }
        a.m.send(b.number, mode, text)
        n.pump()
        assertEquals(Hs.WAIT_TRUST, a.m.sessionView(b.key, mode).hs)
        assertEquals(MsgStatus.WAITING_TRUST, a.outgoing(b).last().status)       // nothing sent before trust
        assertEquals(smBefore, n.log.count { Frame.parse(it.wire).let { f -> f.type.code == "SM" && f.mode == mode } })
        assertEquals(b.m.myFingerprint(mode), a.m.sessionView(b.key, mode).peerFingerprint)   // fingerprints shown match
        a.m.trust(b.key, mode); n.pump()
        assertEquals(a.m.myFingerprint(mode), b.m.sessionView(a.key, mode).peerFingerprint)
        assertTrue(b.incoming(a).none { it.status == MsgStatus.RECEIVED && it.mode == mode })        // held until B verifies A
        b.m.trust(a.key, mode)
    }

    @Test fun firstRsaCommunicationEndToEnd() {
        val (n, a, b) = pair()
        establish(n, a, b, Mode.RSA)
        val got = b.incoming(a).single()
        assertEquals("hello bob", got.text); assertEquals(Mode.RSA, got.mode); assertEquals(MsgStatus.RECEIVED, got.status)
        assertTrue(a.m.sessionView(b.key, Mode.RSA).established)
        assertEquals(MsgStatus.SENDING, a.outgoing(b).single().status)
    }

    @Test fun subsequentRsaMessagesReuseSessionWithoutHandshake() {
        val (n, a, b) = pair(); establish(n, a, b, Mode.RSA)
        n.log.clear()
        a.m.send(b.number, Mode.RSA, "second"); n.pump()
        assertEquals(1, n.log.size); assertEquals("SM", Frame.parse(n.log[0].wire).type.code)
        assertEquals(listOf("hello bob", "second"), b.incoming(a).map { it.text })
        b.m.send(a.number, Mode.RSA, "reply"); n.pump()                         // other direction works too
        assertEquals("reply", a.incoming(b).single().text)
    }

    @Test fun firstAndSubsequentEccCommunication() {
        val (n, a, b) = pair(); establish(n, a, b, Mode.ECC, "ecc hi")
        assertEquals("ecc hi", b.incoming(a).single().text); assertEquals(Mode.ECC, b.incoming(a).single().mode)
        n.log.clear(); a.m.send(b.number, Mode.ECC, "again"); n.pump()
        assertEquals(1, n.log.size); assertEquals(2, b.incoming(a).size)
    }

    @Test fun receiverIdentifiesModeAutomaticallyWhenModesAreMixed() {
        val (n, a, b) = pair(); establish(n, a, b, Mode.RSA, "rsa one"); establish(n, a, b, Mode.ECC, "ecc one")
        a.m.send(b.number, Mode.RSA, "rsa two"); a.m.send(b.number, Mode.ECC, "ecc two"); n.pump()
        val got = b.incoming(a).map { it.mode to it.text }
        assertTrue(got.containsAll(listOf(Mode.RSA to "rsa one", Mode.ECC to "ecc one", Mode.RSA to "rsa two", Mode.ECC to "ecc two")))
    }

    @Test fun plaintextNeverAppearsOnTheWire() {
        val (n, a, b) = pair(); val secret = "TOP-SECRET-PLAINTEXT"
        establish(n, a, b, Mode.RSA, secret); establish(n, a, b, Mode.ECC, secret)
        assertTrue(n.log.isNotEmpty())
        for (p in n.log) {
            assertTrue(p.wire.startsWith("SSMS|"))
            assertFalse(p.wire.contains(secret))
            assertFalse(String(Fields.unpack(B64.dec(p.wire.substringAfterLast('|'))).fold(ByteArray(0)) { x, y -> x + y }, Charsets.ISO_8859_1).contains(secret))
        }
    }

    @Test fun noFallbackWhenTransportFailsOrMessageTooLong() {
        val (n, a, b) = pair(); establish(n, a, b, Mode.ECC)
        n.log.clear(); n.failSecure = true
        a.m.send(b.number, Mode.ECC, "will fail")
        val m = a.outgoing(b).last(); assertEquals(MsgStatus.FAILED, m.status); assertTrue(m.info!!.startsWith("Not sent"))
        assertTrue(n.log.isEmpty())
        n.failSecure = false; a.m.retry(m.id); n.pump()
        assertEquals("will fail", b.incoming(a).last().text)
        expectFail { a.m.send(b.number, Mode.ECC, "x".repeat(Messenger.MAX_PLAINTEXT + 1)) }
        assertTrue(n.log.none { it.wire.contains("xxxx") })
        a.m.send(b.number, Mode.RSA, "é".repeat(200)); n.pump()                         // 400 bytes exactly: allowed
    }

    @Test fun modifiedCiphertextIsRejectedForBothModes() {
        for (mode in Mode.entries) {
            val (n, a, b) = pair(); establish(n, a, b, mode)
            a.m.send(b.number, mode, "genuine")
            n.pump { p ->
                val f = Frame.parse(p.wire)
                if (f.type.code != "SM") return@pump p
                val ct = f.fields[2].copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
                // attacker re-encodes the frame with a flipped ciphertext bit but cannot re-sign
                Net.Pkt(p.from, p.to, Frame(f.mode, f.type, f.sessionId, f.msgId, listOf(f.fields[0], f.fields[1], ct, f.fields[3]), f.sig).encode())
            }
            assertEquals(1, b.incoming(a).count { it.status == MsgStatus.RECEIVED })
            assertEquals(1, b.incoming(a).count { it.status == MsgStatus.REJECTED })
            assertNull(b.incoming(a).last().text)
        }
    }

    @Test fun forgedSignatureAndWrongTagAreRejected() {
        val (n, a, b) = pair(); establish(n, a, b, Mode.ECC)
        val mallory = EccSuiteHolder.id
        a.m.send(b.number, Mode.ECC, "genuine")
        n.pump { p ->
            val f = Frame.parse(p.wire)
            val forged = Frame(f.mode, f.type, f.sessionId, f.msgId, f.fields)
            Net.Pkt(p.from, p.to, forged.signed(com.securesms.crypto.ecc.EccSuite.sign(mallory.priv, forged.signedBytes())).encode())
        }
        assertEquals(MsgStatus.REJECTED, b.incoming(a).last().status)
        assertTrue(b.incoming(a).last().info!!.contains("signature"))
        // wrong tag but re-signed by the attacker is still rejected (not the pinned key)
        assertEquals(1, b.incoming(a).count { it.status == MsgStatus.RECEIVED })
    }

    @Test fun replayedAndDuplicatedMessagesAreRejectedButReorderingIsAccepted() {
        val (n, a, b) = pair(); establish(n, a, b, Mode.RSA)
        a.m.send(b.number, Mode.RSA, "m2"); a.m.send(b.number, Mode.RSA, "m3"); a.m.send(b.number, Mode.RSA, "m4")
        val pk = ArrayList(n.queue); n.queue.clear()
        n.queue.addAll(listOf(pk[2], pk[0], pk[1])); n.pump()                           // delivered out of order
        assertEquals(listOf("hello bob", "m4", "m2", "m3"), b.incoming(a).filter { it.status == MsgStatus.RECEIVED }.map { it.text })
        n.queue.add(pk[1]); n.queue.add(pk[2]); n.pump()                                // replay
        assertEquals(2, b.incoming(a).count { it.status == MsgStatus.REJECTED })
        assertEquals(4, b.incoming(a).count { it.status == MsgStatus.RECEIVED })
    }

    @Test fun wrongModeOrUnknownSessionIsRejected() {
        val (n, a, b) = pair(); establish(n, a, b, Mode.RSA)
        a.m.send(b.number, Mode.RSA, "x")
        n.pump { p -> Net.Pkt(p.from, p.to, p.wire.replaceFirst("SSMS|1|R|", "SSMS|1|E|")) }   // header says ECC
        assertEquals(MsgStatus.REJECTED, b.incoming(a).last().status)
        assertTrue(b.incoming(a).last().info!!.contains("No ECC"))
    }

    @Test fun tamperedKeyRequestIsIgnoredAndNoResponseIsSent() {
        for (mode in Mode.entries) {
            val (n, a, b) = pair()
            a.m.send(b.number, mode, "hi")
            n.pump { p ->
                val f = Frame.parse(p.wire)
                val pub = f.fields[0].copyOf(); val nonce = f.fields[1].copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
                Net.Pkt(p.from, p.to, Frame(f.mode, f.type, f.sessionId, f.msgId, listOf(pub, nonce) + f.fields.drop(2), f.sig).encode())
            }
            assertTrue(n.log.none { Frame.parse(it.wire).type.code == "KR" })
            assertTrue(b.events.any { it.title == "Invalid signature" })
        }
    }

    @Test fun invalidPublicKeyInRequestIsRejected() {
        val (n, a, b) = pair()
        a.m.send(b.number, Mode.ECC, "hi")
        n.pump { p ->
            val f = Frame.parse(p.wire); val bad = f.fields[0].copyOf().also { it[40] = (it[40].toInt() xor 1).toByte() }
            Net.Pkt(p.from, p.to, Frame(f.mode, f.type, f.sessionId, f.msgId, listOf(bad) + f.fields.drop(1), f.sig).encode())
        }
        assertTrue(n.log.none { Frame.parse(it.wire).type.code == "KR" })
    }

    @Test fun mitmKeySubstitutionIsVisibleThroughFingerprint() {
        val (n, a, b) = pair(); val mallory = Phone(n, "+52 222 333 3333")
        a.m.send(b.number, Mode.ECC, "hi")
        // Mallory answers in Bob's place with her own (validly self-signed) identity
        n.queue.clear(); mallory.m.onSms(a.number, n.log[0].wire)
        n.queue.forEach { a.m.onSms(b.number, it.wire) }
        assertEquals(Hs.WAIT_TRUST, a.m.sessionView(b.key, Mode.ECC).hs)
        assertNotEquals(b.m.myFingerprint(Mode.ECC), a.m.sessionView(b.key, Mode.ECC).peerFingerprint)
        assertFalse(a.m.sessionView(b.key, Mode.ECC).trusted)
    }

    @Test fun untrustedPeerCannotDeliverPlaintext() {
        val (n, a, b) = pair()
        a.m.send(b.number, Mode.RSA, "hi"); n.pump(); a.m.trust(b.key, Mode.RSA); n.pump()   // Bob never trusts Alice
        assertTrue(b.incoming(a).isEmpty())
        assertEquals(1, b.m.sessionView(a.key, Mode.RSA).held)
    }

    @Test fun missingResponseKeepsMessagePendingAndRetryRestartsExchange() {
        val (n, a, b) = pair()
        a.m.send(b.number, Mode.ECC, "anyone there?"); n.queue.clear()                  // Bob has no app / no reply
        assertEquals(MsgStatus.WAITING_KEY, a.outgoing(b).single().status)
        n.log.clear(); a.m.restartHandshake(b.key, Mode.ECC)
        assertEquals(1, n.log.size); assertEquals("KQ", Frame.parse(n.log[0].wire).type.code)
        n.pump(); assertEquals(Hs.WAIT_TRUST, a.m.sessionView(b.key, Mode.ECC).hs)
    }

    @Test fun identityChangeRequiresReauthentication() {
        val (n, a, b) = pair(); establish(n, a, b, Mode.ECC)
        val b2 = Phone(n, BOB)                                  // Bob reinstalled: fresh keys, same number
        a.m.restartHandshake(b.key, Mode.ECC); a.m.send(b.number, Mode.ECC, "after reinstall"); n.pump()
        val v = a.m.sessionView(b.key, Mode.ECC)
        assertTrue(v.identityChanged); assertFalse(v.trusted)
        assertTrue(a.events.any { it.title == "IDENTITY KEY CHANGED" })
        assertTrue(b2.incoming(a).isEmpty())                    // nothing delivered until user re-verifies
    }

    @Test fun keyRotationAnnouncementSignedByOldKey() {
        val (n, a, b) = pair(); establish(n, a, b, Mode.RSA)
        a.m.rotateIdentity(Mode.RSA); n.pump()
        assertFalse(b.m.sessionView(a.key, Mode.RSA).exists)
        assertTrue(b.events.any { it.title == "Contact changed key" })
    }

    @Test fun stateSurvivesApplicationRestart() {
        val (n, a, b) = pair(); establish(n, a, b, Mode.RSA); establish(n, a, b, Mode.ECC)
        a.boot(); b.boot(); n.phones[a.key] = a; n.phones[b.key] = b                   // process death: reload from encrypted storage
        a.m.onStart(); n.log.clear()
        a.m.send(b.number, Mode.RSA, "after restart"); b.m.send(a.number, Mode.ECC, "from bob"); n.pump()
        assertTrue(n.log.all { Frame.parse(it.wire).type.code == "SM" })
        assertEquals("after restart", b.incoming(a).last { it.mode == Mode.RSA }.text)
        assertEquals("from bob", a.incoming(b).last().text)
        a.boot()                                                                         // replay across restart still rejected
        val replay = n.log.first { Frame.parse(it.wire).mode == Mode.RSA }
        b.m.onSms(a.number, replay.wire)
        assertEquals(MsgStatus.REJECTED, b.incoming(a).last().status)
    }

    @Test fun pendingMessageIsRecoveredAfterRestartAndInterruptedSendIsMarkedFailed() {
        val (n, a, b) = pair()
        a.m.send(b.number, Mode.RSA, "queued"); n.queue.clear()
        a.boot(); a.m.onStart()
        assertEquals(MsgStatus.WAITING_KEY, a.outgoing(b).single().status)
    }

    @Test fun storageFileIsEncryptedAndRefusesTampering() {
        val (n, a, b) = pair(); establish(n, a, b, Mode.RSA, "persisted-secret-text")
        val raw = b.blob.data!!
        assertFalse(String(raw, Charsets.ISO_8859_1).contains("persisted-secret-text"))
        b.blob.data = raw.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 1).toByte() }
        val s2 = Store(b.vault, b.blob)
        assertNotNull(s2.loadError); expectFail { s2.save() }
    }

    @Test fun benchmarkProducesRealMeasurementsForEveryMode() {
        val s = Benchmark.run(Benchmark.Config(iterations = 4, warmup = 1, keygenIterations = 2, sizes = listOf(32, 140)), "test")
        val stats = Stats.summarize(s, "bench")
        for (m in Mode.entries) {
            for (op in listOf("IDENTITY_KEYGEN", "TOTAL_SEND", "TOTAL_RECV", "HKDF", "AES_ENC", "AES_DEC"))
                assertTrue("$m $op", stats.any { it.mode == m && it.op == op && it.n > 0 && it.medianMs > 0 })
        }
        assertTrue(stats.any { it.mode == Mode.RSA && it.op == "RSA_ENCAP" } && stats.any { it.mode == Mode.RSA && it.op == "RSA_DECAP" })
        assertTrue(stats.any { it.mode == Mode.ECC && it.op == "ECDH" } && stats.any { it.mode == Mode.ECC && it.op == "KEYGEN_EPHEMERAL" })
        val csv = Csv.samples(s); assertEquals(s.size + 1, csv.trim().lines().size)
        assertTrue(csv.startsWith("timestamp_ms,source,mode,scheme,family,key_bits"))
    }
}

object EccSuiteHolder { val id = com.securesms.crypto.ecc.EccSuite.generateIdentity() }
