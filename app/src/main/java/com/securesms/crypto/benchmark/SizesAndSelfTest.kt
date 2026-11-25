package com.securesms.crypto.benchmark

import com.securesms.crypto.*
import com.securesms.crypto.symmetric.AesGcm
import com.securesms.protocol.Frame
import com.securesms.protocol.Type

/** GSM-7 segment maths. '|' costs 2 septets (extension table); Base64 characters cost 1. */
object SmsMath {
    fun septets(s: String) = s.length + s.count { it == '|' }
    fun segments(s: String): Int { val n = septets(s); return if (n <= 160) 1 else (n + 152) / 153 }
}

class SizeRow(val mode: Mode, val frame: String, val plainBytes: Int, val chars: Int, val sms: Int)

/** Idea borrowed from the SmsCrypto project: how many SMS does each mode really need? Built from REAL frames. */
object Sizes {
    fun report(plainSizes: List<Int> = listOf(32, 140, 400), modes: List<Mode> = Mode.entries.toList()): List<SizeRow> {
        val out = ArrayList<SizeRow>()
        for (su in modes.map { Suites.of(it) }) {
            val m = su.mode; val a = su.generateIdentity(); val b = su.generateIdentity()
            val sid = Frame.newSessionId(); val sk = Rng.bytes(32)
            fun row(name: String, plain: Int, wire: String) = out.add(SizeRow(m, name, plain, wire.length, SmsMath.segments(wire)))
            val eph = su.hsRequest()
            val kq = Frame(m, Type.KEY_REQUEST, sid, 0, listOf(a.pub, Rng.bytes(16)) + listOfNotNull(eph.pub))
            val kqWire = kq.signed(su.sign(a.priv, kq.signedBytes())).encode(); row("KEY_REQUEST", 0, kqWire)
            val resp = su.hsRespond(a.pub, eph.pub)
            val kr = Frame(m, Type.KEY_RESPONSE, sid, 0, listOf(b.pub, Rng.bytes(16), resp.extra))
            val krWire = kr.signed(su.sign(b.priv, kr.signedBytes(Sha256.of(kqWire.toByteArray())))).encode(); row("KEY_RESPONSE", 0, krWire)
            val kc = Frame(m, Type.KEY_CONFIRM, sid, 0, listOf(Rng.bytes(32)))
            row("KEY_CONFIRM", 0, kc.signed(su.sign(a.priv, kc.signedBytes())).encode())
            for (n in plainSizes) {
                val aad = Frame.header(m, Type.SECURE_MESSAGE, sid, 1).toByteArray()
                val s = su.seal(b.pub, sk, Benchmark.plaintext(n), aad)
                val f = Frame(m, Type.SECURE_MESSAGE, sid, 1, listOf(s.kem, s.nonce, s.ct, s.tag))
                row("SECURE_MESSAGE", n, f.signed(su.sign(a.priv, f.signedBytes())).encode())
            }
        }
        return out
    }
}

/** Quick correctness check you can run on the phone (also verifies Conscrypt supports OAEP-SHA256/PSS). */
object SelfTest {
    fun run(onLine: (String) -> Unit): Boolean {
        var ok = true
        for (su in Suites.all) {
            try {
                val a = su.generateIdentity(); val b = su.generateIdentity(); val sk = Rng.bytes(32)
                su.validatePublic(a.pub)
                val sig = su.sign(a.priv, "x".toByteArray())
                check(su.verify(a.pub, "x".toByteArray(), sig)) { "signature verify" }
                check(!su.verify(a.pub, "y".toByteArray(), sig)) { "signature must fail on other data" }
                for (n in intArrayOf(0, 1, 32, 160, 400)) {
                    val pt = Benchmark.plaintext(n); val aad = "hdr".toByteArray()
                    val s = su.seal(b.pub, sk, pt, aad)
                    check(su.open(b.priv, b.pub, sk, s, aad, Timings()).contentEquals(pt)) { "round trip $n bytes" }
                }
                val s = su.seal(b.pub, sk, "abc".toByteArray(), "h".toByteArray())
                val bad = try { su.open(b.priv, b.pub, sk, Sealed(s.kem, s.nonce, s.ct, s.tag.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }), "h".toByteArray()); false } catch (e: CryptoException) { true }
                check(bad) { "modified tag must be rejected" }
                val e = su.hsRequest(); val r = su.hsRespond(a.pub, e.pub)
                check(su.hsFinish(a.priv, e.priv, r.extra).contentEquals(r.secret)) { "handshake secret agreement" }
                onLine("OK    ${su.mode.label}: sign/verify, seal/open (0-400 B), tamper rejection, handshake secret")
            } catch (e: Exception) { ok = false; onLine("FAIL  ${su.mode.label}: ${e.javaClass.simpleName} ${e.message}") }
        }
        return ok
    }
}
