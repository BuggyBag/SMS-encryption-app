package com.securesms.crypto.benchmark

import com.securesms.crypto.*
import kotlin.math.sqrt

class Stat(
    val mode: Mode, val side: String, val op: String, val n: Int,
    val meanMs: Double, val medianMs: Double, val stdMs: Double,
    val minMs: Double, val maxMs: Double, val p95Ms: Double,
)

object Stats {
    fun summarize(samples: List<Sample>, source: String): List<Stat> =
        samples.filter { it.source == source }
            .groupBy { Triple(it.mode, it.side, it.op) }
            .map { (k, v) ->
                val ms = v.map { it.nanos / 1e6 }.sorted()
                val mean = ms.average()
                val sd = if (ms.size > 1) sqrt(ms.sumOf { (it - mean) * (it - mean) } / (ms.size - 1)) else 0.0
                val med = if (ms.size % 2 == 1) ms[ms.size / 2] else (ms[ms.size / 2 - 1] + ms[ms.size / 2]) / 2
                Stat(k.first, k.second, k.third, ms.size, mean, med, sd, ms.first(), ms.last(), ms[((ms.size - 1) * 0.95).toInt()])
            }
            .sortedWith(compareBy({ it.side }, { it.op }, { it.mode }))
}

object Csv {
    private fun q(s: String) = "\"" + s.replace("\"", "\"\"") + "\""
    fun samples(list: List<Sample>): String = buildString {
        appendLine("timestamp_ms,source,mode,scheme,family,key_bits,side,operation,duration_ns,duration_ms,message_bytes,iteration,device")
        for (s in list) appendLine("${s.ts},${s.source},${s.mode.name},${q(s.mode.label)},${s.mode.family.name},${s.mode.bits},${s.side},${s.op},${s.nanos},${"%.6f".format(java.util.Locale.ROOT, s.nanos / 1e6)},${s.msgBytes},${s.iteration},${q(s.device)}")
    }
    fun stats(list: List<Stat>): String = buildString {
        appendLine("mode,scheme,family,key_bits,side,operation,n,mean_ms,median_ms,stddev_ms,min_ms,max_ms,p95_ms")
        for (s in list) appendLine("${s.mode.name},${q(s.mode.label)},${s.mode.family.name},${s.mode.bits},${s.side},${s.op},${s.n},${f(s.meanMs)},${f(s.medianMs)},${f(s.stdMs)},${f(s.minMs)},${f(s.maxMs)},${f(s.p95Ms)}")
    }
    private fun f(d: Double) = "%.6f".format(java.util.Locale.ROOT, d)
}

/**
 * Measurement boundaries (documented in README):
 *  - side S ("sender"):   TOTAL_SEND = seal (KEM/ECDH, HKDF, AES-GCM encrypt) + signature. Sub-ops are separate rows.
 *  - side R ("receiver"): TOTAL_RECV = signature verification + open (decapsulation/ECDH, HKDF, AES-GCM decrypt).
 *  - Excluded: Base64/framing, SMS transmission, storage, UI, parsing of key encodings is outside the timed sub-ops
 *    except inside TOTAL_*. Identity key generation is measured separately (side "-").
 * Clock: System.nanoTime() (monotonic). Same plaintexts, same AES-GCM code, same device for both modes.
 */
object Benchmark {
    class Config(
        val iterations: Int = 30, val warmup: Int = 5, val keygenIterations: Int = 10,
        val sizes: List<Int> = listOf(32, 140, 400),
        /** Which key sizes to measure (default: all of them, in Mode order). */
        val modes: List<Mode> = Mode.entries.toList(),
        /** RSA-3072/4096 key generation is slow (seconds on a phone), so it gets fewer repetitions. */
        val heavyKeygenIterations: Int = 3,
    ) {
        fun keygenReps(m: Mode) = if (m.family == Family.RSA && m.bits >= 3072) minOf(keygenIterations, heavyKeygenIterations) else keygenIterations
    }

    fun plaintext(size: Int) = ByteArray(size) { ('a'.code + (it * 7) % 26).toByte() }

    fun run(
        cfg: Config, device: String, now: () -> Long = System::currentTimeMillis,
        progress: (String, Float) -> Unit = { _, _ -> }, cancelled: () -> Boolean = { false },
    ): List<Sample> {
        val out = ArrayList<Sample>()
        val suites = cfg.modes.map { Suites.of(it) }
        val total = suites.sumOf { cfg.keygenReps(it.mode) + cfg.sizes.size * (cfg.iterations + cfg.warmup) }
        var done = 0
        val sessionKey = Rng.bytes(32)
        for (s in suites) {
            val m = s.mode
            var last: Identity? = null
            for (i in 0 until cfg.keygenReps(m)) {
                if (cancelled()) return out
                val t = Timings(); last = s.generateIdentity(t)
                t.ns.forEach { (k, v) -> out.add(Sample(now(), "bench", m, "-", k, v, 0, i, device)) }
                progress("${m.label}: key generation", ++done / total.toFloat())
            }
            val receiver = last!!
            val sender = s.generateIdentity()
            for (size in cfg.sizes) {
                val pt = plaintext(size)
                for (i in -cfg.warmup until cfg.iterations) {
                    if (cancelled()) return out
                    val aad = Frame0.header(m, i)
                    val ts = Timings()
                    lateinit var sealed: Sealed
                    lateinit var sig: ByteArray
                    ts.t("TOTAL_SEND") {
                        sealed = s.seal(receiver.pub, sessionKey, pt, aad, ts)
                        sig = s.sign(sender.priv, aad + sealed.kem + sealed.nonce + sealed.ct + sealed.tag, ts)
                    }
                    val tr = Timings()
                    val back = tr.t("TOTAL_RECV") {
                        check(s.verify(sender.pub, aad + sealed.kem + sealed.nonce + sealed.ct + sealed.tag, sig, tr)) { "benchmark signature failed" }
                        s.open(receiver.priv, receiver.pub, sessionKey, sealed, aad, tr)
                    }
                    check(back.contentEquals(pt)) { "benchmark round-trip mismatch" }
                    if (i >= 0) {
                        ts.ns.forEach { (k, v) -> out.add(Sample(now(), "bench", m, "S", k, v, size, i, device)) }
                        tr.ns.forEach { (k, v) -> out.add(Sample(now(), "bench", m, "R", k, v, size, i, device)) }
                    }
                    progress("${m.label}: ${size}-byte messages", ++done / total.toFloat())
                }
            }
        }
        return out
    }

    private object Frame0 { fun header(m: Mode, i: Int) = "SSMS|1|${m.code}|SM|bench|${i}|".toByteArray() }
}
