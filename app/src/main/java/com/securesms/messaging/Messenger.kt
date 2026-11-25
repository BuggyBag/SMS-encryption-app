package com.securesms.messaging

import com.securesms.crypto.*
import com.securesms.crypto.symmetric.Hkdf
import com.securesms.protocol.Frame
import com.securesms.protocol.Type
import com.securesms.storage.*

/** Sends one complete SecureSMS frame. Implementations must throw if the frame cannot be handed to the radio. */
interface SmsTransport {
    fun send(address: String, text: String, tag: Long)
}

enum class SmsStatus { SENT, DELIVERED, FAILED }

class Event(val phoneKey: String, val title: String, val detail: String, val isError: Boolean)

class SessionView(
    val mode: Mode, val exists: Boolean, val hs: Hs?, val trusted: Boolean, val identityChanged: Boolean,
    val peerFingerprint: String?, val held: Int, val pending: Int, val createdAt: Long, val initiator: Boolean,
) {
    val established get() = exists && (hs == Hs.ESTABLISHED) && trusted
}

class ContactRow(val key: String, val address: String, val lastText: String, val lastTs: Long)

/** One line of the conversation list (like a normal messaging app). Built by [Messenger.conversations]. */
class ConversationRow(
    val key: String, val address: String, val preview: String, val ts: Long, val mode: Mode,
    val meta: String,              // e.g. "ECC P-256 · verify fingerprint"
    val secure: Boolean,           // an established, verified session exists
    val needsAction: Boolean,      // user must verify a fingerprint (new request or changed key)
)

/**
 * Protocol state machine: handshake (KQ/KR/KC), per-message hybrid encryption (SM), key update (KU), ERROR.
 * Pure JVM so the whole flow can be tested with two in-memory phones. Plaintext is only ever passed to the crypto
 * suites; the only thing handed to [SmsTransport] is an encoded frame beginning with "SSMS|" (enforced by check()).
 */
class Messenger(
    private val store: Store,
    private val transport: SmsTransport,
    private val clock: () -> Long = System::currentTimeMillis,
    private val device: String = "jvm",
) {
    companion object {
        const val MAX_PLAINTEXT = 400      // UTF-8 bytes; larger messages are refused, never truncated
        const val MAX_WIRE = 1530          // 10 concatenated GSM-7 segments of 153 chars
        const val MAX_HELD = 20

        /**
         * Largest plaintext (UTF-8 bytes) of [mode] whose SECURE_MESSAGE frame still fits in [MAX_WIRE] SMS characters.
         * Conservative: assumes the longest header and the longest possible ECDSA signature, so a message of this size
         * is never refused later. Large RSA keys make the frame (KEM + signature = 2 x key size) big: RSA-4096 leaves ~50 bytes.
         */
        fun maxPlaintext(mode: Mode): Int {
            val rsa = mode.family == Family.RSA
            val coord = (mode.bits + 7) / 8
            val kem = if (rsa) mode.bits / 8 else 1 + 2 * coord                 // RSA-OAEP block | uncompressed EC point
            val sig = if (rsa) mode.bits / 8 else 2 * (coord + 3) + 3           // RSA-PSS | DER ECDSA upper bound
            val header = "SSMS|${Frame.VERSION}|${mode.code}|SM|${"0".repeat(16)}|${"f".repeat(15)}|".length
            fun wireLen(pt: Int): Int {
                val packed = (2 + kem) + (2 + 12) + (2 + pt) + (2 + 16) + (2 + sig)  // kem, nonce, ct, tag, signature
                return header + 4 * ((packed + 2) / 3)                                // Base64
            }
            var n = MAX_PLAINTEXT
            while (n > 0 && wireLen(n) > MAX_WIRE) n--
            return n
        }
        const val MAX_LIVE_SAMPLES = 3000
        /** Marker stored in ChatMessage.info for local, app-generated notes such as "X wants to start a conversation". */
        const val SYSTEM_INFO = "system"
        fun key(address: String): String {
            val trimmed = address.trim()
            if (trimmed.contains(".") || trimmed.lowercase(java.util.Locale.ROOT).contains("localhost")) {
                return trimmed.substringBefore(":")
            }
            val d = trimmed.filter { it.isDigit() }
            return if (d.length > 10) d.takeLast(10) else d
        }
    }

    var onEvent: (Event) -> Unit = {}
    var onChange: () -> Unit = {}
    private val st get() = store.state
    private fun suite(m: Mode): Suite = Suites.of(m)

    // ---------------------------------------------------------------- public API (UI side)

    @Synchronized
    fun send(address: String, mode: Mode, text: String): Long {
        val bytes = text.toByteArray(Charsets.UTF_8)
        require(text.isNotBlank()) { "Message is empty" }
        val limit = maxPlaintext(mode)
        require(bytes.size <= limit) { "Message too long for ${mode.label} (${bytes.size} > $limit bytes; the encrypted frame must fit in ${MAX_WIRE / 153} SMS); it was not sent" }
        require(key(address).length >= 3) { "Invalid phone number or IP address" }
        val c = st.contacts.getOrPut(key(address)) { Contact(key(address), address) }
        c.address = address
        val m = ChatMessage(st.nextId++, c.key, Dir.OUT, mode, text, MsgStatus.WAITING_KEY, clock())
        st.messages.add(m)
        advance(c, mode)
        commit()
        return m.id
    }

    @Synchronized
    fun openContact(address: String): String {
        require(key(address).length >= 3) { "Invalid phone number or IP address" }
        st.contacts.getOrPut(key(address)) { Contact(key(address), address) }
        commit()
        return key(address)
    }

    /** The user compared the fingerprint out-of-band and accepts this peer key for [mode]. */
    @Synchronized
    fun trust(phoneKey: String, mode: Mode) {
        val c = st.contacts[phoneKey] ?: return
        val s = c.sessions[mode] ?: return
        val pub = s.peerPub ?: return
        s.trusted = true; s.identityChanged = false; c.pinned[mode] = pub
        if (s.initiator && s.hs == Hs.WAIT_TRUST) completeInitiator(c, s)
        if (!s.initiator && s.hs == Hs.WAIT_CONFIRM && s.confirmReceived) s.hs = Hs.ESTABLISHED
        afterStateChange(c, mode)
        commit()
    }

    /** User rejects the peer key / abandons the session. Pending messages are failed (never sent). */
    @Synchronized
    fun rejectPeer(phoneKey: String, mode: Mode) {
        val c = st.contacts[phoneKey] ?: return
        c.sessions.remove(mode); c.pinned.remove(mode)
        st.messages.filter { it.phone == phoneKey && it.mode == mode && it.dir == Dir.OUT && it.status in listOf(MsgStatus.WAITING_KEY, MsgStatus.WAITING_TRUST) }
            .forEach { it.status = MsgStatus.FAILED; it.info = "Cancelled: peer key rejected" }
        commit()
    }

    /** Discard a stuck session (e.g. peer never answered) and start a fresh key exchange for waiting messages. */
    @Synchronized
    fun restartHandshake(phoneKey: String, mode: Mode) {
        val c = st.contacts[phoneKey] ?: return
        c.sessions.remove(mode)
        st.messages.filter { it.phone == phoneKey && it.mode == mode && it.dir == Dir.OUT && it.status == MsgStatus.FAILED && it.info?.startsWith("Not sent") == true }
            .forEach { it.status = MsgStatus.WAITING_KEY; it.info = null }
        startHandshake(c, mode)
        commit()
    }

    @Synchronized
    fun retry(messageId: Long) {
        val m = st.messages.firstOrNull { it.id == messageId && it.dir == Dir.OUT && it.status == MsgStatus.FAILED } ?: return
        val c = st.contacts[m.phone] ?: return
        m.status = MsgStatus.WAITING_KEY; m.info = null
        advance(c, m.mode)
        commit()
    }

    @Synchronized
    fun cancel(messageId: Long) {
        st.messages.removeAll { it.id == messageId && it.dir == Dir.OUT && it.status != MsgStatus.SENT && it.status != MsgStatus.DELIVERED }
        commit()
    }

    /** Replace our identity for [mode]; peers are told with a KEY_UPDATE signed by the OLD key. Sessions are dropped. */
    @Synchronized
    fun rotateIdentity(mode: Mode) {
        val old = st.identities[mode]
        val s = suite(mode)
        val fresh = s.generateIdentity()
        if (old != null) {
            for (c in st.contacts.values.toList()) {
                if (c.sessions[mode] == null && c.pinned[mode] == null) continue
                val ku = Frame(mode, Type.KEY_UPDATE, Frame.newSessionId(), clock(), listOf(fresh.pub))
                sendFrame(c, ku.signed(s.sign(old.priv, ku.signedBytes())).encode(), 0)
            }
        }
        st.identities[mode] = fresh
        st.contacts.values.forEach { it.sessions.remove(mode); it.pinned.remove(mode) }
        commit()
    }

    @Synchronized
    fun onStart() {
        st.messages.filter { it.status == MsgStatus.SENDING }.forEach { it.status = MsgStatus.FAILED; it.info = "Not sent: app was interrupted — retry" }
        for (c in st.contacts.values.toList()) for (m in Mode.entries) advance(c, m, startIfMissing = false)
        commit()
    }

    @Synchronized
    fun onSmsStatus(tag: Long, status: SmsStatus, detail: String?) {
        val m = st.messages.firstOrNull { it.id == tag } ?: return
        when (status) {
            SmsStatus.SENT -> if (m.status == MsgStatus.SENDING) m.status = MsgStatus.SENT
            SmsStatus.DELIVERED -> if (m.status != MsgStatus.FAILED) m.status = MsgStatus.DELIVERED
            SmsStatus.FAILED -> { m.status = MsgStatus.FAILED; m.info = "Not sent: SMS failed (${detail ?: "network error"}) — retry" }
        }
        commit()
    }

    @Synchronized fun deleteConversation(phoneKey: String) { st.messages.removeAll { it.phone == phoneKey }; commit() }

    @Synchronized
    fun myFingerprint(mode: Mode): String = Fingerprint.of(mode, ensureIdentity(mode).pub).also { commit() }

    @Synchronized fun contacts(): List<ContactRow> = st.contacts.values.map { c ->
        val last = st.messages.lastOrNull { it.phone == c.key }
        ContactRow(c.key, c.address, last?.text ?: last?.info ?: "", last?.ts ?: 0)
    }.sortedByDescending { it.lastTs }

    /** Conversations that have at least one message, newest first. Includes incoming conversation requests. */
    @Synchronized
    fun conversations(): List<ConversationRow> = st.contacts.values.mapNotNull { c ->
        val msgs = st.messages.filter { it.phone == c.key }
        val last = msgs.lastOrNull() ?: return@mapNotNull null
        val mark = when (last.status) {
            MsgStatus.WAITING_KEY, MsgStatus.WAITING_TRUST -> "⏳ "
            MsgStatus.SENDING -> "↑ "
            MsgStatus.SENT -> "✓ "
            MsgStatus.DELIVERED -> "✓✓ "
            MsgStatus.FAILED -> "⚠ not sent: "
            else -> ""
        }
        val preview = when {
            last.info == SYSTEM_INFO -> last.text ?: ""
            last.status == MsgStatus.REJECTED -> "⚠ Message rejected"
            last.dir == Dir.OUT -> "You: $mark${last.text ?: ""}"
            else -> last.text ?: ""
        }
        val s = c.sessions.values.maxByOrNull { it.createdAt }
        val action = s != null && (s.identityChanged || (!s.trusted && s.peerPub != null))
        val state = when {
            s == null -> "no session"
            s.identityChanged -> "KEY CHANGED - verify"
            s.hs == Hs.ESTABLISHED && s.trusted -> "secure"
            s.hs == Hs.REQ_SENT -> "waiting for reply"
            !s.trusted && s.peerPub != null -> "verify fingerprint"
            else -> "waiting for confirmation"
        }
        ConversationRow(c.key, c.address, preview, last.ts, last.mode,
            (s?.mode ?: last.mode).label + " · " + state, s != null && s.hs == Hs.ESTABLISHED && s.trusted, action)
    }.sortedByDescending { it.ts }

    /** Incoming messages (including requests and rejected ones) newer than [afterId]; the UI remembers the last id it showed. */
    @Synchronized fun unread(phoneKey: String, afterId: Long): Int =
        st.messages.count { it.phone == phoneKey && it.dir == Dir.IN && it.id > afterId }

    @Synchronized fun lastIncomingId(phoneKey: String): Long =
        st.messages.lastOrNull { it.phone == phoneKey && it.dir == Dir.IN }?.id ?: 0L

    @Synchronized fun messages(phoneKey: String): List<ChatMessage> = st.messages.filter { it.phone == phoneKey }.map { it.copy() }

    @Synchronized
    fun sessionView(phoneKey: String, mode: Mode): SessionView {
        val c = st.contacts[phoneKey]
        val s = c?.sessions?.get(mode)
        val pending = st.messages.count { it.phone == phoneKey && it.mode == mode && it.dir == Dir.OUT && (it.status == MsgStatus.WAITING_KEY || it.status == MsgStatus.WAITING_TRUST) }
        return SessionView(mode, s != null, s?.hs, s?.trusted ?: false, s?.identityChanged ?: false,
            s?.peerPub?.let { Fingerprint.of(mode, it) }, c?.held?.size ?: 0, pending, s?.createdAt ?: 0, s?.initiator ?: false)
    }

    @Synchronized fun samples(): List<Sample> = st.samples.toList()
    @Synchronized fun addSamples(l: List<Sample>) { st.samples.addAll(l); commit() }
    @Synchronized fun clearSamples(source: String? = null) { st.samples.removeAll { source == null || it.source == source }; commit() }
    @Synchronized fun addressOf(phoneKey: String) = st.contacts[phoneKey]?.address ?: phoneKey

    // ---------------------------------------------------------------- outgoing

    private fun ensureIdentity(mode: Mode): Identity = st.identities.getOrPut(mode) {
        val t = Timings(); val id = suite(mode).generateIdentity(t)
        t.ns.forEach { (k, v) -> st.samples.add(Sample(clock(), "live", mode, "-", k, v, 0, 0, device)) }
        id
    }

    private fun advance(c: Contact, mode: Mode, startIfMissing: Boolean = true) {
        val s = c.sessions[mode]
        val waiting = st.messages.any { it.phone == c.key && it.mode == mode && it.dir == Dir.OUT && (it.status == MsgStatus.WAITING_KEY || it.status == MsgStatus.WAITING_TRUST) }
        if (!waiting) return
        when {
            s == null -> if (startIfMissing) startHandshake(c, mode)
            s.hs == Hs.ESTABLISHED && s.trusted -> flushPending(c, s)
            else -> st.messages.filter { it.phone == c.key && it.mode == mode && it.dir == Dir.OUT && it.status == MsgStatus.WAITING_KEY && s.hs == Hs.WAIT_TRUST }
                .forEach { it.status = MsgStatus.WAITING_TRUST }
        }
    }

    private fun startHandshake(c: Contact, mode: Mode) {
        try {
            val s = suite(mode); val id = ensureIdentity(mode)
            val eph = s.hsRequest()
            val na = Rng.bytes(16)
            val fields = if (mode.family == Family.ECC) listOf(id.pub, na, eph.pub!!) else listOf(id.pub, na)
            val f = Frame(mode, Type.KEY_REQUEST, Frame.newSessionId(), 0, fields)
            val wire = f.signed(s.sign(id.priv, f.signedBytes())).encode()
            val ses = Session(mode, f.sessionId, true, clock()).apply {
                this.na = na; myEphPriv = eph.priv; kqHash = Sha256.of(wire.toByteArray())
            }
            c.sessions[mode] = ses
            sendFrame(c, wire, 0)
            event(c, "Key exchange started", "Sent ${mode.label} key request to ${c.address}. Waiting for the peer's response.", false)
        } catch (e: Exception) {
            failWaiting(c, mode, "Not sent: key exchange failed (${e.message})")
        }
    }

    private fun flushPending(c: Contact, s: Session) {
        st.messages.filter { it.phone == c.key && it.dir == Dir.OUT && it.mode == s.mode && (it.status == MsgStatus.WAITING_KEY || it.status == MsgStatus.WAITING_TRUST) }
            .forEach { sendSecure(c, s, it) }
    }

    private fun sendSecure(c: Contact, ses: Session, m: ChatMessage) {
        try {
            val mode = ses.mode; val su = suite(mode)
            val id = st.identities[mode] ?: throw CryptoException("identity key missing")
            val seq = ses.sendSeq + 1
            val aad = Frame.header(mode, Type.SECURE_MESSAGE, ses.sessionId, seq).toByteArray()
            val t = Timings()
            lateinit var frame: Frame
            t.t("TOTAL_SEND") {
                val sealed = su.seal(ses.peerPub!!, ses.sessionKey!!, m.text!!.toByteArray(Charsets.UTF_8), aad, t)
                val f = Frame(mode, Type.SECURE_MESSAGE, ses.sessionId, seq, listOf(sealed.kem, sealed.nonce, sealed.ct, sealed.tag))
                frame = f.signed(su.sign(id.priv, f.signedBytes(), t))
            }
            val wire = frame.encode()
            if (wire.length > MAX_WIRE) throw CryptoException("encrypted message too large for SMS")
            ses.sendSeq = seq; m.seq = seq; m.status = MsgStatus.SENDING; m.info = null
            record(mode, "S", t, m.text!!.toByteArray(Charsets.UTF_8).size)
            transport.send(c.address, wire, m.id)
        } catch (e: Exception) {
            m.status = MsgStatus.FAILED; m.info = "Not sent: ${e.message} — plaintext was NOT transmitted"
            event(c, "Message not sent", m.info!!, true)
        }
    }

    private fun failWaiting(c: Contact, mode: Mode, why: String) {
        st.messages.filter { it.phone == c.key && it.mode == mode && it.dir == Dir.OUT && it.status in listOf(MsgStatus.WAITING_KEY, MsgStatus.WAITING_TRUST) }
            .forEach { it.status = MsgStatus.FAILED; it.info = why }
        event(c, "Key exchange failed", why, true)
    }

    private fun sendFrame(c: Contact, wire: String, tag: Long) {
        check(wire.startsWith("SSMS|")) { "refusing to transmit non-protocol data" }
        try { transport.send(c.address, wire, tag) } catch (e: Exception) {
            event(c, "SMS not sent", e.message ?: "transmission failed", true)
            throw e
        }
    }

    // ---------------------------------------------------------------- incoming

    @Synchronized
    fun onSms(from: String, body: String) {
        if (!body.startsWith("SSMS|")) return
        try {
            val f = Frame.parse(body)
            when (f.type) {
                Type.KEY_REQUEST -> handleKq(from, f, body)
                Type.KEY_RESPONSE -> handleKr(from, f, body)
                Type.KEY_CONFIRM -> handleKc(from, f)
                Type.SECURE_MESSAGE -> handleSm(from, f, body)
                Type.KEY_UPDATE -> handleKu(from, f)
                Type.ERROR -> handleEr(from, f)
            }
        } catch (e: ProtocolException) {
            st.contacts[key(from)]?.let { event(it, "Invalid message", "Rejected malformed SecureSMS frame: ${e.message}", true) }
        } catch (e: CryptoException) {
            st.contacts[key(from)]?.let { event(it, "Invalid message", "Rejected: ${e.message}", true) }
        }
        commit()
    }

    private fun need(f: Frame, n: Int) { if (f.fields.size != n || f.sig == null) throw ProtocolException("wrong field count for ${f.type}") }

    private fun deriveSession(mode: Mode, sid: String, secret: ByteArray, na: ByteArray, nb: ByteArray, kqHash: ByteArray): Pair<ByteArray, ByteArray> {
        val okm = Hkdf.derive(secret, na + nb, "SSMS-v1 handshake ${mode.code}".toByteArray() + sid.toByteArray() + kqHash, 64)
        return okm.copyOfRange(0, 32) to okm.copyOfRange(32, 64)
    }

    private fun handleKq(from: String, f: Frame, wire: String) {
        val mode = f.mode; val su = suite(mode)
        need(f, if (mode.family == Family.ECC) 3 else 2)
        val peerPub = f.fields[0]; val na = f.fields[1]
        if (na.size != 16) throw ProtocolException("bad nonce")
        su.validatePublic(peerPub)
        if (!su.verify(peerPub, f.signedBytes(), f.sig!!)) {
            onEvent(Event(key(from), "Invalid signature", "Key request from $from has an invalid signature and was ignored.", true))
            return
        }
        val c = st.contacts.getOrPut(key(from)) { Contact(key(from), from) }
        val nHex = Hex.enc(na)
        if (nHex in c.seenKq) return                      // replayed request
        val ex = c.sessions[mode]
        if (ex != null && ex.initiator && ex.hs == Hs.REQ_SENT && ex.sessionId < f.sessionId) return // crossing requests: lower id wins
        c.seenKq.add(nHex); if (c.seenKq.size > 50) c.seenKq.removeAt(0)

        val pinned = c.pinned[mode]
        val changed = pinned != null && !pinned.contentEquals(peerPub)
        val id = ensureIdentity(mode)
        val nb = Rng.bytes(16)
        val resp = su.hsRespond(peerPub, if (mode.family == Family.ECC) f.fields[2] else null)
        val kqHash = Sha256.of(wire.toByteArray())
        val (sk, ck) = deriveSession(mode, f.sessionId, resp.secret, na, nb, kqHash)
        val kr = Frame(mode, Type.KEY_RESPONSE, f.sessionId, 0, listOf(id.pub, nb, resp.extra))
        val krWire = kr.signed(su.sign(id.priv, kr.signedBytes(kqHash))).encode()
        c.sessions[mode] = Session(mode, f.sessionId, false, clock()).apply {
            this.peerPub = peerPub; hs = Hs.WAIT_CONFIRM; trusted = pinned != null && !changed; identityChanged = changed
            sessionKey = sk; confirmKey = ck; this.kqHash = kqHash; krHash = Sha256.of(krWire.toByteArray())
        }
        sendFrame(c, krWire, 0)
        val s = c.sessions[mode]!!
        // Make the request visible as a received message, so the conversation shows up in the list like a normal chat.
        val already = st.messages.lastOrNull { it.phone == c.key && it.mode == mode }?.info == SYSTEM_INFO
        if (changed) st.messages.add(ChatMessage(st.nextId++, c.key, Dir.IN, mode,
            "⚠ ${c.address} is now using a different ${mode.label} key. Verify the new fingerprint before trusting.", MsgStatus.RECEIVED, clock(), SYSTEM_INFO))
        else if (!s.trusted && !already) st.messages.add(ChatMessage(st.nextId++, c.key, Dir.IN, mode,
            "🔒 ${c.address} wants to start a secure ${mode.label} conversation. Verify their fingerprint to continue.", MsgStatus.RECEIVED, clock(), SYSTEM_INFO))
        if (changed) event(c, "IDENTITY KEY CHANGED", "${c.address} is using a different ${mode.label} key than the one you verified. Compare fingerprints again before trusting.", true)
        else if (!s.trusted) event(c, "Key exchange request", "${c.address} wants a secure ${mode.label} session. Open the conversation and verify the fingerprint.", false)
    }

    private fun handleKr(from: String, f: Frame, wire: String) {
        val c = st.contacts[key(from)] ?: return
        val mode = f.mode; val su = suite(mode)
        val s = c.sessions[mode]
        if (s != null && s.initiator && s.sessionId == f.sessionId && s.hs != Hs.REQ_SENT) return   // duplicate delivery of a response we already processed
        if (s == null || !s.initiator || s.hs != Hs.REQ_SENT || s.sessionId != f.sessionId) {
            val why = when {
                s == null -> "you have no ${mode.label} key exchange in progress with this contact"
                !s.initiator -> "this phone did not start the exchange (the other phone did)"
                s.sessionId != f.sessionId -> "it belongs to an older request that was replaced (Restart or a second request)"
                else -> "the exchange is already in state ${s.hs}"
            }
            event(c, "Unexpected response", "Ignored a ${mode.label} key response from ${c.address}: $why.", true); return
        }
        need(f, 3)
        val peerPub = f.fields[0]; val nb = f.fields[1]
        if (nb.size != 16) throw ProtocolException("bad nonce")
        su.validatePublic(peerPub)
        if (!su.verify(peerPub, f.signedBytes(s.kqHash!!), f.sig!!)) {
            event(c, "Invalid signature", "Key response from ${c.address} has an invalid signature. Session NOT established.", true); return
        }
        val id = st.identities[mode] ?: throw CryptoException("identity missing")
        val secret = su.hsFinish(id.priv, s.myEphPriv, f.fields[2])
        val (sk, ck) = deriveSession(mode, s.sessionId, secret, s.na!!, nb, s.kqHash!!)
        val pinned = c.pinned[mode]
        val changed = pinned != null && !pinned.contentEquals(peerPub)
        s.peerPub = peerPub; s.sessionKey = sk; s.confirmKey = ck; s.krHash = Sha256.of(wire.toByteArray()); s.myEphPriv = null
        s.hs = Hs.WAIT_TRUST; s.trusted = pinned != null && !changed; s.identityChanged = changed
        if (s.trusted) { completeInitiator(c, s); afterStateChange(c, mode) }
        else {
            advance(c, mode)
            event(c, if (changed) "IDENTITY KEY CHANGED" else "Verify fingerprint",
                "Compare the ${mode.label} fingerprint of ${c.address} with them (in person or by call) and tap Trust. Your message stays queued; nothing is sent until you do.", changed)
        }
    }

    private fun completeInitiator(c: Contact, s: Session) {
        val su = suite(s.mode); val id = st.identities[s.mode]!!
        val mac = Hkdf.hmac(s.confirmKey!!, "KC".toByteArray(), s.kqHash!!, s.krHash!!)
        val f = Frame(s.mode, Type.KEY_CONFIRM, s.sessionId, 0, listOf(mac))
        sendFrame(c, f.signed(su.sign(id.priv, f.signedBytes(s.kqHash!! + s.krHash!!))).encode(), 0)
        s.hs = Hs.ESTABLISHED
    }

    private fun handleKc(from: String, f: Frame) {
        val c = st.contacts[key(from)] ?: return
        val s = c.sessions[f.mode] ?: return
        if (s.initiator || s.hs != Hs.WAIT_CONFIRM || s.sessionId != f.sessionId) return
        need(f, 1)
        val su = suite(f.mode)
        if (!su.verify(s.peerPub!!, f.signedBytes(s.kqHash!! + s.krHash!!), f.sig!!)) {
            event(c, "Invalid signature", "Key confirmation from ${c.address} has an invalid signature.", true); return
        }
        val expect = Hkdf.hmac(s.confirmKey!!, "KC".toByteArray(), s.kqHash!!, s.krHash!!)
        if (!java.security.MessageDigest.isEqual(expect, f.fields[0])) {
            event(c, "Key confirmation failed", "Session keys do not match; session NOT established.", true); return
        }
        s.confirmReceived = true
        if (s.trusted) { s.hs = Hs.ESTABLISHED; afterStateChange(c, f.mode); event(c, "Secure session ready", "${f.mode.label} session with ${c.address} is established.", false) }
        else event(c, "Awaiting your verification", "${c.address} confirmed the key exchange. Verify their fingerprint to activate the session.", false)
    }

    private fun handleSm(from: String, f: Frame, wire: String) {
        val c = st.contacts[key(from)]
        val s = c?.sessions?.get(f.mode)
        if (c == null || s == null || s.sessionId != f.sessionId) {
            if (c != null) rejectIn(c, f.mode, "No ${f.mode.label} session for this message (unknown session or wrong mode)", "NO_SESSION", f.msgId)
            return
        }
        if (s.hs != Hs.ESTABLISHED || !s.trusted) {
            if (c.held.size < MAX_HELD && wire !in c.held) c.held.add(wire)
            event(c, "Message held", "A ${f.mode.label} message from ${c.address} is waiting. Verify their fingerprint to read it.", false)
            return
        }
        if (f.msgId < 1 || s.isReplay(f.msgId)) { rejectIn(c, f.mode, "Duplicate or replayed message #${f.msgId} rejected", "REPLAY", f.msgId); return }
        need(f, 4)
        val su = suite(f.mode); val id = st.identities[f.mode] ?: throw CryptoException("identity missing")
        val t = Timings()
        try {
            lateinit var plain: ByteArray
            t.t("TOTAL_RECV") {
                if (!su.verify(s.peerPub!!, f.signedBytes(), f.sig!!, t)) throw CryptoException("invalid sender signature")
                plain = su.open(id.priv, id.pub, s.sessionKey!!, Sealed(f.fields[0], f.fields[1], f.fields[2], f.fields[3]), f.header().toByteArray(), t)
            }
            val text = Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(plain)).toString()
            s.markSeen(f.msgId)
            st.messages.add(ChatMessage(st.nextId++, c.key, Dir.IN, f.mode, text, MsgStatus.RECEIVED, clock(), "authenticated", f.msgId))
            record(f.mode, "R", t, plain.size)
            event(c, "New secure message", "From ${c.address} (${f.mode.label})", false)
        } catch (e: CryptoException) {
            rejectIn(c, f.mode, "Rejected: ${e.message}", if (e.message?.contains("signature") == true) "BAD_SIGNATURE" else "AUTH_FAILED", f.msgId)
        } catch (e: java.nio.charset.CharacterCodingException) {
            rejectIn(c, f.mode, "Rejected: plaintext is not valid UTF-8", "AUTH_FAILED", f.msgId)
        }
    }

    private fun rejectIn(c: Contact, mode: Mode, why: String, code: String, mid: Long) {
        st.messages.add(ChatMessage(st.nextId++, c.key, Dir.IN, mode, null, MsgStatus.REJECTED, clock(), why, mid))
        event(c, "Message rejected", "${c.address}: $why", true)
        if (clock() - c.lastErrorSent > 60_000) {   // rate-limited, informational, unauthenticated
            c.lastErrorSent = clock()
            val er = Frame(mode, Type.ERROR, c.sessions[mode]?.sessionId ?: "0".repeat(16), 0, listOf(code.toByteArray(), mid.toString().toByteArray()))
            try { transport.send(c.address, er.encode(), 0) } catch (_: Exception) {}
        }
    }

    private fun handleEr(from: String, f: Frame) {
        val c = st.contacts[key(from)] ?: return
        if (f.fields.size != 2) return
        val code = String(f.fields[0]).take(24).filter { it.isLetterOrDigit() || it == '_' }
        val mid = String(f.fields[1]).toLongOrNull()
        st.messages.firstOrNull { it.phone == c.key && it.dir == Dir.OUT && it.mode == f.mode && it.seq == mid }
            ?.let { it.info = "Peer reported: $code (unauthenticated notice)" }
        event(c, "Peer reported an error", "${c.address} reported $code for a ${f.mode.label} message (unauthenticated notice).", true)
    }

    private fun handleKu(from: String, f: Frame) {
        val c = st.contacts[key(from)] ?: return
        need(f, 1)
        val old = c.pinned[f.mode] ?: c.sessions[f.mode]?.peerPub ?: return
        val su = suite(f.mode)
        if (!su.verify(old, f.signedBytes(), f.sig!!)) { event(c, "Invalid key update", "KEY_UPDATE from ${c.address} is not signed by the key you trust; ignored.", true); return }
        if (f.msgId <= (c.lastKu[f.mode] ?: 0L)) return
        c.lastKu[f.mode] = f.msgId
        c.sessions.remove(f.mode); c.pinned.remove(f.mode)
        event(c, "Contact changed key", "${c.address} rotated their ${f.mode.label} identity. A new key exchange and fingerprint check is required.", true)
    }

    // ---------------------------------------------------------------- helpers

    private fun afterStateChange(c: Contact, mode: Mode) {
        val s = c.sessions[mode] ?: return
        if (s.hs == Hs.ESTABLISHED && s.trusted) {
            flushPending(c, s)
            val h = c.held.toList(); c.held.clear()
            for (w in h) try { handleSm(c.address, Frame.parse(w), w) } catch (_: Exception) {}
        }
    }

    private fun record(mode: Mode, side: String, t: Timings, bytes: Int) {
        t.ns.forEach { (k, v) -> st.samples.add(Sample(clock(), "live", mode, side, k, v, bytes, 0, device)) }
        val live = st.samples.count { it.source == "live" }
        if (live > MAX_LIVE_SAMPLES) { var drop = live - MAX_LIVE_SAMPLES; st.samples.removeAll { it.source == "live" && drop-- > 0 } }
    }

    private fun event(c: Contact, title: String, detail: String, err: Boolean) = onEvent(Event(c.key, title, detail, err))

    private fun commit() {
        try { store.save() } catch (e: Exception) { onEvent(Event("", "Storage error", e.message ?: "could not save", true)) }
        onChange()
    }
}
