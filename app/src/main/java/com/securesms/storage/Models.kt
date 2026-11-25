package com.securesms.storage

import com.securesms.crypto.Identity
import com.securesms.crypto.Mode
import com.securesms.crypto.Sample
import java.io.Serializable

enum class Dir { IN, OUT }

enum class MsgStatus { WAITING_KEY, WAITING_TRUST, SENDING, SENT, DELIVERED, FAILED, RECEIVED, REJECTED }

/** Handshake state of one (contact, mode) session. */
enum class Hs { REQ_SENT, WAIT_TRUST, WAIT_CONFIRM, ESTABLISHED }

data class ChatMessage(
    val id: Long, val phone: String, val dir: Dir, val mode: Mode,
    var text: String?, var status: MsgStatus, val ts: Long, var info: String? = null, var seq: Long = 0,
) : Serializable {
    companion object {
        private const val serialVersionUID = 1L
    }
}

class Session(val mode: Mode, val sessionId: String, val initiator: Boolean, val createdAt: Long) : Serializable {
    var hs: Hs = Hs.REQ_SENT
    var peerPub: ByteArray? = null
    var trusted = false
    var identityChanged = false
    var confirmReceived = false
    var myEphPriv: ByteArray? = null
    var na: ByteArray? = null
    var kqHash: ByteArray? = null
    var krHash: ByteArray? = null
    var sessionKey: ByteArray? = null
    var confirmKey: ByteArray? = null
    var sendSeq = 0L
    var recvHigh = 0L
    val recvSeen = HashSet<Long>()

    /** Sliding-window replay protection: duplicates and anything older than the window are rejected. */
    fun isReplay(mid: Long) = (mid <= recvHigh - WINDOW) || (mid in recvSeen)

    fun markSeen(mid: Long) {
        recvSeen.add(mid)
        if (mid > recvHigh) recvHigh = mid
        recvSeen.removeAll { it <= recvHigh - WINDOW }
    }

    companion object {
        private const val serialVersionUID = 1L
        const val WINDOW = 64
    }
}

class Contact(val key: String, var address: String) : Serializable {
    val sessions = HashMap<Mode, Session>()
    val pinned = HashMap<Mode, ByteArray>()       // identity key the user verified
    val seenKq = ArrayList<String>()              // nonces of key requests already processed
    val held = ArrayList<String>()                // authentic-looking frames waiting for trust
    val lastKu = HashMap<Mode, Long>()
    var lastErrorSent = 0L

    companion object {
        private const val serialVersionUID = 1L
    }
}

class State : Serializable {
    val identities = HashMap<Mode, Identity>()
    val contacts = HashMap<String, Contact>()
    val messages = ArrayList<ChatMessage>()
    val samples = ArrayList<Sample>()
    var nextId = 1L
    var lastDevice = ""

    companion object {
        private const val serialVersionUID = 1L
    }
}
