package com.securesms

import com.securesms.crypto.Mode
import com.securesms.messaging.Messenger
import com.securesms.storage.Dir
import com.securesms.storage.MsgStatus
import org.junit.Assert.*
import org.junit.Test

class ConversationListTest {
    private val ALICE = "+52 222 111 1111"; private val BOB = "+52 222 222 2222"

    @Test fun receiverSeesConversationRequestAsReceivedMessageInTheList() {
        val n = Net(); val a = Phone(n, ALICE); val b = Phone(n, BOB)
        assertTrue(b.m.conversations().isEmpty())
        a.m.send(b.number, Mode.ECC, "hi bob"); n.pump()
        // Bob never typed anything, yet the conversation is in his list with a request message
        val rows = b.m.conversations()
        assertEquals(1, rows.size)
        assertEquals(a.key, rows[0].key)
        assertTrue(rows[0].preview, rows[0].preview.contains("wants to start a secure ECC P-256 conversation"))
        assertTrue(rows[0].needsAction); assertFalse(rows[0].secure)
        assertEquals(Mode.ECC, rows[0].mode)
        val msg = b.m.messages(a.key).single()
        assertEquals(Dir.IN, msg.dir); assertEquals(MsgStatus.RECEIVED, msg.status); assertEquals(Messenger.SYSTEM_INFO, msg.info)
        assertEquals(1, b.m.unread(a.key, 0L))
        assertEquals(0, b.m.unread(a.key, b.m.lastIncomingId(a.key)))      // opening the chat marks it read
    }

    @Test fun senderListShowsHisOwnMessageAndItBecomesSecureAfterVerification() {
        val n = Net(); val a = Phone(n, ALICE); val b = Phone(n, BOB)
        a.m.send(b.number, Mode.RSA, "hello"); n.pump()
        val mine = a.m.conversations().single()
        assertTrue(mine.preview, mine.preview.startsWith("You: ⏳ hello"))
        assertTrue(mine.needsAction)                       // Alice must verify Bob's fingerprint
        a.m.trust(b.key, Mode.RSA); n.pump(); b.m.trust(a.key, Mode.RSA)
        assertTrue(a.m.conversations().single().secure)
        val theirs = b.m.conversations().single()
        assertEquals("hello", theirs.preview); assertTrue(theirs.secure); assertFalse(theirs.needsAction)
    }

    @Test fun requestNoteIsNotRepeatedAndKnownContactsAreNotNagged() {
        val n = Net(); val a = Phone(n, ALICE); val b = Phone(n, BOB)
        a.m.send(b.number, Mode.ECC, "one"); n.pump()
        a.m.restartHandshake(b.key, Mode.ECC); n.pump()         // new request while the first is still unanswered
        assertEquals(1, b.m.messages(a.key).count { it.info == Messenger.SYSTEM_INFO })
        a.m.trust(b.key, Mode.ECC); n.pump(); b.m.trust(a.key, Mode.ECC)
        a.m.restartHandshake(b.key, Mode.ECC); n.pump()         // verified peer: automatic, no new note
        assertEquals(1, b.m.messages(a.key).count { it.info == Messenger.SYSTEM_INFO })
    }

    @Test fun newestConversationFirstAndDeletedHistoryDisappears() {
        val n = Net(); val a = Phone(n, ALICE); val b = Phone(n, BOB); val c = Phone(n, "+52 222 333 3333")
        a.m.send(b.number, Mode.ECC, "to bob"); Thread.sleep(5); a.m.send(c.number, Mode.ECC, "to carol")
        assertEquals(listOf(c.key, b.key), a.m.conversations().map { it.key })
        a.m.deleteConversation(c.key)
        assertEquals(listOf(b.key), a.m.conversations().map { it.key })
    }

    @Test fun changedKeyIsAnnouncedInTheConversation() {
        val n = Net(); val a = Phone(n, ALICE); val b = Phone(n, BOB)
        a.m.send(b.number, Mode.ECC, "x"); n.pump(); a.m.trust(b.key, Mode.ECC); n.pump(); b.m.trust(a.key, Mode.ECC)
        val a2 = Phone(n, ALICE)                                  // Alice reinstalled: new keys, same number
        a2.m.send(b.number, Mode.ECC, "x"); n.pump()
        val last = b.m.messages(a.key).last()
        assertTrue(last.text, last.text!!.contains("different ECC P-256 key"))
        assertTrue(b.m.conversations().single().needsAction)
    }
}

class KeyResponseHandlingTest {
    private val ALICE = "+52 222 111 1111"; private val BOB = "+52 222 222 2222"

    @Test fun duplicateKeyResponseIsIgnoredQuietly() {
        val n = Net(); val a = Phone(n, ALICE); val b = Phone(n, BOB)
        a.m.send(b.number, Mode.ECC, "hi"); n.pump()
        val kr = n.log.first { com.securesms.protocol.Frame.parse(it.wire).type.code == "KR" }
        val before = a.events.size
        a.m.onSms(b.number, kr.wire)                       // the carrier / phone delivers the same SMS twice
        assertEquals(before, a.events.size)
        assertTrue(a.m.sessionView(b.key, Mode.ECC).peerFingerprint != null)
    }

    @Test fun staleKeyResponseExplainsWhy() {
        val n = Net(); val a = Phone(n, ALICE); val b = Phone(n, BOB)
        a.m.send(b.number, Mode.ECC, "hi")
        val kq = n.queue.removeAt(0); b.m.onSms(a.number, kq.wire)      // Bob answers the first request...
        val oldKr = n.queue.removeAt(0)
        a.m.restartHandshake(a.m.contacts().single().key, Mode.ECC)     // ...but Alice restarted meanwhile
        n.queue.clear()
        a.m.onSms(b.number, oldKr.wire)
        val e = a.events.last()
        assertEquals("Unexpected response", e.title)
        assertTrue(e.detail, e.detail.contains("older request"))
    }
}
