package com.securesms.sms

import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Telephony
import android.telephony.SmsManager
import com.securesms.SecureSmsApp
import com.securesms.messaging.Messenger
import com.securesms.messaging.SmsStatus
import com.securesms.messaging.SmsTransport
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/** Hands finished SecureSMS frames to the cellular network. Long frames become concatenated multipart SMS. */
class AndroidSms(private val ctx: Context) : SmsTransport {
    companion object {
        const val ACTION_SENT = "com.securesms.SMS_SENT"
        const val ACTION_DELIVERED = "com.securesms.SMS_DELIVERED"
        const val MAX_PARTS = 10
    }

    private fun manager(): SmsManager =
        (if (Build.VERSION.SDK_INT >= 31) ctx.getSystemService(SmsManager::class.java) else null)
            ?: @Suppress("DEPRECATION") SmsManager.getDefault()
            ?: throw IllegalStateException("SmsManager is not available on this device")

    private fun pi(action: String, tag: Long, idx: Int, total: Int): PendingIntent {
        val i = Intent(action).setClass(ctx, SmsStatusReceiver::class.java).putExtra("tag", tag).putExtra("total", total)
        val requestCode = (((tag * 31 + idx) * 7) + action.length).toInt()
        return PendingIntent.getBroadcast(ctx, requestCode, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    override fun send(address: String, text: String, tag: Long) {
        check(text.startsWith("SSMS|")) { "refusing to send non-protocol text" }
        val sm = manager()
        val parts = sm.divideMessage(text)
        check(parts.size <= MAX_PARTS) { "message needs ${parts.size} SMS parts (max $MAX_PARTS)" }
        val sent = if (tag > 0) ArrayList(parts.indices.map { pi(ACTION_SENT, tag, it, parts.size) }) else null
        val deliv = if (tag > 0) ArrayList(parts.indices.map { pi(ACTION_DELIVERED, tag, it, parts.size) }) else null
        if (parts.size == 1) sm.sendTextMessage(address, null, text, sent?.get(0), deliv?.get(0))
        else sm.sendMultipartTextMessage(address, null, parts, sent, deliv)
    }
}

/** Incoming SMS_RECEIVED. Only frames starting with "SSMS|" are consumed; everything else is ignored. */
class SmsReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent) ?: return
        val from = parts.firstOrNull()?.originatingAddress ?: return
        val body = parts.joinToString("") { it.messageBody ?: "" }   // platform already ordered the concatenated segments
        if (!body.startsWith("SSMS|")) return
        val app = context.applicationContext as? SecureSmsApp ?: return
        val pending = goAsync()
        thread { try { app.messenger.onSms(from, body) } finally { pending.finish() } }
    }
}

/** Per-part sent / delivered results, aggregated to one status per message. */
class SmsStatusReceiver : BroadcastReceiver() {
    companion object {
        private val sentCount = ConcurrentHashMap<Long, AtomicInteger>()
        private val deliveredCount = ConcurrentHashMap<Long, AtomicInteger>()
    }

    override fun onReceive(context: Context, intent: Intent) {
        val tag = intent.getLongExtra("tag", 0); val total = intent.getIntExtra("total", 1)
        if (tag <= 0) return
        val app = context.applicationContext as? SecureSmsApp ?: return
        val messenger: Messenger = app.messenger
        val code = resultCode
        val pending = goAsync()
        thread {
            try {
                when (intent.action) {
                    AndroidSms.ACTION_SENT ->
                        if (code != Activity.RESULT_OK) {
                            sentCount.remove(tag)
                            messenger.onSmsStatus(tag, SmsStatus.FAILED, reason(code))
                        } else if (sentCount.getOrPut(tag) { AtomicInteger() }.incrementAndGet() >= total) {
                            sentCount.remove(tag)
                            messenger.onSmsStatus(tag, SmsStatus.SENT, null)
                        }
                    AndroidSms.ACTION_DELIVERED ->
                        if (code == Activity.RESULT_OK && deliveredCount.getOrPut(tag) { AtomicInteger() }.incrementAndGet() >= total) {
                            deliveredCount.remove(tag)
                            messenger.onSmsStatus(tag, SmsStatus.DELIVERED, null)
                        }
                }
            } finally { pending.finish() }
        }
    }

    private fun reason(code: Int) = when (code) {
        SmsManager.RESULT_ERROR_NO_SERVICE -> "no network service"
        SmsManager.RESULT_ERROR_RADIO_OFF -> "airplane mode / radio off"
        SmsManager.RESULT_ERROR_NULL_PDU -> "invalid PDU"
        else -> "generic failure ($code)"
    }
}
