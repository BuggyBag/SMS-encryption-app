package com.securesms

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.securesms.messaging.Event
import com.securesms.messaging.Messenger
import com.securesms.sms.HybridTransport
import com.securesms.storage.AndroidVault
import com.securesms.storage.FileBlob
import com.securesms.storage.Store
import com.securesms.ui.MainActivity
import java.io.File
import kotlin.concurrent.thread

/** Implemented by MainActivity while it is on screen. */
interface UiHooks {
    fun changed()
    fun event(e: Event)
}

/** Owns the long-lived objects so SMS receivers can work even when the Activity is closed. */
class SecureSmsApp : Application() {
    lateinit var store: Store
    lateinit var transport: HybridTransport
    lateinit var messenger: Messenger
    @Volatile var ui: UiHooks? = null
    val deviceLabel get() = "${Build.MANUFACTURER} ${Build.MODEL} (Android ${Build.VERSION.RELEASE}, API ${Build.VERSION.SDK_INT})"

    override fun onCreate() {
        super.onCreate()
        store = Store(AndroidVault(), FileBlob(File(filesDir, "securesms.state")))
        transport = HybridTransport(this)
        messenger = Messenger(store, transport, device = deviceLabel)
        transport.messenger = messenger
        transport.startListening { messenger }
        messenger.onChange = { ui?.changed() }
        messenger.onEvent = { e -> ui?.event(e) ?: notify(e) }
        getSystemService(NotificationManager::class.java)?.createNotificationChannel(
            NotificationChannel("msgs", "Secure messages", NotificationManager.IMPORTANCE_DEFAULT)
        )
        thread { messenger.onStart() }   // resume queued messages, mark interrupted sends as failed
    }

    private fun notify(e: Event) {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val n = NotificationCompat.Builder(this, "msgs").setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentTitle(e.title).setContentText(e.detail).setContentIntent(open).setAutoCancel(true).build()
        try { NotificationManagerCompat.from(this).notify(e.hashCode(), n) } catch (_: SecurityException) { /* permission not granted */ }
    }
}
