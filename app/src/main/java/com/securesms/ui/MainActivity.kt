package com.securesms.ui

/*
 * MainActivity.kt - four tabs on one XML screen (same style as the SmsCrypto layout):
 *   Chats      : list of conversations like a normal messaging app (incoming requests appear here by themselves)
 *   Chat       : mode spinner, phone, security status, verify/restart/retry, transcript, message + send
 *   RSA vs ECC : benchmark, self-test, SMS-size table, text bar charts, CSV export
 *   My keys    : my fingerprints (to read to the contact) and key rotation
 * All crypto / protocol logic lives in crypto/, protocol/, messaging/ (pure Kotlin, unit-tested on the JVM).
 */

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ListView
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.core.widget.doAfterTextChanged
import com.google.android.material.tabs.TabLayout
import com.securesms.R
import com.securesms.SecureSmsApp
import com.securesms.UiHooks
import com.securesms.crypto.Family
import com.securesms.crypto.Mode
import com.securesms.crypto.benchmark.Benchmark
import com.securesms.crypto.benchmark.Csv
import com.securesms.crypto.benchmark.SelfTest
import com.securesms.crypto.benchmark.Sizes
import com.securesms.crypto.benchmark.Stat
import com.securesms.crypto.benchmark.Stats
import com.securesms.messaging.ConversationRow
import com.securesms.messaging.Event
import com.securesms.messaging.Messenger
import com.securesms.messaging.SessionView
import com.securesms.storage.ChatMessage
import com.securesms.storage.Dir
import com.securesms.storage.Hs
import com.securesms.storage.MsgStatus
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors
import android.view.ContextThemeWrapper

class MainActivity : AppCompatActivity(), UiHooks {

    private val worker = Executors.newSingleThreadExecutor()   // crypto never runs on the UI thread

    private val darkCtx by lazy {
        ContextThemeWrapper(this, androidx.appcompat.R.style.ThemeOverlay_AppCompat_Dark)
    }
    private val app get() = application as SecureSmsApp
    private val m get() = app.messenger
    private var tab = TAB_CONV
    private var benchRunning = false
    private var extraText = ""     // output of Self-test / SMS sizes, shown above the charts

    companion object {
        const val TAB_CONV = 0; const val TAB_CHAT = 1; const val TAB_COMPARE = 2; const val TAB_KEYS = 3
    }

    private lateinit var tabs: TabLayout
    private lateinit var tabConversations: View
    private lateinit var lvConversations: ListView
    private lateinit var tvEmpty: TextView
    private lateinit var btnNewConv: Button
    private lateinit var convAdapter: ConversationAdapter
    private val prefs by lazy { getSharedPreferences("ui", MODE_PRIVATE) }     // last message the user has seen, per contact
    private lateinit var tabChat: View
    private lateinit var tabCompare: View
    private lateinit var tabKeys: View
    private lateinit var spMode: Spinner
    private lateinit var etPhone: EditText
    private lateinit var etMessage: EditText
    private lateinit var tvStatus: TextView
    private lateinit var tvChat: TextView
    private lateinit var scrollChat: ScrollView
    private lateinit var btnVerify: Button
    private lateinit var btnRestart: Button
    private lateinit var btnRetry: Button
    private lateinit var btnSend: Button
    private lateinit var btnBench: Button
    private lateinit var cbLive: CheckBox
    private lateinit var pbBench: ProgressBar
    private lateinit var tvProgress: TextView
    private lateinit var tvCompare: TextView
    private lateinit var tvFp: TextView
    private lateinit var spKeyMode: Spinner
    private var keyMode: Mode = Mode.ECC

    private val permLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { r ->
            if (!r.values.all { it }) toast("Some permissions were denied: SMS (or notifications) will not work fully.")
        }

    // ------------------------------------------------------------------ lifecycle
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tabConversations = findViewById(R.id.tabConversations); lvConversations = findViewById(R.id.lvConversations)
        tvEmpty = findViewById(R.id.tvEmpty); btnNewConv = findViewById(R.id.btnNewConv)
        tabChat = findViewById(R.id.tabChat); tabCompare = findViewById(R.id.tabCompare); tabKeys = findViewById(R.id.tabKeys)
        spMode = findViewById(R.id.spMode); etPhone = findViewById(R.id.etPhone); etMessage = findViewById(R.id.etMessage)
        tvStatus = findViewById(R.id.tvStatus); tvChat = findViewById(R.id.tvChat); scrollChat = findViewById(R.id.scrollChat)
        btnVerify = findViewById(R.id.btnVerify); btnRestart = findViewById(R.id.btnRestart)
        btnRetry = findViewById(R.id.btnRetry); btnSend = findViewById(R.id.btnSend)
        btnBench = findViewById(R.id.btnBench); cbLive = findViewById(R.id.cbLive)
        pbBench = findViewById(R.id.pbBench); tvProgress = findViewById(R.id.tvProgress); tvCompare = findViewById(R.id.tvCompare)
        tvFp = findViewById(R.id.tvFp); spKeyMode = findViewById(R.id.spKeyMode)

        val savedTab = savedInstanceState?.getInt("active_tab", 0) ?: 0

        tabs = findViewById(R.id.tabs)
        for (t in listOf(R.string.tab_conversations, R.string.tab_chat, R.string.tab_compare, R.string.tab_keys)) {
            tabs.addTab(tabs.newTab().setText(t))
        }
        tabs.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(t: TabLayout.Tab) { showTab(t.position) }
            override fun onTabUnselected(t: TabLayout.Tab) {}
            override fun onTabReselected(t: TabLayout.Tab) {}
        })

        if (savedTab != 0) {
            tabs.getTabAt(savedTab)?.select()
        }
        spKeyMode.adapter = ArrayAdapter(darkCtx, R.layout.item_spinner_mode, Mode.entries.map { it.label })
        spKeyMode.setSelection(Mode.ECC.ordinal)
        spKeyMode.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(p: AdapterView<*>?, v: View?, pos: Int, id: Long) { keyMode = Mode.entries[pos]; if (tab == TAB_KEYS) loadKeys() }
            override fun onNothingSelected(p: AdapterView<*>?) {}
        }

        spMode.adapter = ArrayAdapter(darkCtx, R.layout.item_spinner_mode, Mode.entries.map { it.label })
        spMode.setSelection(Mode.ECC.ordinal)
        spMode.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(p: AdapterView<*>?, v: View?, pos: Int, id: Long) { refreshChat() }
            override fun onNothingSelected(p: AdapterView<*>?) {}
        }
        etPhone.doAfterTextChanged { refreshChat() }

        // ---- Chats tab
        convAdapter = ConversationAdapter()
        lvConversations.adapter = convAdapter
        lvConversations.setOnItemClickListener { _, _, pos, _ -> convAdapter.getItem(pos)?.let { openConversation(it) } }
        lvConversations.setOnItemLongClickListener { _, _, pos, _ -> convAdapter.getItem(pos)?.let { confirmDelete(it) }; true }
        btnNewConv.setOnClickListener {
            etPhone.setText(""); tabs.getTabAt(TAB_CHAT)?.select(); etPhone.requestFocus()
        }
        showTab(savedTab)

        btnSend.setOnClickListener { onSend() }
        btnVerify.setOnClickListener { onVerify() }
        btnRestart.setOnClickListener { val k = currentKey() ?: return@setOnClickListener; val md = mode(); worker.execute { m.restartHandshake(k, md) } }
        btnRetry.setOnClickListener { onRetry() }
        btnRetry.isEnabled = true
        findViewById<Button>(R.id.btnBench).setOnClickListener { onBenchmark() }
        findViewById<Button>(R.id.btnSelfTest).setOnClickListener { onSelfTest() }
        findViewById<Button>(R.id.btnSizes).setOnClickListener { onSizes() }
        findViewById<Button>(R.id.btnExportRaw).setOnClickListener { export(summary = false) }
        findViewById<Button>(R.id.btnExportSummary).setOnClickListener { export(summary = true) }
        cbLive.setOnCheckedChangeListener { _, _ -> renderCompare() }
        findViewById<Button>(R.id.btnRotate).setOnClickListener { rotate(keyMode) }

        val needed = buildList {
            add(Manifest.permission.SEND_SMS); add(Manifest.permission.RECEIVE_SMS)
            if (Build.VERSION.SDK_INT >= 33) add(Manifest.permission.POST_NOTIFICATIONS)
        }
        if (needed.any { ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED }) permLauncher.launch(needed.toTypedArray())
        app.store.loadError?.let { toast("STORAGE ERROR - nothing will be saved: $it") }
        refreshChat()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt("active_tab", tab)
    }

    override fun onStart() { super.onStart(); app.ui = this; refreshChat(); refreshConversations() }
    override fun onStop() { super.onStop(); app.ui = null }
    override fun onDestroy() { super.onDestroy(); worker.shutdown() }

    // UiHooks: called from any thread
    override fun changed() = runOnUiThread {
        if (!isFinishing && !isDestroyed) {
            refreshChat()
            refreshConversations()
            if (tab == TAB_COMPARE) renderCompare()
        }
    }

    override fun event(e: Event) = runOnUiThread {
        if (!isFinishing && !isDestroyed) {
            toast("${e.title}: ${e.detail}")
        }
    }

    private fun toast(s: String?) = Toast.makeText(this, s ?: "", Toast.LENGTH_LONG).show()

    private fun showTab(i: Int) {
        tab = i
        tabConversations.visibility = if (i == TAB_CONV) View.VISIBLE else View.GONE
        tabChat.visibility = if (i == TAB_CHAT) View.VISIBLE else View.GONE
        tabCompare.visibility = if (i == TAB_COMPARE) View.VISIBLE else View.GONE
        tabKeys.visibility = if (i == TAB_KEYS) View.VISIBLE else View.GONE
        if (i == TAB_CONV) refreshConversations()
        if (i == TAB_CHAT) refreshChat()
        if (i == TAB_COMPARE) renderCompare()
        if (i == TAB_KEYS) loadKeys()
    }

    // ------------------------------------------------------------------ TAB 0: conversation list
    private fun seenId(key: String) = prefs.getLong("seen_$key", 0L)

    private fun markSeen(key: String) {
        val last = m.lastIncomingId(key)
        if (last > seenId(key)) prefs.edit().putLong("seen_$key", last).apply()
    }

    private fun refreshConversations() {
        val rows = m.conversations()
        convAdapter.clear(); convAdapter.addAll(rows); convAdapter.notifyDataSetChanged()
        tvEmpty.visibility = if (rows.isEmpty()) View.VISIBLE else View.GONE
        lvConversations.visibility = if (rows.isEmpty()) View.GONE else View.VISIBLE
        val unread = rows.sumOf { unreadFor(it) }
        tabs.getTabAt(TAB_CONV)?.text = getString(R.string.tab_conversations) + if (unread > 0) " ($unread)" else ""
    }

    // a conversation that is open on screen counts as read
    private fun unreadFor(r: ConversationRow) =
        if (tab == TAB_CHAT && currentKey() == r.key) 0 else m.unread(r.key, seenId(r.key))

    /** Tapping a row opens it in the Chat tab with the right number and the mode of its latest message. */
    private fun openConversation(r: ConversationRow) {
        etPhone.setText(r.address)
        spMode.setSelection(r.mode.ordinal)
        tabs.getTabAt(TAB_CHAT)?.select()
    }

    private fun confirmDelete(r: ConversationRow) {
        AlertDialog.Builder(this).setTitle(R.string.conv_delete_title).setMessage(R.string.conv_delete_msg)
            .setPositiveButton("Delete") { _, _ -> worker.execute { m.deleteConversation(r.key) } }
            .setNegativeButton("Cancel", null).show()
    }

    private inner class ConversationAdapter : ArrayAdapter<ConversationRow>(this@MainActivity, 0) {
        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val v = convertView ?: layoutInflater.inflate(R.layout.item_conversation, parent, false)
            val r = getItem(position)!!
            val unread = unreadFor(r)
            v.findViewById<TextView>(R.id.tvAvatar).text = if (r.needsAction) "!" else if (r.secure) "🔒" else "✉"
            v.findViewById<TextView>(R.id.tvTitle).apply {
                text = r.address
                setTypeface(null, if (unread > 0) android.graphics.Typeface.BOLD else android.graphics.Typeface.NORMAL)
            }
            v.findViewById<TextView>(R.id.tvPreview).text = r.preview
            v.findViewById<TextView>(R.id.tvMeta).text = r.meta
            val sameDay = SimpleDateFormat("yyyyMMdd", Locale.US).let { it.format(Date(r.ts)) == it.format(Date()) }
            v.findViewById<TextView>(R.id.tvTime).text = SimpleDateFormat(if (sameDay) "HH:mm" else "dd/MM", Locale.US).format(Date(r.ts))
            v.findViewById<TextView>(R.id.tvBadge).apply {
                visibility = if (unread > 0) View.VISIBLE else View.GONE
                text = unread.toString()
            }
            return v
        }
    }

    // ------------------------------------------------------------------ TAB 1: chat
    private fun mode() = Mode.entries[spMode.selectedItemPosition]
    private fun currentKey(): String? = Messenger.key(etPhone.text.toString()).takeIf { it.length >= 4 }

    private fun refreshChat() {
        val key = currentKey()
        if (key == null) {
            tvStatus.text = getString(R.string.status_enter_phone)
            tvChat.text = ""; btnVerify.isEnabled = false
            return
        }
        val sv = m.sessionView(key, mode())
        tvStatus.text = statusText(sv)
        btnVerify.isEnabled = (sv.peerFingerprint != null) && !sv.trusted
        tvChat.text = m.messages(key).joinToString("\n\n") { line(it) }
        scrollChat.post { scrollChat.fullScroll(View.FOCUS_DOWN) }
        if (tab == TAB_CHAT) { markSeen(key); refreshConversations() }
    }

    private fun statusText(sv: SessionView): String {
        val myIp = com.securesms.sms.HybridTransport.getLocalIpAddress()
        val ipInfo = "\n[My IP: $myIp:7777 (or phone #)]"
        val extra = (if (sv.pending > 0) "  [${sv.pending} queued]" else "") + (if (sv.held > 0) "  [${sv.held} held]" else "")
        val base = when {
            sv.identityChanged -> "⚠ The ${sv.mode.label} identity key of this contact CHANGED. Verify the new fingerprint before trusting."
            !sv.exists -> "No ${sv.mode.label} session. Sending starts an automatic key exchange; nothing is sent in clear."
            sv.established -> "Secure ${sv.mode.label} session active (identity verified)."
            sv.hs == Hs.REQ_SENT -> "Key request sent. Waiting for the other phone to answer…"
            sv.hs == Hs.WAIT_TRUST || (!sv.trusted && sv.peerFingerprint != null) -> "Verify this contact's ${sv.mode.label} fingerprint (button below)."
            else -> "Waiting for the contact to confirm the key exchange…"
        }
        return base + extra + ipInfo + "\nMax message in ${sv.mode.label}: ${Messenger.maxPlaintext(sv.mode)} bytes."
    }

    private fun statusWord(x: ChatMessage) = when (x.status) {
        MsgStatus.WAITING_KEY -> "waiting for key exchange"
        MsgStatus.WAITING_TRUST -> "waiting for fingerprint verification"
        MsgStatus.SENDING -> "encrypted, sending"
        MsgStatus.SENT -> "sent (encrypted)"
        MsgStatus.DELIVERED -> "delivered (encrypted)"
        MsgStatus.FAILED -> "NOT SENT"
        MsgStatus.RECEIVED -> "received, authenticated"
        MsgStatus.REJECTED -> "REJECTED"
    }

    private fun line(x: ChatMessage): String {
        val time = SimpleDateFormat("HH:mm", Locale.US).format(Date(x.ts))
        val arrow = if (x.dir == Dir.OUT) "→" else "←"
        if (x.info == Messenger.SYSTEM_INFO) return "$arrow $time ✉ ${x.text}"      // conversation request / key-change note
        val body = x.text ?: "⚠ message rejected (not displayed)"
        val info = x.info?.takeIf { x.status != MsgStatus.RECEIVED }?.let { "\n   $it" } ?: ""
        return "$arrow $time [${x.mode.label}] $body\n   ${statusWord(x)}$info"
    }

    private fun onSend() {
        if (currentKey() == null) { toast("Enter the contact's number."); return }
        val phone = etPhone.text.toString().trim(); val text = etMessage.text.toString(); val md = mode()
        if (text.isBlank()) { toast("Write a message."); return }
        etMessage.setText("")
        worker.execute {
            try {
                m.send(phone, md, text)   // may generate keys / start key exchange: keep off the UI thread
            } catch (e: Exception) {
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        toast(e.message ?: "Failed to send")
                        etMessage.setText(text)
                    }
                }
            }
        }
    }

    private fun onVerify() {
        val key = currentKey() ?: return; val md = mode()
        val peerFp = m.sessionView(key, md).peerFingerprint ?: return
        worker.execute {
            val mine = m.myFingerprint(md)
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                AlertDialog.Builder(this).setTitle("Verify ${md.label} identity")
                    .setMessage("Contact fingerprint (received by SMS):\n$peerFp\n\nYour fingerprint:\n$mine\n\n" +
                        "Ask your contact, in person or by voice call (NOT by SMS), to read the fingerprint under 'My keys' on THEIR phone. Trust only if it matches exactly.")
                    .setPositiveButton("They match - Trust") { _, _ -> worker.execute { m.trust(key, md) } }
                    .setNegativeButton("Reject") { _, _ -> worker.execute { m.rejectPeer(key, md) } }
                    .setNeutralButton("Later", null).show()
            }
        }
    }

    private fun onRetry() {
        val key = currentKey() ?: return
        worker.execute { m.messages(key).filter { it.dir == Dir.OUT && it.status == MsgStatus.FAILED }.forEach { m.retry(it.id) } }
    }

    // ------------------------------------------------------------------ TAB 2: RSA vs ECC
    private fun onBenchmark() {
        if (benchRunning) return
        benchRunning = true
        pbBench.visibility = View.VISIBLE; btnBench.isEnabled = false
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        tvProgress.text = "Running… (keep the phone plugged in; RSA key generation is slow)"
        worker.execute {
            try {
                val res = Benchmark.run(Benchmark.Config(), app.deviceLabel, progress = { label, p ->
                    runOnUiThread {
                        if (!isFinishing && !isDestroyed) {
                            pbBench.progress = (p * 100).toInt()
                            tvProgress.text = label
                        }
                    }
                })
                m.clearSamples("bench"); m.addSamples(res)
            } catch (e: Exception) {
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) toast("Benchmark failed: ${e.javaClass.simpleName} ${e.message}")
                }
            }
            benchRunning = false
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                pbBench.visibility = View.GONE; btnBench.isEnabled = true; tvProgress.text = "Done."
                window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON); renderCompare()
            }
        }
    }

    private fun onSelfTest() {
        tvProgress.text = "Self-test running…"
        worker.execute {
            val lines = ArrayList<String>()
            val ok = SelfTest.run { lines.add(it) }
            extraText = "SELF-TEST ${if (ok) "PASSED" else "FAILED"}\n${lines.joinToString("\n")}\n\n"
            runOnUiThread {
                if (!isFinishing && !isDestroyed) {
                    tvProgress.text = ""
                    renderCompare()
                }
            }
        }
    }

    private fun onSizes() {
        tvProgress.text = "Building real frames…"
        worker.execute {
            val sb = StringBuilder("SMS NEEDED PER FRAME (real frames, GSM-7, 153 chars per segment)\n")
            sb.appendLine("mode    frame           plain  chars  SMS")
            for (r in Sizes.report()) sb.appendLine(String.format(Locale.US, "%-7s %-15s %5d %6d %4d", r.mode.name, r.frame, r.plainBytes, r.chars, r.sms))
            extraText = sb.append("\n").toString()
            runOnUiThread {
                if (!isFinishing && !isDestroyed) {
                    tvProgress.text = ""
                    renderCompare()
                }
            }
        }
    }

    private fun renderCompare() {
        android.util.Log.d("renderCompare", "samples=${m.samples().size}  extra=${extraText.length}ch  live=${cbLive.isChecked}")
        val stats = Stats.summarize(m.samples(), if (cbLive.isChecked) "live" else "bench")
        tvCompare.text = extraText + if (stats.isEmpty())
            (if (cbLive.isChecked) "No real encrypted messages recorded yet." else "No benchmark data yet - tap Benchmark.") else charts(stats) + table(stats)
    }

    private fun bar(v: Double?, mx: Double) = if (v == null) "-" else "█".repeat(((v / mx) * 24).toInt().coerceAtLeast(1)) + String.format(Locale.US, " %.3f ms", v)

    private fun charts(stats: List<Stat>): String {
        fun med(md: Mode, side: String, op: String) = stats.firstOrNull { it.mode == md && it.side == side && it.op == op }?.medianMs
        fun sum(md: Mode, side: String, vararg ops: String): Double? { val l = ops.map { med(md, side, it) }; return if (l.any { it == null }) null else l.sumOf { it!! } }
        fun rsa(md: Mode) = md.family == Family.RSA
        // one block per metric, one bar per key size (every RSA and ECC size that was measured)
        val items: List<Pair<String, (Mode) -> Double?>> = listOf(
            "Identity key generation" to { md -> med(md, "-", "IDENTITY_KEYGEN") },
            "Sender key establishment (RSA-OAEP wrap | ECC ephemeral keygen + ECDH)" to { md -> if (rsa(md)) med(md, "S", "RSA_ENCAP") else sum(md, "S", "KEYGEN_EPHEMERAL", "ECDH") },
            "Receiver key recovery (RSA-OAEP unwrap | ECDH)" to { md -> if (rsa(md)) med(md, "R", "RSA_DECAP") else med(md, "R", "ECDH") },
            "HKDF-SHA-256 (sender)" to { md -> med(md, "S", "HKDF") },
            "AES-256-GCM encrypt" to { md -> med(md, "S", "AES_ENC") },
            "AES-256-GCM decrypt" to { md -> med(md, "R", "AES_DEC") },
            "Signature create (RSA-PSS | ECDSA)" to { md -> med(md, "S", "SIGN") },
            "Signature verify" to { md -> med(md, "R", "VERIFY") },
            "TOTAL sender processing" to { md -> med(md, "S", "TOTAL_SEND") },
            "TOTAL receiver processing" to { md -> med(md, "R", "TOTAL_RECV") },
        )
        val present = Mode.entries.filter { md -> stats.any { it.mode == md } }
        val sb = StringBuilder("MEDIAN TIMES (crypto only, no SMS/network)\n\n")
        for ((title, f) in items) {
            val vals = present.map { it to f(it) }
            val mx = maxOf(vals.maxOfOrNull { it.second ?: 0.0 } ?: 0.0, 1e-9)
            sb.appendLine(title)
            for ((md, v) in vals) sb.appendLine(String.format(Locale.US, " %-9s %s", md.label.substringBefore(" ("), bar(v, mx)))
            sb.appendLine()
        }
        return sb.toString()
    }

    private fun table(stats: List<Stat>): String {
        val sb = StringBuilder("ALL STATISTICS (ms)\nmode    sd operation          n    mean  median   stdev     min     max\n")
        for (s in stats) sb.appendLine(String.format(Locale.US, "%-7s %-2s %-16s %4d %7.3f %7.3f %7.3f %7.3f %7.3f", s.mode.name, s.side, s.op, s.n, s.meanMs, s.medianMs, s.stdMs, s.minMs, s.maxMs))
        return sb.toString()
    }

    private fun export(summary: Boolean) {
        val samples = m.samples()
        if (samples.isEmpty()) { toast("No measurements yet - run the benchmark first."); return }
        val dir = File(cacheDir, "exports").apply { mkdirs() }
        val f = File(dir, if (summary) "securesms_summary.csv" else "securesms_measurements.csv")
        f.writeText(if (summary) Csv.stats(Stats.summarize(samples, "bench")) + "\n" + Csv.stats(Stats.summarize(samples, "live")).lineSequence().drop(1).joinToString("\n") else Csv.samples(samples))
        val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", f)
        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/csv"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(shareIntent, "Export CSV")
        try {
            startActivity(chooser)
        } catch (e: Exception) {
            toast("Could not start export: ${e.message}")
        }
    }

    // ------------------------------------------------------------------ TAB 3: my keys
    private fun loadKeys() {
        val md = keyMode
        val myIp = com.securesms.sms.HybridTransport.getLocalIpAddress()
        tvFp.text = "generating ${md.label} key" + if (md.family == Family.RSA && md.bits >= 3072) " (can take several seconds)…" else "…"
        worker.execute {
            try {
                val fp = m.myFingerprint(md)
                runOnUiThread {
                    if (!isFinishing && !isDestroyed && md == keyMode) {
                        tvFp.text = "My IP Address: $myIp:7777\n\n${md.label} Fingerprint:\n$fp\n\nMax message in ${md.label}: ${Messenger.maxPlaintext(md)} bytes"
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) toast("Failed to generate key: ${e.message}")
                }
            }
        }
    }

    private fun rotate(md: Mode) {
        AlertDialog.Builder(this).setTitle("Rotate ${md.label} key?")
            .setMessage("Contacts will be notified and every contact must verify your new fingerprint again.")
            .setPositiveButton("Rotate") { _, _ ->
                worker.execute {
                    m.rotateIdentity(md)
                    runOnUiThread {
                        if (!isFinishing && !isDestroyed) loadKeys()
                    }
                }
            }
            .setNegativeButton("Cancel", null).show()
    }
}
