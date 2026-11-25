package com.securesms.sms

import android.content.Context
import android.util.Log
import com.securesms.messaging.Messenger
import com.securesms.messaging.SmsStatus
import com.securesms.messaging.SmsTransport
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

/**
 * TCP socket-based transport allowing direct IP frame exchange between physical devices and emulators
 * over LAN/Wi-Fi or adb port forwarding, as well as standard cellular SMS via [AndroidSms].
 */
class HybridTransport(
    private val ctx: Context,
    private val androidSms: AndroidSms = AndroidSms(ctx),
    val port: Int = DEFAULT_PORT
) : SmsTransport {

    companion object {
        const val DEFAULT_PORT = 7777
        private const val TAG = "HybridTransport"

        fun getLocalIpAddress(): String {
            try {
                val interfaces = NetworkInterface.getNetworkInterfaces() ?: return "127.0.0.1"
                for (iface in interfaces) {
                    if (iface.isLoopback || !iface.isUp) continue
                    val addrs = iface.inetAddresses
                    for (addr in addrs) {
                        if (!addr.isLoopbackAddress && addr is Inet4Address) {
                            val ip = addr.hostAddress
                            if (!ip.isNullOrBlank()) return ip
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error finding local IP", e)
            }
            return "127.0.0.1"
        }
    }

    private var serverSocket: ServerSocket? = null
    @Volatile var messenger: Messenger? = null
    @Volatile private var isListening = false

    fun startListening(messengerSupplier: () -> Messenger) {
        if (isListening) return
        isListening = true
        thread(name = "SecureSMS-SocketServer", isDaemon = true) {
            try {
                val ss = ServerSocket(port)
                serverSocket = ss
                Log.d(TAG, "Listening for SecureSMS network frames on port $port")
                while (isListening && !ss.isClosed) {
                    try {
                        val socket = ss.accept()
                        handleIncomingSocket(socket, messengerSupplier)
                    } catch (e: Exception) {
                        if (isListening) Log.e(TAG, "Error accepting socket connection", e)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Could not start ServerSocket on port $port", e)
            }
        }
    }

    private fun handleIncomingSocket(socket: Socket, messengerSupplier: () -> Messenger) {
        thread(isDaemon = true) {
            try {
                socket.soTimeout = 5000
                val reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8))
                val line = reader.readLine() ?: return@thread
                if (line.startsWith("SSMS|")) {
                    val remoteHost = socket.inetAddress.hostAddress ?: "127.0.0.1"
                    val writer = PrintWriter(socket.getOutputStream(), true)
                    writer.println("OK")
                    socket.close()
                    val m = messengerSupplier()
                    m.onSms(remoteHost, line)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error handling incoming frame", e)
            } finally {
                try { if (!socket.isClosed) socket.close() } catch (_: Exception) {}
            }
        }
    }

    override fun send(address: String, text: String, tag: Long) {
        val trimmed = address.trim()
        val isNetworkTarget = trimmed.contains(".") || trimmed.lowercase(java.util.Locale.ROOT).contains("localhost")

        if (isNetworkTarget) {
            sendOverNetwork(trimmed, text, tag)
        } else {
            try {
                androidSms.send(trimmed, text, tag)
            } catch (e: Exception) {
                Log.w(TAG, "Cellular SMS send failed, attempting IP fallback for $trimmed: ${e.message}")
                sendOverNetwork("127.0.0.1", text, tag)
            }
        }
    }

    private fun sendOverNetwork(address: String, text: String, tag: Long) {
        val host: String
        val targetPort: Int
        if (address.contains(":")) {
            host = address.substringBefore(":")
            targetPort = address.substringAfter(":").toIntOrNull() ?: port
        } else {
            host = address
            targetPort = port
        }

        try {
            val socket = Socket(host, targetPort)
            socket.soTimeout = 5000
            val writer = PrintWriter(socket.getOutputStream(), true)
            val reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.UTF_8))
            writer.println(text)
            reader.readLine()
            socket.close()

            if (tag > 0) {
                messenger?.onSmsStatus(tag, SmsStatus.SENT, null)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send frame to $host:$targetPort: ${e.message}")
            if (tag > 0) {
                messenger?.onSmsStatus(tag, SmsStatus.FAILED, "Network error: ${e.message}")
            }
            throw IllegalStateException("Network send to $host:$targetPort failed: ${e.message}", e)
        }
    }

    fun stop() {
        isListening = false
        try { serverSocket?.close() } catch (_: Exception) {}
    }
}
