package com.ep2pc.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.ep2pc.R
import com.ep2pc.core.NativeBridge

/**
 * Long-lived foreground service that keeps the libp2p socket alive (EP2PC-008 §8.3).
 *
 * There is NO polling and NO wakelock here: once [NativeBridge.start] launches the Rust
 * event loop, the process parks on epoll and consumes ~0% CPU at rest (EP2PC-001 §1.4).
 * The foreground notification is the only thing Android requires to keep us running.
 */
class Ep2pcService : Service() {

    // Without a held MulticastLock, Android's Wi-Fi driver drops inbound multicast packets,
    // so libp2p mDNS never discovers peers on the same LAN (EP2PC-003 §3.4.1). The
    // CHANGE_WIFI_MULTICAST_STATE permission alone does nothing — the lock must be held.
    private var multicastLock: WifiManager.MulticastLock? = null

    override fun onCreate() {
        super.onCreate()
        startForeground(NOTIF_ID, buildNotification())
        acquireMulticastLock()
        // The DB key must be fetched from the Android Keystore (EP2PC-007 §7.2).
        val dbKey = KeystoreKeys.getOrCreateDbKey(this)
        val dbPath = filesDir.resolve("ep2pc.db").absolutePath
        val relay = com.ep2pc.core.Settings.getRelay(this)
        NativeBridge.start(dbPath, dbKey, relay)
    }

    private fun acquireMulticastLock() {
        try {
            val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            multicastLock = wifi.createMulticastLock("ep2pc-mdns").apply {
                setReferenceCounted(false)
                acquire()
            }
        } catch (e: Exception) {
            // Non-fatal: mDNS won't work but DHT/bootstrap discovery still can.
        }
    }

    override fun onDestroy() {
        try {
            multicastLock?.let { if (it.isHeld) it.release() }
        } catch (_: Exception) {
        }
        multicastLock = null
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    override fun onBind(intent: Intent?): IBinder? = null

    private fun buildNotification(): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.service_channel_name),
                NotificationManager.IMPORTANCE_MIN // silent, minimal
            ).apply { setShowBadge(false) }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.service_running))
            .setSmallIcon(R.drawable.ic_stat_ep2pc)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "ep2pc_core"
        private const val NOTIF_ID = 1

        fun start(ctx: Context) {
            val intent = Intent(ctx, Ep2pcService::class.java)
            ctx.startForegroundService(intent)
        }
    }
}
