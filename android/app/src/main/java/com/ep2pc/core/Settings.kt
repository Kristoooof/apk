package com.ep2pc.core

import android.content.Context

/**
 * Small persistent settings store (EP2PC-008 §8.7). Backed by SharedPreferences so values
 * survive restarts — this is where the user's VPS relay/bootstrap address lives.
 */
object Settings {
    private const val PREFS = "ep2pc_settings"
    private const val KEY_RELAY = "relay_addr"
    private const val KEY_DISPLAY_NAME = "display_name"

    private fun prefs(ctx: Context) =
        ctx.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** The VPS relay/bootstrap multiaddr, e.g. `/ip4/1.2.3.4/tcp/4001/p2p/12D3Koo...` */
    fun getRelay(ctx: Context): String = prefs(ctx).getString(KEY_RELAY, "") ?: ""

    fun setRelay(ctx: Context, value: String) {
        prefs(ctx).edit().putString(KEY_RELAY, value.trim()).apply()
    }

    fun getDisplayName(ctx: Context): String = prefs(ctx).getString(KEY_DISPLAY_NAME, "") ?: ""

    fun setDisplayName(ctx: Context, value: String) {
        prefs(ctx).edit().putString(KEY_DISPLAY_NAME, value.trim()).apply()
    }
}
