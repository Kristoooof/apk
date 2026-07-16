package com.ep2pc.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * Restarts the core service after device reboot so availability isn't lost to a restart
 * (EP2PC-008 §8.3). Only fires if the user granted the boot permission.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            Ep2pcService.start(context)
        }
    }
}
