package com.ep2pc

import android.app.Application
import com.ep2pc.service.Ep2pcService

class MainApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Start the always-on core service (EP2PC-008 §8.3).
        Ep2pcService.start(this)
    }
}
