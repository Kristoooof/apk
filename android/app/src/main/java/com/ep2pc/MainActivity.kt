package com.ep2pc

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import com.ep2pc.ui.Ep2pcApp
import com.ep2pc.ui.theme.Ep2pcTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            Ep2pcTheme {
                Surface(color = MaterialTheme.colorScheme.background) {
                    Ep2pcApp()
                }
            }
        }
    }
}
