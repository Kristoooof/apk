package com.ep2pc.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val Teal = Color(0xFF0A7E7A)
private val TealDark = Color(0xFF063E3C)

private val LightColors = lightColorScheme(primary = Teal, secondary = TealDark)
private val DarkColors = darkColorScheme(primary = Teal, secondary = TealDark)

@Composable
fun Ep2pcTheme(darkTheme: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content
    )
}
