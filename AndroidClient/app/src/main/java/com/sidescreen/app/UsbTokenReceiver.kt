package com.sidescreen.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import java.io.File

/**
 * Receives the USB auth token from the Mac over adb.
 *
 * The Mac runs `am broadcast -n <this receiver> --es token <hex>` through
 * `adb shell`. The manifest guards this receiver with `android.permission.DUMP`,
 * which only the adb shell and the system hold, so no other app on the tablet
 * can plant a token. The token is needed because USB streaming goes through
 * `adb reverse`, which opens the Mac's port on the tablet's localhost — where
 * every app can reach it.
 */
class UsbTokenReceiver : BroadcastReceiver() {
    override fun onReceive(
        context: Context,
        intent: Intent,
    ) {
        if (intent.action != ACTION) return
        val token = UsbTokenStore.parseHex(intent.getStringExtra(EXTRA_TOKEN)) ?: run {
            Log.w(TAG, "Ignoring malformed USB token broadcast")
            return
        }
        UsbTokenStore.save(context, token)
        Log.i(TAG, "USB token updated")
    }

    companion object {
        const val ACTION = "com.sidescreen.app.SET_USB_TOKEN"
        const val EXTRA_TOKEN = "token"
        private const val TAG = "UsbTokenReceiver"
    }
}

/**
 * Stores the 32-byte USB token in a private file under `noBackupFilesDir`, so
 * it never leaves the device in a backup.
 */
object UsbTokenStore {
    private const val FILE_NAME = "usb_auth_token"
    const val TOKEN_LEN = 32

    private fun file(context: Context) = File(context.noBackupFilesDir, FILE_NAME)

    fun load(context: Context): ByteArray? =
        runCatching { file(context).readBytes() }.getOrNull()?.takeIf { it.size == TOKEN_LEN }

    fun save(
        context: Context,
        token: ByteArray,
    ) {
        require(token.size == TOKEN_LEN)
        val target = file(context)
        val tmp = File(target.parentFile, "$FILE_NAME.tmp")
        tmp.writeBytes(token)
        if (!tmp.renameTo(target)) {
            target.writeBytes(token)
            tmp.delete()
        }
    }

    fun parseHex(hex: String?): ByteArray? {
        if (hex == null || hex.length != TOKEN_LEN * 2) return null
        val out = ByteArray(TOKEN_LEN)
        for (i in 0 until TOKEN_LEN) {
            val hi = Character.digit(hex[i * 2], 16)
            val lo = Character.digit(hex[i * 2 + 1], 16)
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }
}
