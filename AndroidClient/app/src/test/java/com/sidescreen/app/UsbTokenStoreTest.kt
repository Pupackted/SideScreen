package com.sidescreen.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class UsbTokenStoreTest {
    @Test
    fun parsesA32ByteHexToken() {
        val bytes = ByteArray(32) { it.toByte() }
        val hex = bytes.joinToString("") { "%02x".format(it) }
        assertArrayEquals(bytes, UsbTokenStore.parseHex(hex))
        assertArrayEquals(bytes, UsbTokenStore.parseHex(hex.uppercase()))
    }

    @Test
    fun rejectsWrongLengthOrNonHex() {
        assertNull(UsbTokenStore.parseHex(null))
        assertNull(UsbTokenStore.parseHex(""))
        assertNull(UsbTokenStore.parseHex("ab".repeat(31)))
        assertNull(UsbTokenStore.parseHex("ab".repeat(33)))
        assertNull(UsbTokenStore.parseHex("zz".repeat(32)))
    }
}
