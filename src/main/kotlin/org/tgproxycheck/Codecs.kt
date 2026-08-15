package org.tgproxycheck

import java.io.ByteArrayOutputStream

/**
 * Hex and base64url helpers, plus little-endian primitives.
 *
 * Hand-rolled on purpose: `java.util.Base64` is API 26+ on Android and
 * `android.util.Base64` would tie these sources to Android. Everything here is
 * plain Kotlin so the library half of this project drops into an Android module
 * unchanged.
 */

private const val HEX_DIGITS = "0123456789abcdef"

internal fun String.looksHex(): Boolean =
    isNotEmpty() && length % 2 == 0 && all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

internal fun String.decodeHex(): ByteArray {
    require(length % 2 == 0) { "hex string must have an even length" }
    val out = ByteArray(length / 2)
    for (i in out.indices) {
        out[i] = ((hexDigit(this[i * 2]) shl 4) or hexDigit(this[i * 2 + 1])).toByte()
    }
    return out
}

private fun hexDigit(c: Char): Int = when (c) {
    in '0'..'9' -> c - '0'
    in 'a'..'f' -> c - 'a' + 10
    in 'A'..'F' -> c - 'A' + 10
    else -> throw IllegalArgumentException("not a hex digit: '$c'")
}

internal fun ByteArray.toHex(): String {
    val sb = StringBuilder(size * 2)
    for (b in this) {
        sb.append(HEX_DIGITS[(b.toInt() shr 4) and 0xf])
        sb.append(HEX_DIGITS[b.toInt() and 0xf])
    }
    return sb.toString()
}

/** Accepts both the url-safe (-_) and standard (+/) alphabets, padding optional. */
internal fun String.decodeBase64(): ByteArray {
    val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    val out = ByteArrayOutputStream(size(this))
    var acc = 0
    var bits = 0
    for (raw in this) {
        if (raw == '=') break
        val c = when (raw) {
            '+' -> '-'
            '/' -> '_'
            else -> raw
        }
        val v = alphabet.indexOf(c)
        require(v >= 0) { "not base64: '$raw'" }
        acc = (acc shl 6) or v
        bits += 6
        if (bits >= 8) {
            bits -= 8
            out.write((acc shr bits) and 0xff)
        }
    }
    return out.toByteArray()
}

private fun size(s: String) = s.length * 3 / 4 + 3

// ---- little-endian primitives -------------------------------------------------

internal fun le32(value: Int): ByteArray = byteArrayOf(
    (value and 0xff).toByte(),
    ((value shr 8) and 0xff).toByte(),
    ((value shr 16) and 0xff).toByte(),
    ((value ushr 24) and 0xff).toByte(),
)

internal fun le64(value: Long): ByteArray = ByteArray(8) { i ->
    ((value ushr (i * 8)) and 0xff).toByte()
}

internal fun le24(value: Int): ByteArray = byteArrayOf(
    (value and 0xff).toByte(),
    ((value shr 8) and 0xff).toByte(),
    ((value shr 16) and 0xff).toByte(),
)

internal fun readLe32(b: ByteArray, offset: Int): Int =
    (b[offset].toInt() and 0xff) or
        ((b[offset + 1].toInt() and 0xff) shl 8) or
        ((b[offset + 2].toInt() and 0xff) shl 16) or
        ((b[offset + 3].toInt() and 0xff) shl 24)

internal fun readLe64(b: ByteArray, offset: Int): Long {
    var v = 0L
    for (i in 7 downTo 0) v = (v shl 8) or (b[offset + i].toLong() and 0xff)
    return v
}
