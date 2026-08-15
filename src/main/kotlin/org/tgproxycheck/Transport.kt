package org.tgproxycheck

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream

/**
 * The byte pipe the obfuscated2 layer sits on. Either the socket directly, or
 * the faketls record layer pretending to be one.
 */
internal interface Transport {
    fun write(data: ByteArray)
    fun readExact(n: Int): ByteArray
}

/** Straight through to the socket, for plain and `dd` secrets. */
internal class PlainTransport(
    private val input: InputStream,
    private val output: OutputStream,
) : Transport {
    override fun write(data: ByteArray) {
        output.write(data)
        output.flush()
    }

    override fun readExact(n: Int): ByteArray = input.readExact(n)
}

internal fun InputStream.readExact(n: Int): ByteArray {
    val buf = ByteArray(n)
    var offset = 0
    while (offset < n) {
        val read = read(buf, offset, n - offset)
        if (read < 0) throw EOFException("closed after $offset of $n bytes")
        offset += read
    }
    return buf
}
