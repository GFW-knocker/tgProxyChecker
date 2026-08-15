package org.tgproxycheck

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class FakeTlsTest {

    private val random = SecureRandom()
    private val domain = "www.google.com"
    private val secret = ProxySecret.parse(
        "ee00112233445566778899aabbccddeeff" + domain.toByteArray().toHex()
    )

    private fun be16(b: ByteArray, offset: Int) =
        ((b[offset].toInt() and 0xff) shl 8) or (b[offset + 1].toInt() and 0xff)

    // ---- key shares -----------------------------------------------------------

    /**
     * The output is an x-coordinate after three doublings. If the derivation is
     * right it is still on the curve, i.e. y² is a quadratic residue mod p.
     */
    @Test
    fun `x25519 key lands on the curve`() {
        val p = BigInteger.TWO.pow(255) - BigInteger.valueOf(19)
        val a = BigInteger.valueOf(486662)

        repeat(5) {
            val key = KeyShares.x25519PublicKey(random)
            assertEquals(32, key.size)

            val x = BigInteger(1, key.reversedArray()) // stored little-endian
            val y2 = (((x + a).mod(p) * x).mod(p) + BigInteger.ONE).mod(p).multiply(x).mod(p)
            val legendre = y2.modPow((p - BigInteger.ONE) / BigInteger.TWO, p)
            assertEquals(BigInteger.ONE, legendre, "point is on the twist, not the curve")
        }
    }

    @Test
    fun `ml-kem key packs coefficients below q`() {
        val key = KeyShares.mlKem768PublicKey(random)
        assertEquals(1184, key.size)

        // Unpack the 12-bit pairs back out and check every coefficient is < 3329.
        for (i in 0 until 384) {
            val b0 = key[i * 3].toInt() and 0xff
            val b1 = key[i * 3 + 1].toInt() and 0xff
            val b2 = key[i * 3 + 2].toInt() and 0xff
            val first = b0 or ((b1 and 0x0f) shl 8)
            val second = (b1 shr 4) or (b2 shl 4)
            assertTrue(first < 3329, "coefficient $i low = $first")
            assertTrue(second < 3329, "coefficient $i high = $second")
        }
    }

    // ---- client hello ---------------------------------------------------------

    @Test
    fun `hello has consistent nested lengths`() {
        val hello = TlsHello(domain, random).build()

        assertContentEquals(byteArrayOf(0x16, 0x03, 0x01), hello.copyOfRange(0, 3))
        assertEquals(hello.size - 5, be16(hello, 3), "record length")

        assertEquals(0x01, hello[5].toInt(), "ClientHello handshake type")
        assertEquals(0x00, hello[6].toInt(), "high byte of the 3-byte handshake length")
        assertEquals(hello.size - 9, be16(hello, 7), "handshake length")

        assertContentEquals(byteArrayOf(0x03, 0x03), hello.copyOfRange(9, 11))
        assertEquals(0x20, hello[43].toInt(), "session id length")
        assertEquals(32, be16(hello, 76), "cipher suites length")
        assertContentEquals(byteArrayOf(0x01, 0x00), hello.copyOfRange(110, 112))
        assertEquals(hello.size - 114, be16(hello, 112), "extensions length")
    }

    @Test
    fun `hello leaves the digest field zeroed and carries the domain`() {
        val hello = TlsHello(domain, random).build()

        val digestField = hello.copyOfRange(TlsHello.DIGEST_OFFSET, TlsHello.DIGEST_OFFSET + 32)
        assertContentEquals(ByteArray(32), digestField)

        assertTrue(
            hello.toHex().contains(domain.toByteArray().toHex()),
            "SNI domain missing from the hello",
        )
    }

    @Test
    fun `hello varies between builds`() {
        val first = TlsHello(domain, random).build()
        val second = TlsHello(domain, random).build()
        // Permuted extensions and fresh GREASE mean two hellos should never match.
        assertTrue(!first.contentEquals(second), "hello is deterministic - JA3 would be fixed")
    }

    @Test
    fun `hello is large enough to carry the ml-kem share`() {
        val hello = TlsHello(domain, random).build()
        assertTrue(hello.size > 1184, "hello is only ${hello.size} bytes")
    }

    // ---- record layer ---------------------------------------------------------

    @Test
    fun `first write is preceded by change cipher spec`() {
        val out = ByteArrayOutputStream()
        val transport = FakeTls.RecordTransport(ByteArrayInputStream(ByteArray(0)), out)

        transport.write("hello".toByteArray())
        val written = out.toByteArray()

        assertContentEquals(
            byteArrayOf(0x14, 0x03, 0x03, 0x00, 0x01, 0x01) + // ChangeCipherSpec
                byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x05) +   // application data, 5 bytes
                "hello".toByteArray(),
            written,
        )

        // The second write must not repeat the ChangeCipherSpec.
        out.reset()
        transport.write("x".toByteArray())
        assertContentEquals(byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x01, 'x'.code.toByte()), out.toByteArray())
    }

    @Test
    fun `reads reassemble across record boundaries`() {
        val stream = record("abc".toByteArray()) + record("defgh".toByteArray())
        val transport = FakeTls.RecordTransport(ByteArrayInputStream(stream), ByteArrayOutputStream())

        // Spans the first record and part of the second.
        assertContentEquals("abcd".toByteArray(), transport.readExact(4))
        assertContentEquals("efgh".toByteArray(), transport.readExact(4))
    }

    @Test
    fun `rejects a non application-data record`() {
        val stream = byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x01, 0x00)
        val transport = FakeTls.RecordTransport(ByteArrayInputStream(stream), ByteArrayOutputStream())

        val failure = assertFailsWith<IllegalArgumentException> { transport.readExact(1) }
        assertTrue(failure.message!!.contains("application-data"))
    }

    private fun record(payload: ByteArray) =
        byteArrayOf(0x17, 0x03, 0x03, ((payload.size shr 8) and 0xff).toByte(), (payload.size and 0xff).toByte()) +
            payload
}
