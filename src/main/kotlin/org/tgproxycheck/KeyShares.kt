package org.tgproxycheck

import java.math.BigInteger
import java.security.SecureRandom

/**
 * Key-share payloads for the faketls ClientHello.
 *
 * Nothing on the other end validates these — the proxy only HMACs the hello and
 * never runs a TLS state machine. They are generated properly anyway so the
 * bytes stand up to inspection by anything that does look.
 */
internal object KeyShares {

    private val P: BigInteger = BigInteger.TWO.pow(255) - BigInteger.valueOf(19)
    private val LEGENDRE_EXPONENT: BigInteger = (P - BigInteger.ONE) / BigInteger.TWO
    private val A: BigInteger = BigInteger.valueOf(486662)
    private val FOUR: BigInteger = BigInteger.valueOf(4)

    /**
     * A Curve25519 u-coordinate, 32 bytes little-endian.
     *
     * Rejection-samples an x whose y² is a quadratic residue (so the point is on
     * the curve rather than the twist), then triples it through the doubling
     * formula.
     */
    fun x25519PublicKey(random: SecureRandom): ByteArray {
        var x: BigInteger
        while (true) {
            val candidate = ByteArray(32)
            random.nextBytes(candidate)
            candidate[31] = (candidate[31].toInt() and 127).toByte()
            x = BigInteger(1, candidate).modPow(BigInteger.TWO, P)
            if (y2(x).modPow(LEGENDRE_EXPONENT, P) == BigInteger.ONE) break
        }
        repeat(3) { x = doubleX(x) }

        val out = ByteArray(32)
        val magnitude = x.toByteArray()
        val source = if (magnitude.size > 32) magnitude.copyOfRange(magnitude.size - 32, magnitude.size) else magnitude
        source.copyInto(out, 32 - source.size)
        out.reverse() // big-endian -> little-endian
        return out
    }

    /** y² = x³ + 486662x² + x, evaluated as ((x + A) * x + 1) * x. */
    private fun y2(x: BigInteger): BigInteger =
        (((x + A).mod(P) * x).mod(P) + BigInteger.ONE).mod(P).multiply(x).mod(P)

    /** x₂ = (x² - 1)² / (4y²) */
    private fun doubleX(x: BigInteger): BigInteger {
        val denominator = (y2(x) * FOUR).mod(P).modInverse(P)
        val numerator = (x.modPow(BigInteger.TWO, P) - BigInteger.ONE).mod(P).modPow(BigInteger.TWO, P)
        return (numerator * denominator).mod(P)
    }

    /**
     * An ML-KEM-768 public key, 1184 bytes: 384 coefficient pairs packed 12 bits
     * each, then a 32-byte seed.
     */
    fun mlKem768PublicKey(random: SecureRandom): ByteArray {
        val q = 3329L
        val key = ByteArray(1184)
        for (i in 0 until 384) {
            val a = (random.nextInt().toLong() and 0xFFFFFFFFL) % q
            val b = (random.nextInt().toLong() and 0xFFFFFFFFL) % q
            key[i * 3] = (a and 0xff).toByte()
            key[i * 3 + 1] = (((a shr 8) or ((b and 0x0f) shl 4)) and 0xff).toByte()
            key[i * 3 + 2] = ((b shr 4) and 0xff).toByte()
        }
        val seed = ByteArray(32)
        random.nextBytes(seed)
        seed.copyInto(key, 1152)
        return key
    }
}
