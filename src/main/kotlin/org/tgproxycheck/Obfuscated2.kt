package org.tgproxycheck

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * CTR is a stream mode, so update() must return exactly as many bytes as it was
 * given. Assert it rather than trust it: a provider that buffered would
 * desynchronise the keystream in a way that is painful to debug later.
 */
private fun Cipher.stream(data: ByteArray): ByteArray {
    if (data.isEmpty()) return data
    val out = update(data) ?: ByteArray(0)
    check(out.size == data.size) {
        "AES/CTR provider buffered ${data.size - out.size} of ${data.size} bytes; " +
            "keystream would desynchronise"
    }
    return out
}

/**
 * MTProto "obfuscated2" transport: a 64-byte init frame that carries the AES-CTR
 * keys for the rest of the connection, plus the running cipher state.
 *
 * Note what this does *not* use: no javax.net.ssl, no SSLSocket, no TrustManager,
 * no HostnameVerifier. There is no certificate anywhere in this protocol, so
 * there is nothing to validate and nothing for a Play Store scanner to flag.
 * Only AES-CTR and SHA-256 are needed, both from the platform JCE.
 */
internal class Obfuscated2 private constructor(
    /** Send these 64 bytes verbatim as the very first thing on the socket. */
    val initFrame: ByteArray,
    private val enc: Cipher,
    private val dec: Cipher,
) {
    fun encrypt(data: ByteArray): ByteArray = enc.stream(data)

    fun decrypt(data: ByteArray): ByteArray = dec.stream(data)

    companion object {
        fun create(secret: ProxySecret, dcId: Short, random: SecureRandom): Obfuscated2 {
            val f = ByteArray(64)
            do {
                random.nextBytes(f)
            } while (!acceptable(f, secret.mode))

            val tag: Byte = when (secret.mode) {
                ProxyMode.ABRIDGED -> 0xef.toByte()
                // Padded-intermediate. faketls carries the same inner tag; the TLS
                // mimicry is an outer wrapper, not a different framing.
                ProxyMode.PADDED, ProxyMode.FAKE_TLS -> 0xdd.toByte()
            }
            for (i in 56 until 60) f[i] = tag

            // int16 LE datacenter id. The proxy reads this and dials the DC for us,
            // which is why this client never needs a Telegram IP address.
            f[60] = (dcId.toInt() and 0xff).toByte()
            f[61] = ((dcId.toInt() shr 8) and 0xff).toByte()

            // Send keys come from bytes 8..56; receive keys from the same range
            // reversed. Both are folded with the secret via SHA-256.
            val encKey = sha256(f.copyOfRange(8, 40) + secret.keyMaterial)
            val encIv = f.copyOfRange(40, 56)
            val reversed = f.copyOfRange(8, 56).reversedArray()
            val decKey = sha256(reversed.copyOfRange(0, 32) + secret.keyMaterial)
            val decIv = reversed.copyOfRange(32, 48)

            val enc = ctr(encKey, encIv)
            val dec = ctr(decKey, decIv)

            // All 64 bytes must run through the cipher so the CTR counter lands in
            // the right place for the first real packet, even though only the last
            // 8 bytes are transmitted in their encrypted form. Skipping this is the
            // classic way to get a connection that handshakes and then decodes to
            // garbage.
            val scrambled = enc.stream(f)
            val frame = f.copyOfRange(0, 56) + scrambled.copyOfRange(56, 64)

            return Obfuscated2(frame, enc, dec)
        }

        /**
         * Reject frames the proxy would mistake for something else: an abridged
         * tag in first position, an HTTP verb, a protocol tag, or a zero word at
         * offset 4.
         */
        internal fun acceptable(f: ByteArray, mode: ProxyMode): Boolean {
            // faketls hides the frame inside a TLS record, so these collisions
            // cannot occur and the checks are skipped.
            if (mode == ProxyMode.FAKE_TLS) return true
            if (f[0] == 0xef.toByte()) return false
            val first = readLe32(f, 0)
            if (first == 0x44414548 || // "HEAD"
                first == 0x54534f50 || // "POST"
                first == 0x20544547 || // "GET "
                first == 0x4954504f || // "OPTI"
                first == 0xeeeeeeee.toInt() ||
                first == 0xdddddddd.toInt() ||
                first == 0x02010316
            ) {
                return false
            }
            return readLe32(f, 4) != 0
        }

        private fun sha256(data: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(data)

        private fun ctr(key: ByteArray, iv: ByteArray): Cipher =
            Cipher.getInstance("AES/CTR/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            }
    }
}
