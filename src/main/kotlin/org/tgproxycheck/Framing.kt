package org.tgproxycheck

import java.security.SecureRandom

/**
 * Packet framing. The length prefix travels on the same AES-CTR stream as the
 * payload, so callers must encrypt/decrypt through a single [Obfuscated2] in
 * strict wire order.
 *
 * The functions here work on plaintext only, which keeps them unit-testable
 * without a socket or a cipher.
 */
internal object Framing {

    /** Largest packet we will believe from the wire, as a sanity bound. */
    private const val MAX_PACKET = 1 shl 20

    /**
     * Builds a plaintext packet: length prefix, payload, and padding where the
     * mode calls for it. Encrypt the whole result in one pass.
     */
    fun buildPacket(payload: ByteArray, mode: ProxyMode, random: SecureRandom): ByteArray =
        when (mode) {
            ProxyMode.ABRIDGED -> {
                require(payload.size % 4 == 0) {
                    "abridged framing needs a payload length divisible by 4, got ${payload.size}"
                }
                val quarters = payload.size / 4
                if (quarters < 0x7f) {
                    byteArrayOf(quarters.toByte()) + payload
                } else {
                    byteArrayOf(0x7f) + le24(quarters) + payload
                }
            }

            ProxyMode.PADDED, ProxyMode.FAKE_TLS -> {
                // Unencrypted packets take 0..256 bytes of padding, and the length
                // prefix covers payload plus padding. The receiver recovers the
                // real size from the MTProto header, so trailing bytes are ignored.
                val pad = ByteArray(random.nextInt(257))
                if (pad.isNotEmpty()) random.nextBytes(pad)
                le32(payload.size + pad.size) + payload + pad
            }
        }

    /**
     * Reads one packet. [readExact] pulls raw bytes off the socket, [decrypt]
     * advances the receive keystream. Returns the decrypted packet body, padding
     * included.
     */
    fun readPacket(
        mode: ProxyMode,
        readExact: (Int) -> ByteArray,
        decrypt: (ByteArray) -> ByteArray,
    ): ByteArray {
        val length = when (mode) {
            ProxyMode.ABRIDGED -> {
                val first = decrypt(readExact(1))[0].toInt() and 0xff
                // Bit 7 marks a quick-ack. We never request one, so seeing it means
                // the stream is not what we think it is.
                require((first and 0x80) == 0) { "unexpected quick-ack byte 0x${first.toString(16)}" }
                if (first == 0x7f) {
                    val more = decrypt(readExact(3))
                    val quarters = (more[0].toInt() and 0xff) or
                        ((more[1].toInt() and 0xff) shl 8) or
                        ((more[2].toInt() and 0xff) shl 16)
                    quarters * 4
                } else {
                    first * 4
                }
            }

            ProxyMode.PADDED, ProxyMode.FAKE_TLS -> readLe32(decrypt(readExact(4)), 0)
        }

        require(length in 1..MAX_PACKET) { "implausible packet length: $length" }
        return decrypt(readExact(length))
    }
}
