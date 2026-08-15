package org.tgproxycheck

/**
 * Transport mode, selected by the shape of the proxy secret.
 *
 * The mapping is dictated by the secret's first byte and length, and it decides
 * both the protocol tag written into the obfuscated2 init frame and the packet
 * framing used afterwards.
 */
enum class ProxyMode {
    /** Plain 16-byte secret. Init tag 0xef, abridged framing, no padding. */
    ABRIDGED,

    /** Secret prefixed with 0xdd. Init tag 0xdd, int32 length prefix, padded. */
    PADDED,

    /** Secret prefixed with 0xee. Padded framing wrapped in a faketls session. */
    FAKE_TLS,
}

/**
 * A parsed MTProxy secret.
 *
 * Accepts hex or base64 (url-safe or standard). The three recognised shapes:
 *
 *   16 bytes                -> ABRIDGED, key material = the whole secret
 *   >=17 bytes, [0] == 0xdd -> PADDED,   key material = bytes 1..17
 *   >17 bytes,  [0] == 0xee -> FAKE_TLS, key material = bytes 1..17,
 *                                        SNI domain  = bytes 17..
 */
class ProxySecret private constructor(
    val raw: ByteArray,
    /** The bytes folded into both obfuscation keys. */
    val keyMaterial: ByteArray,
    val mode: ProxyMode,
    /** Domain to present as SNI. Non-null only for [ProxyMode.FAKE_TLS]. */
    val tlsDomain: String?,
) {
    override fun toString() = "ProxySecret(mode=$mode" + (tlsDomain?.let { ", domain=$it" } ?: "") + ")"

    companion object {
        private val DD = 0xdd.toByte()
        private val EE = 0xee.toByte()

        fun parse(text: String): ProxySecret {
            val t = text.trim()
            require(t.isNotEmpty()) { "empty secret" }
            val raw = if (t.looksHex()) t.decodeHex() else t.decodeBase64()
            require(raw.isNotEmpty()) { "secret decoded to zero bytes" }

            return when {
                raw.size >= 17 && raw[0] == DD ->
                    ProxySecret(raw, raw.copyOfRange(1, 17), ProxyMode.PADDED, null)

                raw.size > 17 && raw[0] == EE ->
                    ProxySecret(
                        raw,
                        raw.copyOfRange(1, 17),
                        ProxyMode.FAKE_TLS,
                        String(raw, 17, raw.size - 17, Charsets.US_ASCII),
                    )

                else ->
                    ProxySecret(raw, raw.copyOfRange(0, minOf(16, raw.size)), ProxyMode.ABRIDGED, null)
            }
        }
    }
}
