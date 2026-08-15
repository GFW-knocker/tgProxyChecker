package org.tgproxycheck

import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The faketls outer layer.
 *
 * Emphatically not TLS: no cipher negotiation, no key exchange, no certificate.
 * The client emits a ClientHello whose `random` field carries
 * `HMAC-SHA256(secret, hello)`, the proxy answers with a fixed-shape response
 * carrying the same HMAC over what it sent, and afterwards both sides simply
 * wrap bytes in application-data records.
 *
 * This means no `SSLSocket`, no `TrustManager`, and no certificate validation to
 * get wrong — the whole layer is byte construction over a plain socket.
 */
internal object FakeTls {

    private val SERVER_HELLO_PREFIX = byteArrayOf(0x16, 0x03, 0x03)
    private val CHANGE_CIPHER_SPEC = byteArrayOf(0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
    private val APPLICATION_DATA = byteArrayOf(0x17, 0x03, 0x03)

    /** ChangeCipherSpec followed by the start of the first application record. */
    private val SERVER_MIDDLE = CHANGE_CIPHER_SPEC + APPLICATION_DATA

    /**
     * Performs the handshake. Throws with a specific reason on any mismatch;
     * returns normally when the proxy has proven it knows the secret.
     */
    fun handshake(
        secret: ProxySecret,
        input: InputStream,
        output: OutputStream,
        random: SecureRandom,
    ) {
        val domain = requireNotNull(secret.tlsDomain) { "faketls secret carries no domain" }
        val hello = TlsHello(domain, random).build()

        // The digest is computed over the hello with the random field still zero,
        // then written into that field.
        val digest = hmac(secret.keyMaterial, hello)
        mixInTimestamp(digest)
        digest.copyInto(hello, TlsHello.DIGEST_OFFSET)

        output.write(hello)
        output.flush()

        val response = readServerHello(input)

        // The server's digest sits in the same place and is computed the same
        // way, over our digest followed by its own response with that field
        // zeroed.
        val serverDigest = response.copyOfRange(TlsHello.DIGEST_OFFSET, TlsHello.DIGEST_OFFSET + 32)
        response.fill(0, TlsHello.DIGEST_OFFSET, TlsHello.DIGEST_OFFSET + 32)
        val expected = hmac(secret.keyMaterial, digest + response)

        require(expected.contentEquals(serverDigest)) {
            "faketls digest mismatch - wrong secret, or something on the path is not the proxy"
        }
    }

    /**
     * Reads the three-part response: ServerHello record, ChangeCipherSpec, and
     * the first application-data record.
     */
    private fun readServerHello(input: InputStream): ByteArray {
        val head = input.readExact(5)
        require(head.copyOfRange(0, 3).contentEquals(SERVER_HELLO_PREFIX)) {
            "not a TLS ServerHello: ${head.copyOfRange(0, 3).toHex()}"
        }
        val helloLength = beInt16(head, 3)
        require(helloLength <= 64 * 1024 - 5) { "implausible ServerHello length: $helloLength" }
        val helloBody = input.readExact(helloLength)

        val middle = input.readExact(SERVER_MIDDLE.size)
        require(middle.contentEquals(SERVER_MIDDLE)) {
            "expected ChangeCipherSpec + application data, got ${middle.toHex()}"
        }

        val lengthBytes = input.readExact(2)
        val dataLength = beInt16(lengthBytes, 0)
        require(dataLength <= 64 * 1024) { "implausible application data length: $dataLength" }
        val data = input.readExact(dataLength)

        return head + helloBody + middle + lengthBytes + data
    }

    /**
     * The low 4 bytes of the digest tail carry the timestamp, little-endian, so
     * the proxy can reject stale hellos.
     */
    private fun mixInTimestamp(digest: ByteArray) {
        val now = (System.currentTimeMillis() / 1000).toInt()
        val existing = readLe32(digest, 28)
        le32(existing xor now).copyInto(digest, 28)
    }

    private fun hmac(key: ByteArray, message: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(message)
        }

    private fun beInt16(b: ByteArray, offset: Int): Int =
        ((b[offset].toInt() and 0xff) shl 8) or (b[offset + 1].toInt() and 0xff)

    private fun beInt16Bytes(value: Int): ByteArray =
        byteArrayOf(((value shr 8) and 0xff).toByte(), (value and 0xff).toByte())

    /**
     * Wraps the obfuscated2 byte stream in application-data records.
     *
     * The first outbound write is preceded by a ChangeCipherSpec, and records are
     * capped at 2878 bytes to match what a real client emits.
     */
    class RecordTransport(
        private val input: InputStream,
        private val output: OutputStream,
    ) : Transport {

        private var sentChangeCipherSpec = false
        private var buffered = ByteArray(0)
        private var consumed = 0

        override fun write(data: ByteArray) {
            var offset = 0
            while (offset < data.size) {
                val chunk = minOf(MAX_RECORD, data.size - offset)
                val prefix = if (!sentChangeCipherSpec) {
                    sentChangeCipherSpec = true
                    CHANGE_CIPHER_SPEC
                } else {
                    ByteArray(0)
                }
                output.write(prefix + APPLICATION_DATA + beInt16Bytes(chunk) + data.copyOfRange(offset, offset + chunk))
                offset += chunk
            }
            output.flush()
        }

        override fun readExact(n: Int): ByteArray {
            while (buffered.size - consumed < n) {
                val header = input.readExact(5)
                require(header.copyOfRange(0, 3).contentEquals(APPLICATION_DATA)) {
                    "expected a TLS application-data record, got ${header.copyOfRange(0, 3).toHex()}"
                }
                val length = beInt16(header, 3)
                require(length in 1..64 * 1024) { "implausible record length: $length" }
                append(input.readExact(length))
            }
            val out = buffered.copyOfRange(consumed, consumed + n)
            consumed += n
            return out
        }

        private fun append(payload: ByteArray) {
            // Drop the already-consumed prefix rather than growing without bound.
            val remaining = buffered.copyOfRange(consumed, buffered.size)
            buffered = remaining + payload
            consumed = 0
        }

        private companion object {
            const val MAX_RECORD = 2878
        }
    }
}
