package org.tgproxycheck

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * These cover internal consistency: encoding, framing, key derivation, and the
 * reply validator. They do not and cannot prove interoperability with a real
 * proxy — only a live probe does that.
 */
class ProtocolTest {

    private val random = SecureRandom()
    private val plainSecret = ProxySecret.parse("00112233445566778899aabbccddeeff")
    private val ddSecret = ProxySecret.parse("dd00112233445566778899aabbccddeeff")

    // ---- codecs ---------------------------------------------------------------

    @Test
    fun `hex round trips`() {
        val bytes = ByteArray(32).also { random.nextBytes(it) }
        assertContentEquals(bytes, bytes.toHex().decodeHex())
    }

    @Test
    fun `base64 accepts both alphabets`() {
        // "aGVsbG8" is "hello" in either alphabet, padding omitted.
        assertContentEquals("hello".toByteArray(), "aGVsbG8".decodeBase64())
    }

    // ---- secret parsing -------------------------------------------------------

    @Test
    fun `plain secret selects abridged`() {
        assertEquals(ProxyMode.ABRIDGED, plainSecret.mode)
        assertEquals(16, plainSecret.keyMaterial.size)
        assertContentEquals(plainSecret.raw, plainSecret.keyMaterial)
    }

    @Test
    fun `dd secret selects padded and drops the tag byte`() {
        assertEquals(ProxyMode.PADDED, ddSecret.mode)
        assertEquals(16, ddSecret.keyMaterial.size)
        assertContentEquals(ddSecret.raw.copyOfRange(1, 17), ddSecret.keyMaterial)
    }

    @Test
    fun `ee secret selects faketls and carries the domain`() {
        val domain = "www.google.com"
        val hex = "ee" + "00112233445566778899aabbccddeeff" + domain.toByteArray().toHex()
        val secret = ProxySecret.parse(hex)
        assertEquals(ProxyMode.FAKE_TLS, secret.mode)
        assertEquals(domain, secret.tlsDomain)
        assertEquals(16, secret.keyMaterial.size)
    }

    // ---- init frame -----------------------------------------------------------

    @Test
    fun `init frame carries tag and datacenter id`() {
        val obf = Obfuscated2.create(ddSecret, dcId = 2, random = random)
        val frame = obf.initFrame
        assertEquals(64, frame.size)

        // Bytes 56..64 go out encrypted — that is what hides the tag and the
        // datacenter id from anyone watching. Read them the way the proxy does.
        val revealed = peerCipher(frame, ddSecret).update(frame)
        for (i in 56 until 60) assertEquals(0xdd.toByte(), revealed[i], "tag byte $i")
        assertEquals(2, revealed[60].toInt())
        assertEquals(0, revealed[61].toInt())
    }

    @Test
    fun `abridged mode tags the frame with ef`() {
        val frame = Obfuscated2.create(plainSecret, dcId = 2, random = random).initFrame
        val revealed = peerCipher(frame, plainSecret).update(frame)
        for (i in 56 until 60) assertEquals(0xef.toByte(), revealed[i], "tag byte $i")
    }

    /**
     * Builds the cipher the peer derives from the plaintext half of the frame we
     * transmit. Feeding it the 64-byte frame both reveals the encrypted tail and
     * leaves the counter where real data begins.
     */
    private fun peerCipher(frame: ByteArray, secret: ProxySecret): Cipher {
        val key = MessageDigest.getInstance("SHA-256")
            .digest(frame.copyOfRange(8, 40) + secret.keyMaterial)
        val iv = frame.copyOfRange(40, 56)
        return Cipher.getInstance("AES/CTR/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        }
    }

    @Test
    fun `frames colliding with http verbs or tags are rejected`() {
        fun frameStartingWith(prefix: ByteArray) = ByteArray(64).also {
            prefix.copyInto(it)
            it[4] = 1 // keep the word at offset 4 non-zero
        }

        assertFalse(Obfuscated2.acceptable(frameStartingWith("POST".toByteArray()), ProxyMode.ABRIDGED))
        assertFalse(Obfuscated2.acceptable(frameStartingWith("GET ".toByteArray()), ProxyMode.ABRIDGED))
        assertFalse(Obfuscated2.acceptable(frameStartingWith("HEAD".toByteArray()), ProxyMode.ABRIDGED))
        assertFalse(Obfuscated2.acceptable(frameStartingWith(byteArrayOf(0xef.toByte())), ProxyMode.ABRIDGED))

        // Zero word at offset 4 is rejected even when byte 0 is fine.
        assertFalse(Obfuscated2.acceptable(ByteArray(64) { if (it == 0) 1 else 0 }, ProxyMode.ABRIDGED))

        val good = ByteArray(64) { 1 }
        assertTrue(Obfuscated2.acceptable(good, ProxyMode.ABRIDGED))
    }

    /**
     * The important one: derive the receive keys the way the peer does, from the
     * plaintext part of the frame we transmit, and confirm it can read what we
     * write. This pins both the SHA-256 key derivation and the rule that all 64
     * frame bytes must pass through the cipher.
     */
    @Test
    fun `peer can decrypt what we encrypt`() {
        val obf = Obfuscated2.create(ddSecret, dcId = 2, random = random)
        val frame = obf.initFrame

        // The peer consumes the 64-byte frame too, which is what puts both
        // counters at the same offset before real data flows.
        val peer = peerCipher(frame, ddSecret)
        peer.update(frame)

        val payload = ByteArray(200).also { random.nextBytes(it) }
        assertContentEquals(payload, peer.update(obf.encrypt(payload)))
    }

    // ---- framing --------------------------------------------------------------

    @Test
    fun `abridged framing round trips`() {
        val payload = ByteArray(40) { it.toByte() }
        val packet = Framing.buildPacket(payload, ProxyMode.ABRIDGED, random)

        assertEquals(41, packet.size)
        assertEquals(10, packet[0].toInt()) // 40 / 4

        assertContentEquals(payload, readBack(packet, ProxyMode.ABRIDGED))
    }

    @Test
    fun `padded framing round trips and covers its padding`() {
        val payload = ByteArray(40) { it.toByte() }
        val packet = Framing.buildPacket(payload, ProxyMode.PADDED, random)

        val declared = readLe32(packet, 0)
        assertEquals(packet.size - 4, declared)
        assertTrue(declared >= payload.size)

        // The body may carry padding, but it starts with the payload.
        val body = readBack(packet, ProxyMode.PADDED)
        assertContentEquals(payload, body.copyOfRange(0, payload.size))
    }

    @Test
    fun `abridged framing rejects a misaligned payload`() {
        assertFailsWith<IllegalArgumentException> {
            Framing.buildPacket(ByteArray(41), ProxyMode.ABRIDGED, random)
        }
    }

    /** Feeds a plaintext packet back through the reader with a no-op cipher. */
    private fun readBack(packet: ByteArray, mode: ProxyMode): ByteArray {
        var offset = 0
        return Framing.readPacket(
            mode = mode,
            readExact = { n ->
                require(offset + n <= packet.size) { "reader ran past the packet" }
                packet.copyOfRange(offset, offset + n).also { offset += n }
            },
            decrypt = { it },
        )
    }

    // ---- mtproto --------------------------------------------------------------

    @Test
    fun `req_pq_multi has the expected shape`() {
        val nonce = MtProto.newNonce(random)
        val message = MtProto.buildReqPqMulti(nonce, random)

        assertEquals(40, message.size)
        assertEquals(0L, readLe64(message, 0))          // auth_key_id
        assertEquals(0L, readLe64(message, 8) % 4)      // client msg ids divide by 4
        assertEquals(20, readLe32(message, 16))         // message_data_length
        assertEquals(MtProto.REQ_PQ_MULTI, readLe32(message, 20))
        assertContentEquals(nonce, message.copyOfRange(24, 40))
    }

    @Test
    fun `resPQ validation accepts a well formed reply`() {
        val nonce = MtProto.newNonce(random)
        MtProto.verifyResPq(resPq(nonce), nonce)
    }

    @Test
    fun `resPQ validation rejects a foreign nonce`() {
        val ours = MtProto.newNonce(random)
        val theirs = MtProto.newNonce(random)
        val failure = assertFailsWith<IllegalArgumentException> {
            MtProto.verifyResPq(resPq(theirs), ours)
        }
        assertTrue(failure.message!!.contains("nonce mismatch"))
    }

    @Test
    fun `resPQ validation rejects a wrong constructor`() {
        val nonce = MtProto.newNonce(random)
        val packet = resPq(nonce)
        le32(0x12345678).copyInto(packet, 20) // clobber the constructor
        assertFailsWith<IllegalArgumentException> { MtProto.verifyResPq(packet, nonce) }
    }

    private fun resPq(nonce: ByteArray): ByteArray {
        val body = le32(MtProto.RES_PQ) + nonce + ByteArray(16) { 7 } // + server_nonce
        return le64(0L) + le64(0x5F00000000000004L) + le32(body.size) + body
    }

    // ---- links ----------------------------------------------------------------

    @Test
    fun `parses a t_me proxy link`() {
        val proxy = ProxyLink.parse(
            "https://t.me/proxy?server=1.2.3.4&port=443&secret=dd00112233445566778899aabbccddeeff"
        )
        assertEquals("1.2.3.4", proxy.host)
        assertEquals(443, proxy.port)
        assertEquals(ProxyMode.PADDED, proxy.mode)
    }

    @Test
    fun `parses the host port secret shorthand`() {
        val proxy = ProxyLink.parse("1.2.3.4:443:00112233445566778899aabbccddeeff")
        assertEquals("1.2.3.4", proxy.host)
        assertEquals(443, proxy.port)
        assertEquals(ProxyMode.ABRIDGED, proxy.mode)
    }

    @Test
    fun `rejects a socks link`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            ProxyLink.parse("https://t.me/socks?server=1.2.3.4&port=1080&user=a&pass=b")
        }
        assertTrue(failure.message!!.contains("SOCKS5"))
    }
}
