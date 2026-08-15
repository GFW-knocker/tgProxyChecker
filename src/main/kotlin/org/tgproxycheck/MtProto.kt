package org.tgproxycheck

import java.security.SecureRandom

/**
 * The smallest useful slice of MTProto: one unencrypted request and its reply.
 *
 * `req_pq_multi` is the first message of the DH handshake and travels with
 * `auth_key_id = 0`, which means no auth key, no session, and no login. That is
 * exactly what a reachability probe wants — and getting `resPQ` back with our
 * own nonce echoed proves the proxy accepted the secret, relayed to a real
 * datacenter, and carried the answer home.
 */
internal object MtProto {

    /** req_pq_multi#be7e8ef1 nonce:int128 = ResPQ */
    val REQ_PQ_MULTI = 0xbe7e8ef1.toInt()

    /** resPQ#05162463 nonce:int128 server_nonce:int128 pq:string ... = ResPQ */
    const val RES_PQ = 0x05162463

    /** auth_key_id(8) + message_id(8) + message_data_length(4) */
    private const val HEADER = 20

    /** constructor(4) + nonce(16) + server_nonce(16) */
    private const val MIN_RES_PQ_BODY = 36

    fun newNonce(random: SecureRandom): ByteArray = ByteArray(16).also { random.nextBytes(it) }

    fun buildReqPqMulti(nonce: ByteArray, random: SecureRandom): ByteArray {
        require(nonce.size == 16) { "nonce must be 16 bytes" }
        val body = le32(REQ_PQ_MULTI) + nonce
        return le64(0L) + le64(newMessageId(random)) + le32(body.size) + body
    }

    /**
     * Validates the envelope and constructor, returning the nonce the server
     * echoed. Throws with a specific reason on anything unexpected, so the
     * caller can report *why* a proxy failed rather than just that it did.
     *
     * Returning the nonce rather than comparing it lets the caller recognise a
     * late reply to an earlier, already-timed-out request.
     */
    fun readResPqNonce(packet: ByteArray): ByteArray {
        require(packet.size >= HEADER) { "short reply: ${packet.size} bytes" }

        val authKeyId = readLe64(packet, 0)
        require(authKeyId == 0L) { "expected an unencrypted reply, got auth_key_id=$authKeyId" }

        val bodyLength = readLe32(packet, 16)
        require(bodyLength >= MIN_RES_PQ_BODY && HEADER + bodyLength <= packet.size) {
            "bad message_data_length=$bodyLength for a ${packet.size}-byte packet"
        }

        val constructor = readLe32(packet, HEADER)
        require(constructor == RES_PQ) {
            "expected resPQ (0x05162463), got 0x${constructor.toUInt().toString(16)}"
        }

        return packet.copyOfRange(HEADER + 4, HEADER + 20)
    }

    /** Strict form: the reply must echo exactly [expectedNonce]. */
    fun verifyResPq(packet: ByteArray, expectedNonce: ByteArray) {
        val echoed = readResPqNonce(packet)
        require(echoed.contentEquals(expectedNonce)) {
            "nonce mismatch: sent ${expectedNonce.toHex()}, got ${echoed.toHex()}"
        }
    }

    /**
     * Message ids approximate unixtime shifted into the high 32 bits, and client
     * ids must be divisible by 4.
     */
    private fun newMessageId(random: SecureRandom): Long {
        val seconds = System.currentTimeMillis() / 1000
        val low = random.nextInt().toLong() and 0xFFFFFFFCL
        return (seconds shl 32) or low
    }
}
