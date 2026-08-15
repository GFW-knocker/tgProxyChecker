package org.tgproxycheck

import java.security.SecureRandom

/**
 * Builds the ClientHello used by faketls.
 *
 * This is not TLS. Nothing here negotiates anything: the hello is a shaped byte
 * string whose 32-byte `random` field carries an HMAC the proxy checks. It is
 * built from a small op language rather than a frozen blob so the shape — cipher
 * suites, extension order, GREASE values — stays adjustable. A fixed hello means
 * a fixed JA3, which is exactly what fingerprinting DPI looks for.
 *
 * The layout mimics Chrome: GREASE in the cipher list and extensions, a permuted
 * extension order, and both X25519 and ML-KEM-768 key shares.
 */
internal class TlsHello(private val domain: String, private val random: SecureRandom) {

    sealed interface Op {
        class Str(val bytes: ByteArray) : Op
        class Rand(val length: Int) : Op
        class Zero(val length: Int) : Op
        class Grease(val seed: Int) : Op
        class Permutation(val entities: List<List<Op>>) : Op

        /** X25519 public key, 32 bytes. */
        data object K : Op

        /** ML-KEM-768 public key, 1184 bytes. */
        data object M : Op

        /** Random padding, one of 144/176/208/240 bytes. */
        data object E : Op

        /** Pad the hello out to 513 bytes, if it is not already longer. */
        data object P : Op

        data object BeginScope : Op
        data object EndScope : Op
    }

    private val data = ByteArray(8192)
    private var offset = 0
    private val scopes = ArrayDeque<Int>()

    /**
     * GREASE values have the form 0x?A repeated, and adjacent pairs are forced to
     * differ so the hello does not repeat one twice in a row.
     */
    private val grease = ByteArray(GREASE_COUNT).also {
        random.nextBytes(it)
        for (i in it.indices) it[i] = ((it[i].toInt() and 0xf0) + 0x0A).toByte()
        var i = 1
        while (i + 1 < GREASE_COUNT) {
            if (it[i] == it[i + 1]) it[i] = (it[i].toInt() xor 0x10).toByte()
            i += 2
        }
    }

    fun build(): ByteArray {
        offset = 0
        scopes.clear()
        for (op in ops()) write(op)
        return data.copyOfRange(0, offset)
    }

    private fun write(op: Op) {
        when (op) {
            is Op.Str -> {
                op.bytes.copyInto(data, offset)
                offset += op.bytes.size
            }

            is Op.Rand -> {
                val bytes = ByteArray(op.length)
                random.nextBytes(bytes)
                bytes.copyInto(data, offset)
                offset += op.length
            }

            is Op.Zero -> {
                data.fill(0, offset, offset + op.length)
                offset += op.length
            }

            is Op.Grease -> {
                // Both bytes of a GREASE value are the same, e.g. 0x1a1a.
                data[offset] = grease[op.seed]
                data[offset + 1] = grease[op.seed]
                offset += 2
            }

            Op.K -> {
                KeyShares.x25519PublicKey(random).copyInto(data, offset)
                offset += 32
            }

            Op.M -> {
                KeyShares.mlKem768PublicKey(random).copyInto(data, offset)
                offset += 1184
            }

            Op.E -> {
                val length = intArrayOf(144, 176, 208, 240)[random.nextInt(4)]
                write(Op.Rand(length))
            }

            Op.P -> {
                // With an ML-KEM key share the hello is already well past 513, so
                // this normally emits nothing. Kept for shape fidelity.
                if (offset <= 513) {
                    val padding = 513 - offset
                    write(Op.Str(byteArrayOf(0x00, 0x15)))
                    write(Op.BeginScope)
                    write(Op.Zero(padding))
                    write(Op.EndScope)
                }
            }

            is Op.Permutation -> {
                val list = op.entities.toMutableList()
                for (i in 0 until list.size - 1) {
                    val j = i + random.nextInt(list.size - i)
                    if (i != j) {
                        val tmp = list[i]; list[i] = list[j]; list[j] = tmp
                    }
                }
                for (part in list) for (inner in part) write(inner)
            }

            Op.BeginScope -> {
                scopes.addLast(offset)
                offset += 2 // reserved for the big-endian length
            }

            Op.EndScope -> {
                val start = scopes.removeLast()
                val size = offset - start - 2
                data[start] = ((size shr 8) and 0xff).toByte()
                data[start + 1] = (size and 0xff).toByte()
            }
        }
    }

    /** SNI is capped at 253 bytes, the maximum length of a domain name. */
    private fun domainOp(): Op {
        val bytes = domain.toByteArray(Charsets.US_ASCII)
        return Op.Str(if (bytes.size > 253) bytes.copyOfRange(0, 253) else bytes)
    }

    private fun ops(): List<Op> = listOf(
        str("160301"),                       // record: handshake, TLS 1.0
        Op.BeginScope,                       //   record length
        str("0100"),                         //   ClientHello, first byte of a 3-byte length
        Op.BeginScope,                       //   remaining two bytes of that length
        str("0303"),                         //   client_version TLS 1.2
        Op.Zero(32),                         //   random — the digest lands here, at offset 11
        str("20"),                           //   session_id length
        Op.Rand(32),                         //   session_id
        str("0020"),                         //   cipher_suites length
        Op.Grease(0),
        str("13011302_1303c02b_c02fc02c_c030cca9_cca8c013_c014009c_009d002f_00350100"),
        Op.BeginScope,                       //   extensions length
        Op.Grease(2),
        str("0000"),
        Op.Permutation(
            listOf(
                // server_name
                listOf(
                    str("0000"), Op.BeginScope, Op.BeginScope, str("00"),
                    Op.BeginScope, domainOp(), Op.EndScope, Op.EndScope, Op.EndScope,
                ),
                listOf(str("000500050100000000")),                       // status_request
                listOf(str("000a000c000a"), Op.Grease(4), str("11ec001d00170018")), // supported_groups
                listOf(str("000b00020100")),                             // ec_point_formats
                listOf(str("000d0012001004030804040105030805050108060601")), // signature_algorithms
                listOf(str("0010000e000c02683208687474702f312e31")),     // ALPN: h2, http/1.1
                listOf(str("00120000")),                                 // signed_certificate_timestamp
                listOf(str("00170000")),                                 // extended_master_secret
                listOf(str("001b0003020002")),                           // compress_certificate
                listOf(str("00230000")),                                 // session_ticket
                listOf(str("002b000706"), Op.Grease(6), str("03040303")), // supported_versions
                listOf(str("002d00020101")),                             // psk_key_exchange_modes
                // key_share: ML-KEM-768 hybrid, then X25519
                listOf(
                    str("003304ef04ed"), Op.Grease(4), str("00010011ec04c0"),
                    Op.M, Op.K, str("001d0020"), Op.K,
                ),
                listOf(str("44cd00050003026832")),                       // application_settings
                // encrypted_client_hello
                listOf(
                    str("fe02"), Op.BeginScope, str("0000010001"), Op.Rand(1),
                    str("0020"), Op.Rand(20), Op.BeginScope, Op.E, Op.EndScope, Op.EndScope,
                ),
                listOf(str("ff01000100")),                               // renegotiation_info
            )
        ),
        Op.Grease(3),
        str("000100"),
        Op.P,
        Op.EndScope,                         //   extensions
        Op.EndScope,                         //   handshake
        Op.EndScope,                         //   record
    )

    /** Underscores are allowed as visual separators and stripped before decoding. */
    private fun str(hex: String) = Op.Str(hex.replace("_", "").decodeHex())

    companion object {
        private const val GREASE_COUNT = 8

        /** Offset of the `random` field, where the HMAC digest is written. */
        const val DIGEST_OFFSET = 11
    }
}
