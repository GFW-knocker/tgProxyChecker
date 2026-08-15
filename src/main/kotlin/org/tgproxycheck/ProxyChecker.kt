package org.tgproxycheck

import java.io.EOFException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom

/** Outcome of one probe. [rttMs] is the MTProto round trip, not the TCP connect. */
data class ProxyCheckResult(
    val proxy: MtProxy,
    val ok: Boolean,
    val connectMs: Long?,
    val rttMs: Long?,
    val error: String?,
) {
    // Plain ASCII on purpose: this prints to a Windows console more often than not.
    override fun toString(): String = when {
        ok -> "$proxy : ${rttMs} ms (connect ${connectMs} ms)"
        connectMs != null -> "$proxy : FAILED after connect (${connectMs} ms) - $error"
        else -> "$proxy : FAILED - $error"
    }
}

/**
 * Probes MTProto proxies by completing the obfuscated2 handshake and exchanging
 * one real MTProto message through them.
 *
 * This is a genuine send/receive test, not a TCP ping: a proxy that accepts
 * connections but has a wrong secret, or no working path to a datacenter, fails
 * here with a specific reason.
 *
 * Blocking by design — one socket per call, no shared state. Call it from
 * Dispatchers.IO on Android, or from the pool in [main].
 */
class ProxyChecker(
    private val connectTimeoutMs: Int = 5_000,
    private val readTimeoutMs: Int = 5_000,
    /** Datacenter the proxy should dial on our behalf. Any of 1..5 works. */
    private val dcId: Short = 2,
    private val random: SecureRandom = SecureRandom(),
) {

    fun check(proxy: MtProxy): ProxyCheckResult {
        if (proxy.mode == ProxyMode.FAKE_TLS) {
            return ProxyCheckResult(
                proxy, false, null, null,
                "faketls secrets (ee..., domain ${proxy.secret.tlsDomain}) are not implemented yet",
            )
        }

        var connectMs: Long? = null
        return try {
            Socket().use { socket ->
                val connectStart = System.nanoTime()
                socket.connect(InetSocketAddress(proxy.host, proxy.port), connectTimeoutMs)
                connectMs = millisSince(connectStart)
                socket.tcpNoDelay = true
                socket.soTimeout = readTimeoutMs

                val obf = Obfuscated2.create(proxy.secret, dcId, random)
                val nonce = MtProto.newNonce(random)
                val request = MtProto.buildReqPqMulti(nonce, random)
                val packet = Framing.buildPacket(request, proxy.mode, random)

                val input = socket.getInputStream()
                val output = socket.getOutputStream()

                // The init frame goes out in the clear; everything after it rides
                // the send keystream. One write keeps them in the same segment,
                // which is also what a real client looks like on the wire.
                val rttStart = System.nanoTime()
                output.write(obf.initFrame + obf.encrypt(packet))
                output.flush()

                val reply = Framing.readPacket(
                    mode = proxy.mode,
                    readExact = { n -> input.readExact(n) },
                    decrypt = { bytes -> obf.decrypt(bytes) },
                )
                val rttMs = millisSince(rttStart)

                MtProto.verifyResPq(reply, nonce)
                ProxyCheckResult(proxy, true, connectMs, rttMs, null)
            }
        } catch (e: Exception) {
            ProxyCheckResult(proxy, false, connectMs, null, describe(e))
        }
    }

    private fun millisSince(startNanos: Long) = (System.nanoTime() - startNanos) / 1_000_000

    private fun describe(e: Exception): String {
        val message = e.message?.takeIf { it.isNotBlank() }
        return if (message != null) "${e.javaClass.simpleName}: $message" else e.javaClass.simpleName
    }
}

private fun InputStream.readExact(n: Int): ByteArray {
    val buf = ByteArray(n)
    var offset = 0
    while (offset < n) {
        val read = read(buf, offset, n - offset)
        if (read < 0) throw EOFException("closed after $offset of $n bytes")
        offset += read
    }
    return buf
}
