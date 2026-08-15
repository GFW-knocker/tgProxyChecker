package org.tgproxycheck

import java.io.Closeable
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom

/**
 * Outcome of one probe.
 *
 * [rttMs] holds one entry per successful ping, in order. The first is slightly
 * inflated because the obfuscated2 init frame rides along with it; the second is
 * the steady-state round trip and the better number to rank proxies by.
 *
 * [ok] means at least one ping came back. When fewer than the requested number
 * completed, [error] says what stopped the rest.
 */
data class ProxyCheckResult(
    val proxy: MtProxy,
    val ok: Boolean,
    val connectMs: Long?,
    val tlsMs: Long? = null,
    val rttMs: List<Long> = emptyList(),
    val error: String? = null,
) {
    /** Steady-state round trip: the last ping, which carries no setup overhead. */
    val bestRttMs: Long? get() = rttMs.lastOrNull()

    // Plain ASCII on purpose: this prints to a Windows console more often than not.
    override fun toString(): String {
        val timings = buildString {
            append("connect ${connectMs} ms")
            tlsMs?.let { append(", tls $it ms") }
        }
        return when {
            ok && error == null -> "$proxy : ${rttMs.joinToString(", ") { "$it ms" }} ($timings)"
            ok -> "$proxy : ${rttMs.joinToString(", ") { "$it ms" }} ($timings) - $error"
            connectMs != null -> "$proxy : FAILED after connect ($timings) - $error"
            else -> "$proxy : FAILED - $error"
        }
    }
}

/**
 * Probes MTProto proxies by completing the transport handshake and exchanging
 * real MTProto messages through them.
 *
 * This is a genuine send/receive test, not a TCP ping: a proxy that accepts
 * connections but has a wrong secret, or no working path to a datacenter, fails
 * here with a specific reason.
 *
 * Blocking by design — one socket per call, no shared state. On Android use
 * `checkCancellable`, which closes the socket when the coroutine is cancelled.
 */
class ProxyChecker(
    private val connectTimeoutMs: Int = 5_000,
    /**
     * Total budget for the handshake and every ping, measured from the moment
     * TCP connects. A read already in flight can overrun this by up to one
     * socket timeout.
     */
    private val probeBudgetMs: Int = 10_000,
    /** How many round trips to measure on the one connection. */
    private val pings: Int = 2,
    /** Datacenter the proxy should dial on our behalf. Any of 1..5 works. */
    private val dcId: Short = 2,
    private val random: SecureRandom = SecureRandom(),
) {

    fun check(proxy: MtProxy): ProxyCheckResult = check(proxy) {}

    /**
     * [onConnect] receives the socket before it is dialled. Closing it from
     * another thread aborts the probe — that is how cancellation works, since a
     * blocking read does not respond to thread interruption.
     */
    fun check(proxy: MtProxy, onConnect: (Closeable) -> Unit): ProxyCheckResult {
        var connectMs: Long? = null
        var tlsMs: Long? = null
        val rtts = mutableListOf<Long>()
        var error: String? = null

        try {
            Socket().use { socket ->
                onConnect(socket)

                val connectStart = System.nanoTime()
                socket.connect(InetSocketAddress(proxy.host, proxy.port), connectTimeoutMs)
                connectMs = millisSince(connectStart)
                socket.tcpNoDelay = true

                val deadline = System.nanoTime() + probeBudgetMs * 1_000_000L
                val input = socket.getInputStream()
                val output = socket.getOutputStream()

                socket.soTimeout = remainingMs(deadline)
                val transport: Transport = if (proxy.mode == ProxyMode.FAKE_TLS) {
                    val tlsStart = System.nanoTime()
                    FakeTls.handshake(proxy.secret, input, output, random)
                    tlsMs = millisSince(tlsStart)
                    FakeTls.RecordTransport(input, output)
                } else {
                    PlainTransport(input, output)
                }

                val obf = Obfuscated2.create(proxy.secret, dcId, random)

                for (attempt in 1..pings) {
                    if (deadline - System.nanoTime() <= 0) {
                        error = "ran out of budget after ${rtts.size} of $pings pings"
                        break
                    }
                    socket.soTimeout = remainingMs(deadline)
                    try {
                        // The init frame is prepended to the first request only.
                        val initFrame = if (attempt == 1) obf.initFrame else null
                        rtts += ping(transport, obf, proxy.mode, initFrame)
                    } catch (e: Exception) {
                        error = "ping $attempt of $pings failed - ${describe(e)}"
                        break
                    }
                }
            }
        } catch (e: Exception) {
            error = describe(e)
        }

        return ProxyCheckResult(proxy, rtts.isNotEmpty(), connectMs, tlsMs, rtts, error)
    }

    /** One request/response round trip. Returns the elapsed milliseconds. */
    private fun ping(
        transport: Transport,
        obf: Obfuscated2,
        mode: ProxyMode,
        initFrame: ByteArray?,
    ): Long {
        val nonce = MtProto.newNonce(random)
        val request = MtProto.buildReqPqMulti(nonce, random)
        val packet = obf.encrypt(Framing.buildPacket(request, mode, random))

        val start = System.nanoTime()
        transport.write(if (initFrame != null) initFrame + packet else packet)

        val reply = Framing.readPacket(
            mode = mode,
            readExact = { n -> transport.readExact(n) },
            decrypt = { bytes -> obf.decrypt(bytes) },
        )
        val elapsed = millisSince(start)

        MtProto.verifyResPq(reply, nonce)
        return elapsed
    }

    private fun millisSince(startNanos: Long) = (System.nanoTime() - startNanos) / 1_000_000

    private fun remainingMs(deadline: Long): Int =
        ((deadline - System.nanoTime()) / 1_000_000).coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()

    private fun describe(e: Exception): String {
        val message = e.message?.takeIf { it.isNotBlank() }
        return if (message != null) "${e.javaClass.simpleName}: $message" else e.javaClass.simpleName
    }
}
