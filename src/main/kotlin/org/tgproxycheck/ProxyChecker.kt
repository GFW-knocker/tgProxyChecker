package org.tgproxycheck

import java.io.Closeable
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom

/**
 * Outcome of one probe.
 *
 * [rttMs] always holds one entry per attempted ping, with [FAILED_PING] where
 * that ping did not come back. The first round trip carries the obfuscated2 init
 * frame so it runs slightly long; later ones are the steady-state figure.
 *
 * [ok] means at least one ping came back.
 */
data class ProxyCheckResult(
    val proxy: MtProxy,
    val ok: Boolean,
    val connectMs: Long?,
    val tlsMs: Long? = null,
    val rttMs: List<Long> = emptyList(),
    val error: String? = null,
) {
    /** Steady-state round trip: the last ping that answered. */
    val bestRttMs: Long? get() = rttMs.lastOrNull { it >= 0 }

    // Plain ASCII on purpose: this prints to a Windows console more often than not.
    override fun toString(): String {
        val timings = buildString {
            connectMs?.let { append("connect $it ms") }
            tlsMs?.let {
                if (isNotEmpty()) append(", ")
                append("tls $it ms")
            }
        }
        return buildString {
            append("$proxy : ")
            append(if (ok) "SUCCESS" else "FAILED")
            append(", ping [${rttMs.joinToString(", ")}] ms")
            if (timings.isNotEmpty()) append(" ($timings)")
            error?.let { append(" - $it") }
        }
    }

    companion object {
        /** Placeholder RTT for a ping that never answered. */
        const val FAILED_PING = -1L
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
    /** Cap on any single wait: the faketls handshake, or one ping. */
    private val perAttemptTimeoutMs: Int = 5_000,
    /**
     * Total budget for the handshake and every ping, measured from the moment
     * TCP connects. Sized to fit two full-length pings plus handshake overhead.
     * Whichever of this and [perAttemptTimeoutMs] runs out first wins.
     */
    private val probeBudgetMs: Int = 12_000,
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
        var error: String? = null
        val rtts = MutableList(pings) { ProxyCheckResult.FAILED_PING }

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

                socket.soTimeout = attemptTimeoutMs(deadline)
                val transport: Transport = if (proxy.mode == ProxyMode.FAKE_TLS) {
                    val tlsStart = System.nanoTime()
                    FakeTls.handshake(proxy.secret, input, output, random)
                    tlsMs = millisSince(tlsStart)
                    FakeTls.RecordTransport(input, output)
                } else {
                    PlainTransport(input, output)
                }

                val obf = Obfuscated2.create(proxy.secret, dcId, random)

                // Nonces we sent but never got an answer for. A proxy that was
                // merely busy may still reply to them later, and that reply must
                // be recognised and skipped rather than mistaken for a fresh one.
                val abandoned = mutableListOf<ByteArray>()

                for (attempt in 1..pings) {
                    if (deadline - System.nanoTime() <= 0) {
                        error = error ?: "ran out of budget after ${attempt - 1} of $pings pings"
                        break
                    }
                    socket.soTimeout = attemptTimeoutMs(deadline)
                    val nonce = MtProto.newNonce(random)
                    try {
                        // The init frame rides on the first request only; it has
                        // already been sent even if that request went unanswered.
                        val initFrame = if (attempt == 1) obf.initFrame else null
                        rtts[attempt - 1] = ping(transport, obf, proxy.mode, initFrame, nonce, abandoned)
                    } catch (e: Exception) {
                        // Keep going: a busy server may answer the next one.
                        abandoned += nonce
                        error = error ?: describe(e)
                    }
                }
            }
        } catch (e: Exception) {
            error = error ?: describe(e)
        }

        val succeeded = rtts.any { it >= 0 }
        return ProxyCheckResult(proxy, succeeded, connectMs, tlsMs, rtts, error)
    }

    /**
     * One request/response round trip, returning the elapsed milliseconds.
     *
     * Replies echoing an [abandoned] nonce are late answers to an earlier ping;
     * they are discarded and the read repeated.
     */
    private fun ping(
        transport: Transport,
        obf: Obfuscated2,
        mode: ProxyMode,
        initFrame: ByteArray?,
        nonce: ByteArray,
        abandoned: List<ByteArray>,
    ): Long {
        val request = MtProto.buildReqPqMulti(nonce, random)
        val packet = obf.encrypt(Framing.buildPacket(request, mode, random))

        val start = System.nanoTime()
        transport.write(if (initFrame != null) initFrame + packet else packet)

        // At most one stale reply per abandoned ping can be waiting for us.
        repeat(abandoned.size + 1) {
            val reply = Framing.readPacket(
                mode = mode,
                readExact = { n -> transport.readExact(n) },
                decrypt = { bytes -> obf.decrypt(bytes) },
            )
            val echoed = MtProto.readResPqNonce(reply)
            if (echoed.contentEquals(nonce)) return millisSince(start)
            require(abandoned.any { it.contentEquals(echoed) }) {
                "reply nonce matches no request we sent"
            }
        }
        throw IllegalStateException("only stale replies arrived")
    }

    private fun millisSince(startNanos: Long) = (System.nanoTime() - startNanos) / 1_000_000

    /** The tighter of the per-attempt cap and whatever budget is left. */
    private fun attemptTimeoutMs(deadline: Long): Int =
        minOf(perAttemptTimeoutMs, remainingMs(deadline))

    private fun remainingMs(deadline: Long): Int =
        ((deadline - System.nanoTime()) / 1_000_000).coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()

    private fun describe(e: Exception): String {
        val message = e.message?.takeIf { it.isNotBlank() }
        return if (message != null) "${e.javaClass.simpleName}: $message" else e.javaClass.simpleName
    }
}
