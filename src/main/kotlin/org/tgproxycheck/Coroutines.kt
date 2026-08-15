package org.tgproxycheck

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.util.concurrent.atomic.AtomicReference

/**
 * Coroutine-aware wrappers. This is the only file in the project that depends on
 * kotlinx-coroutines — delete it and the rest still compiles.
 *
 * A blocking socket read ignores thread interruption, so cancellation cannot
 * work by the usual route. The socket has to be closed from another thread,
 * which makes the in-flight read fail immediately.
 *
 * Note that `Job.invokeOnCompletion` is the wrong tool for this: a coroutine
 * stuck in a blocking read never *completes*, so the handler would not run until
 * the read it was supposed to abort had already finished. A watchdog coroutine
 * parked on [awaitCancellation] reacts the moment cancellation is signalled.
 */

/**
 * Probes one proxy on [Dispatchers.IO], closing the socket if the calling
 * coroutine is cancelled.
 *
 * Without this a cancelled probe holds its socket until the probe budget
 * expires — so a user leaving a screen mid-scan would strand one thread per
 * proxy for several seconds.
 */
suspend fun ProxyChecker.checkCancellable(proxy: MtProxy): ProxyCheckResult = coroutineScope {
    val socket = AtomicReference<Closeable?>(null)

    // Parked on Dispatchers.Default rather than IO: if the IO pool is saturated
    // with blocked probes, a watchdog queued behind them could never run.
    val watchdog = launch(Dispatchers.Default) {
        try {
            awaitCancellation()
        } finally {
            socket.get()?.closeQuietly()
        }
    }

    try {
        val result = withContext(Dispatchers.IO) {
            check(proxy) { socket.set(it) }
        }
        // The probe returns a failure result when the socket is yanked out from
        // under it; surface the cancellation instead.
        ensureActive()
        result
    } finally {
        watchdog.cancel()
    }
}

/**
 * Probes every proxy concurrently. Cancelling the caller cancels all of them,
 * and each socket is closed rather than left to time out.
 */
suspend fun ProxyChecker.checkAll(proxies: List<MtProxy>): List<ProxyCheckResult> =
    coroutineScope {
        proxies.map { proxy -> async { checkCancellable(proxy) } }.awaitAll()
    }

private fun Closeable.closeQuietly() {
    try {
        close()
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        // Nothing useful to do; the probe is being torn down either way.
    }
}
