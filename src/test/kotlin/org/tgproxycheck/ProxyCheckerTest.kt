package org.tgproxycheck

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.net.ServerSocket
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread
import kotlin.system.measureTimeMillis
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * End-to-end tests against a simulated proxy.
 *
 * The server half of obfuscated2 is symmetric with the client half, so a fake
 * proxy is short enough to live in a test — and it exercises key derivation in
 * both directions, framing, the req_pq/resPQ exchange, and the multi-ping loop
 * together.
 */
class ProxyCheckerTest {

    private val secretHex = "00112233445566778899aabbccddeeff"
    private val secret = ProxySecret.parse(secretHex)

    private fun linkFor(port: Int) = ProxyLink.parse("127.0.0.1:$port:$secretHex")

    @Test
    fun `two pings complete against a simulated proxy`() {
        ServerSocket(0).use { server ->
            val proxyThread = thread { runFakeProxy(server, replies = 2) }
            val result = ProxyChecker(pings = 2).check(linkFor(server.localPort))
            proxyThread.join(5_000)

            assertTrue(result.ok, "probe failed: ${result.error}")
            assertNull(result.error)
            assertEquals(2, result.rttMs.size, "expected two round trips")
            assertEquals(result.rttMs.last(), result.bestRttMs)
        }
    }

    @Test
    fun `a proxy that answers once is reported as working but incomplete`() {
        ServerSocket(0).use { server ->
            val proxyThread = thread { runFakeProxy(server, replies = 1) }
            val result = ProxyChecker(pings = 2, probeBudgetMs = 2_000).check(linkFor(server.localPort))
            proxyThread.join(5_000)

            assertTrue(result.ok, "one good ping should still count as reachable")
            assertEquals(1, result.rttMs.size)
            assertTrue(result.error!!.contains("ping 2 of 2"), "unexpected error: ${result.error}")
        }
    }

    @Test
    fun `probe budget bounds a proxy that never answers`() {
        ServerSocket(0).use { server ->
            thread { runCatching { server.accept().use { Thread.sleep(30_000) } } }

            val elapsed = measureTimeMillis {
                val result = ProxyChecker(probeBudgetMs = 1_000).check(linkFor(server.localPort))
                assertFalse(result.ok)
            }
            assertTrue(elapsed < 4_000, "budget was not honoured: took $elapsed ms")
        }
    }

    @Test
    fun `cancellation aborts a stalled probe promptly`() = runBlocking {
        ServerSocket(0).use { server ->
            thread { runCatching { server.accept().use { Thread.sleep(30_000) } } }

            // A 30s budget: without cancellation support this would block for
            // the full half minute.
            val checker = ProxyChecker(probeBudgetMs = 30_000)
            val job = launch(Dispatchers.IO) { checker.checkCancellable(linkFor(server.localPort)) }
            delay(300) // let it connect and settle into a blocking read

            val elapsed = measureTimeMillis { job.cancelAndJoin() }
            assertTrue(elapsed < 2_000, "cancellation took $elapsed ms")
        }
    }

    // ---- simulated proxy ------------------------------------------------------

    /**
     * Speaks the abridged/plain-secret side of obfuscated2: reads the init
     * frame, derives the mirrored key pair, then answers [replies] requests with
     * a synthetic resPQ echoing the caller's nonce.
     */
    private fun runFakeProxy(server: ServerSocket, replies: Int) {
        runCatching {
            server.accept().use { socket ->
                val input = socket.getInputStream()
                val output = socket.getOutputStream()

                val frame = input.readExact(64)
                // Client's send keys are ours for receiving, and vice versa.
                val dec = ctr(sha256(frame.copyOfRange(8, 40) + secret.keyMaterial), frame.copyOfRange(40, 56))
                val reversed = frame.copyOfRange(8, 56).reversedArray()
                val enc = ctr(sha256(reversed.copyOfRange(0, 32) + secret.keyMaterial), reversed.copyOfRange(32, 48))

                // The client ran all 64 frame bytes through its send cipher, so
                // our receive cipher has to catch up. Its send cipher starts at
                // zero, so ours does too.
                dec.update(frame)

                repeat(replies) {
                    val quarters = dec.update(input.readExact(1))[0].toInt() and 0xff
                    val request = dec.update(input.readExact(quarters * 4))
                    val nonce = request.copyOfRange(24, 40)

                    val body = le32(MtProto.RES_PQ) + nonce + ByteArray(16) { 9 }
                    val message = le64(0L) + le64(0x5F00000000000004L) + le32(body.size) + body
                    val framed = byteArrayOf((message.size / 4).toByte()) + message
                    output.write(enc.update(framed))
                    output.flush()
                }
            }
        }
    }

    private fun sha256(data: ByteArray) = MessageDigest.getInstance("SHA-256").digest(data)

    private fun ctr(key: ByteArray, iv: ByteArray): Cipher =
        Cipher.getInstance("AES/CTR/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        }
}
