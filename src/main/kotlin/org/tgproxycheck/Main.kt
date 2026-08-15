package org.tgproxycheck

import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Command-line runner, so the library can be exercised on a desktop JVM before
 * it goes anywhere near an Android build.
 *
 *   tgproxychecker "https://t.me/proxy?server=1.2.3.4&port=443&secret=dd00..."
 *   tgproxychecker 1.2.3.4:443:dd00112233445566778899aabbccddeeff
 */
fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("Usage: tgproxychecker <proxy-link | host:port:secret>...")
        println()
        println("Accepts https://t.me/proxy?... and tg://proxy?... links.")
        println("Secrets may be hex or base64. faketls (ee...) is not supported yet.")
        return
    }

    val parsed = args.map { arg ->
        runCatching { ProxyLink.parse(arg) }
            .onFailure { println("$arg : could not parse - ${it.message}") }
            .getOrNull()
    }.filterNotNull()

    if (parsed.isEmpty()) return

    val checker = ProxyChecker()
    val pool = Executors.newFixedThreadPool(minOf(8, parsed.size))
    try {
        pool.invokeAll(parsed.map { proxy -> Callable { checker.check(proxy) } })
            .forEach { future -> println(future.get()) }
    } finally {
        pool.shutdown()
        pool.awaitTermination(30, TimeUnit.SECONDS)
    }
}
