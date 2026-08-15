package org.tgproxycheck

import java.io.ByteArrayOutputStream

/** A proxy to probe, plus the text it was parsed from (for reporting). */
data class MtProxy(
    val host: String,
    val port: Int,
    val secret: ProxySecret,
    val source: String,
) {
    val mode: ProxyMode get() = secret.mode

    override fun toString() = "$host:$port"
}

/**
 * Parses the link formats Telegram hands out:
 *
 *   https://t.me/proxy?server=1.2.3.4&port=443&secret=...
 *   tg://proxy?server=1.2.3.4&port=443&secret=...
 *
 * and a bare `host:port:secret` shorthand for convenience on the command line.
 *
 * Deliberately hand-rolled rather than using android.net.Uri or java.net.URI so
 * these sources stay platform-neutral and behave identically on both.
 */
object ProxyLink {

    fun parse(text: String): MtProxy {
        val t = text.trim()
        return if (t.contains("://") || t.startsWith("t.me/")) parseLink(t) else parseShorthand(t)
    }

    private fun parseLink(text: String): MtProxy {
        val queryStart = text.indexOf('?')
        require(queryStart >= 0) { "no query string in '$text'" }

        val head = text.substring(0, queryStart).lowercase()
        require(!head.endsWith("/socks")) {
            "SOCKS5 links are not MTProto proxies and cannot be probed this way: '$text'"
        }
        require(head.endsWith("/proxy")) { "not an MTProto proxy link: '$text'" }

        val params = HashMap<String, String>()
        for (pair in text.substring(queryStart + 1).split('&')) {
            if (pair.isEmpty()) continue
            val eq = pair.indexOf('=')
            if (eq < 0) continue
            params[percentDecode(pair.substring(0, eq))] = percentDecode(pair.substring(eq + 1))
        }

        val server = requireNotNull(params["server"]) { "link has no 'server': '$text'" }
        val port = requireNotNull(params["port"]) { "link has no 'port': '$text'" }
        val secret = requireNotNull(params["secret"]) { "link has no 'secret': '$text'" }

        return MtProxy(
            host = server,
            port = parsePort(port),
            secret = ProxySecret.parse(secret),
            source = text,
        )
    }

    /** host:port:secret — note IPv6 literals must use the link form instead. */
    private fun parseShorthand(text: String): MtProxy {
        val parts = text.split(':')
        require(parts.size == 3) {
            "expected a t.me/proxy link or host:port:secret, got '$text'"
        }
        return MtProxy(
            host = parts[0],
            port = parsePort(parts[1]),
            secret = ProxySecret.parse(parts[2]),
            source = text,
        )
    }

    private fun parsePort(text: String): Int {
        val port = text.toIntOrNull() ?: throw IllegalArgumentException("bad port: '$text'")
        require(port in 1..65535) { "port out of range: $port" }
        return port
    }

    private fun percentDecode(text: String): String {
        if ('%' !in text && '+' !in text) return text
        val out = ByteArrayOutputStream(text.length)
        var i = 0
        while (i < text.length) {
            when {
                text[i] == '%' && i + 2 < text.length -> {
                    out.write(text.substring(i + 1, i + 3).decodeHex()[0].toInt())
                    i += 3
                }
                text[i] == '+' -> {
                    out.write(' '.code); i++
                }
                else -> {
                    out.write(text[i].code); i++
                }
            }
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }
}
