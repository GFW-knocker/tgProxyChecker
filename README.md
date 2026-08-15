# tgProxyChecker

Measures the real round-trip delay of an MTProto proxy by completing the
obfuscated2 handshake and exchanging an actual MTProto message through it.

Not a TCP ping. A proxy that accepts connections but has the wrong secret, or no
working path to a datacenter, fails here with a specific reason.

Pure Kotlin, no native code, no dependencies beyond `kotlin-stdlib`.

## How it works

1. Open a plain TCP socket to the proxy.
2. Send the 64-byte **obfuscated2 init frame**. It carries a protocol tag, the
   target datacenter id, and the random material both AES-CTR keys are derived
   from — folded with the proxy secret via SHA-256.
3. Send **`req_pq_multi`**, the first message of the MTProto handshake. It
   travels with `auth_key_id = 0`, so it needs no auth key, no session, and no
   login.
4. Wait for **`resPQ`** and check our own nonce comes back.

Step 4 is what makes this a real test: the reply can only exist if the proxy
accepted the secret, relayed to a genuine datacenter, and carried the answer
back.

The datacenter id lives in the init frame and the proxy dials the DC for us, so
this client contains **no Telegram IP addresses** and needs no bootstrap config.

## Building

There is no Gradle wrapper committed yet. Either open the project in IntelliJ or
Android Studio, which supplies its own Gradle, or generate one once:

```bash
gradle wrapper
```

## Usage

```bash
./gradlew run --args="https://t.me/proxy?server=1.2.3.4&port=443&secret=dd00112233445566778899aabbccddeeff"
```

Also accepts `tg://proxy?...` links and a bare `host:port:secret` shorthand.
Secrets may be hex or base64. Multiple proxies are probed concurrently.

Output:

```
1.2.3.4:443 : SUCCESS, ping [152, 151] ms (connect 142 ms)
9.8.7.6:443 : SUCCESS, ping [210, 194] ms (connect 88 ms, tls 205 ms)
2.3.4.5:443 : SUCCESS, ping [163, -1] ms (connect 91 ms) - SocketTimeoutException: Read timed out
5.6.7.8:443 : FAILED, ping [-1, -1] ms (connect 172 ms) - no reply
```

`rttMs` always has one entry per attempted ping, with `-1` where that ping did
not answer. `SUCCESS` means at least one came back.

Each proxy is pinged twice over one connection. The first round trip carries the
obfuscated2 init frame, so it runs slightly long; the second is the steady-state
figure and the better one to rank by (`result.bestRttMs`).

### Timeouts

| Bound | Default | Applies to |
|---|---|---|
| `connectTimeoutMs` | 5s | the TCP connect |
| `perAttemptTimeoutMs` | 5s | any single wait — faketls handshake, or one ping |
| `probeBudgetMs` | 12s | handshake plus all pings, from the moment TCP connects |

Whichever runs out first wins. Two full-length pings take 10s, leaving 2s of
slack for the handshake, so the worst case is 5s to connect plus 12s of probing.

A failed ping does **not** end the probe — a busy server may well answer the next
one. To make that safe, every nonce that goes unanswered is remembered: if the
server later replies to an abandoned request, the reply is recognised and
discarded rather than mistaken for the current ping's. Without that bookkeeping a
late answer would surface as a confusing nonce mismatch.

### A wrong secret looks like a dead proxy

This is by design and not something a client can improve on. With a wrong secret
the init frame decrypts to garbage at the proxy, and it answers with **silence** —
no error, no reset, just a held-open connection. Replying "bad secret" would
confirm to any internet-wide scanner that the host is an MTProxy.

So `FAILED, ping [-1, -1] ms` after two 5-second waits is the
expected result for a wrong secret, a black-holed proxy, and a dead datacenter
path alike. There is no signal that separates them.

## Secret formats

| Secret | Mode | Framing | Status |
|---|---|---|---|
| 16 bytes | abridged, tag `0xef` | 1-byte length | supported |
| `dd` + 16 bytes | padded, tag `0xdd` | int32 length + padding | supported |
| `ee` + 16 bytes + domain | faketls | padded inside TLS records | supported |

### faketls

For `ee` secrets the whole exchange is wrapped in something that looks like a
TLS session but is not one:

```
TCP
 └─ faketls records (0x17 0x03 0x03 <len>)
     └─ obfuscated2 (AES-CTR)
         └─ MTProto framing
             └─ req_pq_multi
```

The client sends a ClientHello whose 32-byte `random` field at offset 11 holds
`HMAC-SHA256(secret, hello)` with the timestamp XORed into its last 4 bytes. The
proxy replies with a ServerHello, a ChangeCipherSpec, and an application-data
record, carrying the same HMAC over our digest plus its own response. Only then
does the obfuscated2 stream start, wrapped in application-data records.

No cipher negotiation, no key exchange, no certificate — so no `SSLSocket` and
nothing to validate.

The hello is built from a small op language ([TlsHello.kt](src/main/kotlin/org/tgproxycheck/TlsHello.kt))
rather than a frozen blob, so cipher suites, extension order, and GREASE stay
adjustable. It currently mimics Chrome: GREASE in the cipher list and
extensions, a permuted extension order, and X25519 plus ML-KEM-768 key shares.
**A fixed hello means a fixed JA3**, which is precisely what fingerprinting DPI
looks for, so keep it varying.

## Android

The library sources use nothing outside `java.net`, `javax.crypto`,
`java.security`, and `kotlin-stdlib`. Copy `src/main/kotlin/org/tgproxycheck/`
into an Android module and it compiles unchanged. Only `Main.kt` is
JVM-CLI-specific; drop it.

Use the coroutine wrappers, which close the socket on cancellation:

```kotlin
val results = ProxyChecker().checkAll(proxies)   // or .checkCancellable(one)
```

This matters more than it looks. `ProxyChecker.check()` blocks, and a blocking
socket read ignores thread interruption — so a plain `async { check(it) }` that
gets cancelled keeps its socket open for the full probe budget. With 40 proxies
that strands the `Dispatchers.IO` pool for ten seconds after the user has already
left the screen. `checkCancellable` parks a watchdog on `Dispatchers.Default` and
closes the socket the moment cancellation is signalled.

`Coroutines.kt` is the only file that needs kotlinx-coroutines. Delete it and
the rest of the library still compiles, with `check(proxy) { socket -> ... }`
available if you want to wire cancellation up yourself.

Requires `android.permission.INTERNET`. Nothing else — raw sockets are not
governed by Network Security Config or `usesCleartextTraffic`.

### Play Store

No `javax.net.ssl` anywhere: no `SSLSocket`, no custom `TrustManager`, no
`HostnameVerifier`. There is no certificate in this protocol, so there is nothing
to validate and nothing for the "unsafe SSL" scanner to match. This holds for
faketls too, which is byte mimicry rather than TLS.

## Licence and provenance

Written from the MTProto wire format (constants, field offsets, key derivation
order). Those are protocol facts, not copyrightable expression. No code was
copied from Telegram, and this project carries no GPL obligation.

## Tests

```bash
./gradlew test
```

Covers encoding, secret parsing, init-frame structure and rejection rules,
framing round-trips, and reply validation. The key-derivation test derives the
receive keys the way a peer would, from the plaintext part of the transmitted
frame, and confirms it can read what we write.

These prove internal consistency. **They cannot prove interoperability** — only
a probe against a live proxy does that.

## Status

All three secret types are verified against live proxies.

32 unit tests cover hello structure (nested length scopes, digest offset, SNI
placement), the X25519 point derivation, ML-KEM coefficient packing, framing
round-trips, and the record layer in both directions.

Four of them run against a simulated proxy built into the test suite — the
server half of obfuscated2 is symmetric with the client half, so a fake proxy is
short enough to live in a test. Those cover key derivation in both directions,
the full req_pq/resPQ exchange, the two-ping loop, budget enforcement, and
cancellation.

The ClientHello was additionally verified byte-for-byte against the reference
implementation: all 31 literal byte sequences match exactly. Worth knowing that
a live probe cannot catch an error there — the proxy HMACs the hello without
parsing it, so a wrong extension byte would pass every functional test while
changing the JA3 fingerprint.
