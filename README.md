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
1.2.3.4:443 : 187 ms (connect 92 ms)
5.6.7.8:443 : FAILED after connect (104 ms) — EOFException: closed after 0 of 4 bytes
```

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

`ProxyChecker.check()` blocks on one socket and holds no shared state, so call
it from `Dispatchers.IO`:

```kotlin
val results = withContext(Dispatchers.IO) {
    proxies.map { async { ProxyChecker().check(it) } }.awaitAll()
}
```

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

| Mode | State |
|---|---|
| plain / `dd` | verified against a live proxy |
| faketls (`ee`) | compiles, unit-tested, **not yet probed against a live proxy** |

The faketls tests cover hello structure (nested length scopes, digest offset,
SNI placement), the X25519 point derivation, ML-KEM coefficient packing, and the
record layer in both directions. They cannot catch a disagreement with a real
proxy — only a live probe does that.
