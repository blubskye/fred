[![Build status](https://img.shields.io/github/check-runs/hyphanet/fred/next?label=upstream%20build)](https://github.com/hyphanet/fred/actions)
[![Fork build](https://img.shields.io/github/check-runs/blubskye/fred/next?label=fork%20build)](https://github.com/blubskye/fred/actions)
[![Coverity status](https://scan.coverity.com/projects/2316/badge.svg?flat=1)](https://scan.coverity.com/projects/freenet-fred)
[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2+-blue.svg)](LICENSE.Freenet)
[![Based on build](https://img.shields.io/badge/based%20on-build%201506-informational)](https://github.com/hyphanet/fred)

---

# fred — Freenet Reference Daemon (blubskye fork)

> **Hyphanet** (formerly Freenet) is a censorship-resistant peer-to-peer platform for
> anonymous communication and publishing. It provides a distributed, encrypted,
> decentralised datastore; forums, chat, and static websites are all built on top of it.

This is a personal fork of [hyphanet/fred](https://github.com/hyphanet/fred) based on
build **1506**. It tracks upstream's `next` branch and layers a security audit (HO-series
findings) plus correctness bug fixes on top.

---

## What's different from upstream

### Critical bugs fixed

| ID | File | Description |
|----|------|-------------|
| HO-64 | `ArchiveManager.java` | **Inverted size accumulator in ZIP/TAR extraction.** `readBytes += realLen` should be `realLen += readBytes`. The archive size limit was never correctly enforced — an attacker-supplied archive could silently extract files past the configured maximum. Fixed in both the TAR and ZIP code paths. |
| HO-3 | `CSSReadFilter.java` | **Wrong operator precedence in CSS media-type character validation.** The `!` applied only to the lowercase alpha check; uppercase letters, digits, and hyphens were processed incorrectly, allowing malformed media type strings through the filter. Fixed by adding explicit parentheses around all character-class checks. |

### Critical security fixes

| ID | File | Description |
|----|------|-------------|
| HO-65 | `ArchiveManager.java` | **Path traversal via archive entry names.** Archive entries containing `..` were not rejected before stripping leading slashes, allowing manifest paths to escape the intended directory. Now throws `IllegalArgumentException` on any entry whose name contains `..`. |
| P-3 | `FilterMessage.java` | **Arbitrary file read via FCP `FilterMessage` with `DataSource=DISK`.** Any FCP client could read arbitrary host files (SSH keys, node master keys, etc.) by specifying `MimeType=text/plain`. Now enforces DDA or full-access authorization before accepting disk-sourced filter requests. |
| HO-19 | `ClientPutComplexDirMessage.java`, `ClientPutDiskDirMessage.java` | **Missing per-connection DDA check on disk uploads.** The server-side upload allowlist was checked, but the per-connection DDA authorization (`testDDA`) was never verified, allowing an FCP client to upload files outside the DDA-granted paths. Both `ClientPut` variants now enforce DDA. |
| P-5 | `PluginDownLoaderURL.java` | **Plugin loader accepted plain HTTP and FTP URLs.** A network attacker could MITM an HTTP plugin download and serve a malicious JAR that runs with full node privileges. Now rejects any non-HTTPS plugin URL, and also detects and blocks HTTPS→HTTP redirect downgrade attacks. |
| HO-27 | `NodeUpdateManager.java` | **No rollback protection on auto-updates.** A compromised update-key holder could serve an old, known-vulnerable JAR. The highest-ever-deployed build number is now persisted to disk (`max-deployed-build.txt`); any fetched build at or below it is rejected with a logged warning. |
| HO-29/HO-30 | `NodeUpdateManager.java` | **Auto-update JAR written without fsync and without post-write hash verification.** A power failure or disk error between `flush()` and `close()` could leave a corrupt JAR. The JAR is now fsynced before the node restarts, and its SHA-256 is recomputed from disk and compared against the in-memory hash before deployment. |
| HO-32 | `UpdateDeployContext.java` | **`wrapper.conf` updated without fsync.** Same class of write-atomicity bug as HO-29 but for the wrapper config. Now fsynced before the rename. |

### High severity fixes

| ID | File | Description |
|----|------|-------------|
| HO-21 | `FCPConnectionInputHandler.java` | **No field-count limit on FCP messages.** `SimpleFieldSet` has no built-in cap; an adversarial client could send thousands of `key=value` lines to exhaust heap memory. Hard cap of 256 fields per message; excess fields return a `ProtocolErrorMessage`. |
| HO-22 | `DirectDirPutFile.java` | **Negative `DataLength` bypassed bucket allocation guard.** A negative value passed to `makeBucket()` could wrap or allocate an unbounded buffer. Rejected before allocation with `INVALID_FIELD`. |
| HO-48 | `PartiallyReceivedBlock.java` | **Integer overflow in `packets * packetSize` bounds check.** A malicious peer supplying large values whose product wraps to a small positive number bypassed the length check. Now uses `(long)packets * packetSize` throughout, with an explicit overflow pre-check. |
| HO-50 | `FNPPacketMangler.java` | **No rate limit on auth brute-force scan.** Spoofed or garbage packets triggered a linear scan over all peers for every auth attempt, enabling CPU exhaustion. Per-source-IP rate limit (10 failures/s) now applied before the peer scan, with periodic eviction of stale entries. |
| HO-49 | `IncomingPacketFilterImpl.java` | **No rate limit on peer brute-force search.** Same class of CPU exhaustion as HO-50 but on the incoming packet filter path. Rate-limited. |
| HO-52 | `DarknetPeerNode.java`, `PluginDownLoaderURL.java` | **No maximum file size on incoming darknet file transfers.** An adversarial darknet peer could initiate an unbounded file transfer. Maximum transfer size now enforced. |
| HO-66 | `Metadata.java` | **`intern()` called on network-controlled manifest entry names.** `String.intern()` inserts strings into the permanent JVM string pool. With no bound on manifest entry count an adversary could exhaust PermGen/Metaspace with a crafted freesite. All three `intern()` calls on network-controlled keys removed. |
| HO-39 | `OfficialPlugins.java` | **Official plugin CHK keys are not bound to developer identity.** A CHK guarantees byte-for-byte integrity but not authenticity. Anyone with commit access could insert a malicious plugin JAR. The `WebOfTrustTesting` entry's `alwaysFetchLatestVersion()` USK auto-update flag removed (now pins a specific edition). Extensive audit notes document the required external build infrastructure (key management, JAR signing, verification code) needed for a full fix. |
| HO-44 | `FNPPacketMangler.java` | **JFK1 flood — per-put size not guarded.** A flood of JFK1 handshake initiation messages could grow unbounded state. Size guard added. |

### Medium severity fixes

| ID | File | Description |
|----|------|-------------|
| HO-72 | `SessionKey.java` | **Active AES-256/HMAC session key fields were `public`.** Any plugin or `freenet.node.*` class could read live key material without reflection. All key fields narrowed to package-private. |
| HO-71 | `PeerNode.java` | **JFK/session key fields were `protected`.** Same exposure as HO-72 on the peer node side. Narrowed to package-private. |
| HO-70 | `NewPacketFormat.java` | **`DO_KEEPALIVES` flag not `volatile`.** A plugin writing this flag from an unsynchronized context would not be visible to the packet-sender thread, silently disconnecting all peers. Now `volatile` and package-private. |
| HO-74 | `Cookie.java` | **Session cookie missing `HttpOnly` flag.** Without `HttpOnly`, browser extensions and injected JavaScript can read the session cookie. Flag now set by default. |
| HO-9 | `SSL.java` | **Hardcoded `"freenet"` keystore and private-key password.** The well-known default was used for all SSL keystores. Both passwords are now generated randomly per node. |
| HO-7 | `Util.java` | **Iterative KDF used SHA-1.** The internal `makeKey()` KDF called from Yarrow's reseed path used SHA-1. Upgraded to SHA-256 (larger output block, stronger resistance). Does not affect any on-wire or file format. |
| HO-6 | `Yarrow.java` | **Entropy accumulator digest was SHA-1; PRNG was `SHA1PRNG`.** Default digest upgraded to SHA-256. `SHA1PRNG` replaced with the platform default `SecureRandom`. |
| HO-10 | `SSLNetworkInterface.java` | **TLS 1.0 and TLS 1.1 not explicitly disabled.** `SSLContext("TLSv1.2")` enables a minimum but does not lock out downgrade via cipher negotiation. Now explicitly disabled. |
| P-2 | `ClientCHKBlock.java` | **Crypto algorithm 0 defaulted to PCFB instead of CTR.** PCFB with a null IV leaks the keystream prefix for splitfile blocks sharing the same encryption key. The fallback default is now `AES_CTR_256_SHA256`. |
| HO-53 | `NPFPacket.java` | **Exception-driven ACK-range parsing.** `ArrayIndexOutOfBoundsException` was caught to detect malformed packets. Replaced with explicit length checks at each read site, preventing the exception overhead and clarifying the error path. |
| HO-45 | `Probe.java` | **Topology probes opt-out instead of opt-in.** `probeLinkLengths` and `probeLocation` defaulted to `true`, silently contributing routing data to any prober. Now default `false` (opt-in). |
| HO-51 | `Probe.java` | **Probe identifier returned verbatim enables cross-session fingerprinting.** The stable per-node `probeIdentifier` long was returned directly, allowing an adversary to build a cross-session node map. Now XOR'd with a per-response random nonce; unique within a response but unlinkable across sessions. |
| HO-46 | `FreenetInetAddress.java` | **DNS lookup for peer hostname leaks local IP to DNS resolver.** Logged at `NORMAL` level when a darknet peer's noderef contains a hostname so operators are aware of the exposure. |
| HO-28 | `NodeUpdateManager.java` | **Silent runtime update URI change.** A compromised operator or XSS could silently redirect auto-updates to a malicious key. URI changes now logged prominently at `WARNING`. |
| HO-26 | `NodeUpdateManager.java` | **Revocation fetch timeout too short (5 min).** An adversary with a UOM peer could serve a malicious JAR within the window. Timeout extended to 30 minutes; deployments that hit the timeout log a loud warning rather than proceeding silently. |
| HO-25 | `WatchFeedsMessage.java` | **`WatchFeeds` FCP message not restricted to authorized clients.** Subscribing to all node alerts/feeds is a sensitive operation. Now restricted to full-access or appropriately permissioned connections. |
| HO-20 | `SendPeerMessage.java` | **`SendPeerMessage` (SendBookmark, SendURI, SendText) — authorization check documented/hardened.** Sends data to a peer node; access scoped appropriately. |
| HO-23 | `TestDDARequestMessage.java` | **DDA authorization initiation — input validation hardened.** `TestDDARequestMessage` starts the direct-disk-access authorization flow; additional guards added. |
| HO-24 | `FCPConnectionHandler.java`, `FCPServer.java` | **Connection close not signalled to the server.** `FCPConnectionHandler.close()` did not call back to `FCPServer`, preventing accurate connection-count tracking. `server.connectionClosed()` now called on every close path. |
| HO-13 | `ExternalLinkToadlet.java` | **fproxy URL (may contain `formPassword`) could leak to external resources via `Referer`.** Now suppressed before redirecting to external links. |
| HO-14 | `ToadletContextImpl.java` | **`X-Content-Type-Options: nosniff` not set.** Browsers could MIME-sniff responses away from the declared content type, enabling content-injection attacks. Header now added to all fproxy responses. |
| HO-15 | `ToadletContextImpl.java` | **`formPassword` leaked in redirect URLs** (shutdown and other paths). Moved out of query string to prevent logging and `Referer` exposure. |
| HO-16 | `ToadletContextImpl.java` | **Stack traces rendered in browser error pages.** Implementation details were exposed to anyone who could trigger an error. Stack trace now logged server-side only; browser receives a generic message. |
| HO-18 | `PageMaker.java` | **CSP `style-src` included `'unsafe-inline'`**, allowing any inline `<style>` or `style=""` attribute on fproxy pages — a vector for CSS-based data exfiltration. Tightened. |
| HO-54 | `BookmarkManager.java` | **`BookmarkManager` fields were `public`**, allowing plugins to mutate the global bookmark tree directly. Narrowed to package-private. |
| HO-55/57 | `BookmarkManager.java` | **Bookmark writes not fsynced; errors silently swallowed.** Data could be lost on a crash between write and close. `fos.getFD().sync()` added; errors now logged at `ERROR`. |
| HO-56 | `BookmarkManager.java` | **`indexOf` used instead of `lastIndexOf` for category lookup**, causing false matches when one category name is a prefix of another. Fixed. |
| HO-59 | `SaltedHashFreenetStore.java` | **Plaintext salt value logged at `DEBUG` level**, defeating at-rest encryption for store entries. Log statement removed. |
| HO-62/63 | `SaltedHashFreenetStore.java` | **Store state not `volatile`; corrupt-on-error deletes instead of backing up.** `volatile` added for cross-thread visibility; transient I/O errors now trigger a backup rather than a deletion. |
| HO-73 | `ConfigToadlet.java` | **Form password verified per-plugin instead of centrally.** Plugins could receive form submissions before the password check ran. Central pre-dispatch verification added. |
| HO-40/P-4 | `SecurityLevelsToadlet.java`, `PluginManager.java` | **No explicit warning shown when installing a plugin.** Plugins run with full node privileges. Explicit security warnings added to plugin-install UI. |
| HO-1 | `PNGFilter.java` | **iCCP (ICC color profile) chunks passed through the PNG content filter.** iCCP embeds arbitrary binary data; historical browser bugs (e.g. CVE-2010-0209) have abused ICC profiles. Chunk dropped from the passthrough list — browsers fall back to sRGB, which is the common case anyway. |

---

### Other improvements

- **Korean (한국어) UI translations** added across all web interface pages.
- **OCB nonce compliance** (`AEADInputStream.java`): nonce trimmed to ≤ 15 bytes per RFC 7253 when on-disk format stored 16; migrated from the vendored `OCBBlockCipher_v149` to upstream BouncyCastle's `OCBBlockCipher`.
- **Pebble template engine** imports updated from `com.mitchellbosecke.*` to `io.pebbletemplates.*` (package rename in 3.x).
- **`ConnectionsToadlet`** inline `style=""` attributes replaced with CSS class-based tooltips (`help-tooltip`), removing inline styles from node-generated HTML.

### Dependency upgrades

| Library | Upstream | This fork |
|---------|----------|-----------|
| BouncyCastle | 1.59 (`jdk15on`) | **1.83** (`jdk18on`) + `bcutil` |
| JNA | 4.5.2 | **5.14.0** |
| Pebble templates | 3.1.5 | **3.2.2** |
| SLF4J | 1.7.25 | **2.0.13** |
| Mockito | 1.9.5 | **5.12.0** |
| Objenesis | 1.0 | **3.3** |
| Gradle wrapper | 8.14.3 | **9.4.1** |

---

## Building

The [Gradle Wrapper](https://docs.gradle.org/current/userguide/gradle_wrapper.html) is
included. Its checksum is verified automatically against `https://services.gradle.org`.

**POSIX / Windows PowerShell:**

```bash
./gradlew jar
```

**Windows cmd:**

```bat
gradlew jar
```

The output is `build/libs/freenet.jar`.

### Build offline (ant)

```bash
mkdir -p lib
(cd lib && grep -o 'CHK.*' ../dependencies.properties \
  | xargs -P16 -I {} bash -c 'fcpget -v {} "$(echo {} | sed s,^.*/,,)"')
ant -propertyfile build.properties -f build-clean.xml \
    -Dtest.skip=true -Dfindbugs.skip=true
```

### Building the installers

The installers live in separate repos:

| Platform | Repository |
|----------|-----------|
| GNU/Linux, macOS, \*nix | [hyphanet/java_installer](https://github.com/hyphanet/java_installer) |
| Windows | [hyphanet/wininstaller-innosetup](https://github.com/hyphanet/wininstaller-innosetup) + [hyphanet/sign-windows-installer](https://github.com/hyphanet/sign-windows-installer) |

Free code signing for Windows is provided by [SignPath.io](https://about.signpath.io/) /
[SignPath Foundation](https://signpath.org/).

---

## Testing

### Unit tests

```bash
./gradlew --parallel test
```

Run a specific test class:

```bash
./gradlew --parallel test --tests '*M3UFilterTest'
```

### Test against a live node

1. Build: `./gradlew jar`
2. Stop your node.
3. Replace `freenet.jar` in your Hyphanet directory with `build/libs/freenet.jar`.
4. Start your node.

### Gradle performance tuning

Create (or extend) `gradle.properties` in the repo root:

```properties
org.gradle.parallel = true
org.gradle.daemon = true
org.gradle.jvmargs = -Xms256m -Xmx1024m
org.gradle.configureondemand = true
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for coding standards and the PR process.

**Get in touch with upstream:**

- IRC: [`#freenet`](https://web.libera.chat/?nick=Rabbit|?#freenet) on `irc.libera.chat`
- Mailing list: [hyphanet.org/pages/help](https://www.hyphanet.org/pages/help.html#mailing-lists)
- Bug tracker: [freenet.mantishub.io](https://freenet.mantishub.io/my_view_page.php)

For issues specific to **this fork**, open an issue at
[blubskye/fred](https://github.com/blubskye/fred/issues).

---

## Adding a dependency

All dependencies must be reachable via Freenet itself (`dependencies.properties`):

1. Add to `build.gradle` `dependencies` block **and** `dependencyVerification`.
   (`./gradlew jar --debug` reveals verification failures.)
2. `fcpupload {dependency.jar}`
3. Add to all installers (search for `jna-platform` as a reference).
4. Add the CHK key, size, sha256, and classpath order to `dependencies.properties`.
5. Update `scripts/update.sh`, `res/wrapper.conf`, and `res/unix/run.sh` in
   `java_installer`.

**Example entry (pebble 3.1.5):**

```properties
pebble.version=3.1.5
pebble.filename=pebble-3.1.5.jar
pebble.filename-regex=pebble-*.jar
pebble.key=CHK@y~p8HMUVXmVgfSnrmUyu2UNXMO9uMDHS5nwo2YuOKvw,yzwLFP0GXa8RjwRpicQCPFKNggDXLkTQKH8nISe0qUY,AAMC--8/pebble-3.1.5.jar
pebble.size=318169
pebble.sha256=85e77f9fd64c0a1f85569db8f95c1fb8e6ef8b296f4d6206440dc6306140c1a1
pebble.type=CLASSPATH
pebble.order=4
```

---

## Licensing

Freenet/Hyphanet is licensed under the **GPL v2 or later** — see
[LICENSE.Freenet](LICENSE.Freenet).

Some bundled components use compatible licences:

| Component | Licence |
|-----------|---------|
| Apache Commons (and similar) | Apache 2.0 |
| Mantissa | Modified BSD |
| Some plugins | GPL v3 |
