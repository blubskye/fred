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
build **1506**. It tracks upstream's `next` branch and layers a set of security hardening
patches and quality-of-life improvements on top.

---

## What's different from upstream

### Security hardening (HO-series audit findings)

| ID | Area | Change |
|----|------|--------|
| HO-53 | `NPFPacket` | Replace exception-driven bounds handling with explicit length checks during ACK-range parsing |
| HO-72 | `SessionKey` | Restrict AES-256/HMAC session key fields from `public` to package-private to prevent leakage to plugins |
| — | `AEADInputStream` | Fix OCB nonce truncation to comply with RFC 7253 (max 15 bytes); use upstream BouncyCastle `OCBBlockCipher` |
| — | FCP layer | Input size/length validation added across `FCPConnectionInputHandler`, `FCPServer`, and FCP message handlers |
| — | HTTP toadlets | Input validation and output encoding hardening in `ConfigToadlet`, `ConnectionsToadlet`, `ToadletContextImpl`, `Cookie`, and others |
| — | Plugin manager | Safer plugin loading and classpath isolation in `JarClassLoader`, `PluginHandler`, `PluginManager` |
| — | Store layer | Concurrency fixes in `SaltedHashFreenetStore` and `LockManager` |

### Dependency updates

- **BouncyCastle** upgraded from 1.78.1 → **1.83** (removed duplicate 1.78.1 jar)
- **Gradle** upgraded to **9.4.1**

### Localisation

- **Korean (한국어)** translations added across the web interface

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
