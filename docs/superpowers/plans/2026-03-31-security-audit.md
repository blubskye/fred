# Freenet (fred) Security Audit — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Perform a full static security audit of hyphanet/fred, producing a private responsible-disclosure document (Critical/High) and a public hardening-opportunities report (Medium/Low).

**Architecture:** Subsystem-by-subsystem sweep — static grep patterns first, manual deep review of all hits, then findings recorded. Seven subsystems in priority order: content filter → crypto → HTTP interface → FCP → auto-updater → plugin manager → network I/O & node.

**Tech Stack:** Java 8+, BouncyCastle crypto, Gradle build system. Branch: `next`. Latest release: build 1503.

---

## Pre-flight: output file locations

- **Private disclosure:** `~/fred-private-disclosure.md` — NEVER commit this, NEVER add to git
- **Public report:** `docs/superpowers/specs/2026-03-31-security-audit-findings-public.md` — committed at end

---

## Task 0: Setup — Baseline and Output Templates

**Files:**
- Create: `~/fred-private-disclosure.md` (outside repo — do not git add)
- Create: `docs/superpowers/specs/2026-03-31-security-audit-findings-public.md`

- [ ] **Step 1: Read NEWS.md and extract known-fixed security issues to avoid re-reporting**

Read `NEWS.md` — extract all security-relevant fixes. Known fixed as of build 1503:
- **1502:** Block-level timing attack distinguishing uploader from forwarder (reported by Yonghuan Xu) — fixed in packet handling
- **1502:** fproxy cross-origin isolation — fixed
- **1502:** Reachability check of global addresses removed (prevented Echo packet fallback leaking info)
- **1500:** Hostname resolution endless loop on F2F nodes with all peers connected — fixed
- **1501:** Reflection and global synchronized removed from fileutils

Keep this list in mind throughout — if a finding matches one of these, mark it "already fixed in buildNNNN" rather than reporting it.

- [ ] **Step 2: Create private disclosure template**

Create `~/fred-private-disclosure.md`:
```markdown
# Freenet (fred) Security Audit — Private Disclosure
**Date:** 2026-03-31
**Branch/Build:** next (post-1503)
**For:** ArneBab via IRC FLIP or Freemail. Backup: SecRabbit on #freenet (irc.libera.chat)
**Do not send via clearnet email.**

---

<!-- Add Critical findings first, then High. Template per finding:

## Finding N: [Short title]
- **Severity:** Critical / High
- **Subsystem:** e.g. client/filter
- **File(s):** src/freenet/...
- **Description:** What the vulnerability is
- **Attack scenario:** How an adversary exploits it in practice
- **F2F impact:** Yes / No
- **Already fixed in NEWS.md:** No (confirmed)
- **Suggested fix direction:** (guidance only, not a patch)

-->
```

- [ ] **Step 3: Create public report template**

Create `docs/superpowers/specs/2026-03-31-security-audit-findings-public.md`:
```markdown
# Freenet (fred) Security Audit — Public Hardening Opportunities
**Date:** 2026-03-31
**Branch/Build:** next (post-1503)
**Scope:** Medium and Low severity only. Critical/High reported privately to maintainers.

These are hardening opportunities — improvements that reduce attack surface or follow
security best practices. None are known to be actively exploited.

---

<!-- Add Medium findings first, then Low. Template per finding:

## Hardening Opportunity N: [Short title]
- **Severity:** Medium / Low
- **Subsystem / File(s):** src/freenet/...
- **Description:** What the issue is
- **Suggested fix direction:**

-->
```

---

## Task 1: client/filter — Static Sweep (50 files)

The content filter processes untrusted Freenet content before it reaches the browser.
This is the highest-priority subsystem: any bypass leaks user IP to a clearnet server.

**Files:** `src/freenet/client/filter/`

> **False-positive warning:** This subsystem contains intentional, hardened sanitization code.
> A pattern match is NOT a finding until you have read the surrounding code and confirmed it
> is reachable with malicious input that bypasses the sanitization.

- [ ] **Step 1: Sweep for clearnet URL construction**

```bash
grep -rn "new URL(" src/freenet/client/filter/ --include="*.java"
grep -rn "HttpURLConnection" src/freenet/client/filter/ --include="*.java"
grep -rn "InetAddress" src/freenet/client/filter/ --include="*.java"
grep -rn "openConnection\|openStream" src/freenet/client/filter/ --include="*.java"
```

For each hit: read the surrounding 20 lines. Is the URL constructed from untrusted content?
Can it resolve to a non-Freenet address? If yes → candidate for manual review (Task 2).

- [ ] **Step 2: Sweep for unescaped HTML output**

```bash
grep -rn "\.append(\"<\|+\"<\|\"<a \|\"<img \|\"<script\|\"<iframe\|\"<form\|\"<input" src/freenet/client/filter/ --include="*.java"
grep -rn "innerHTML\|document\.write\|eval(" src/freenet/client/filter/ --include="*.java"
```

For each hit: is the value being appended user-controlled (from Freenet content)?
Is it sanitized before appending? Note file:line for each unsanitized hit.

- [ ] **Step 3: Sweep for XXE (XML external entity injection)**

```bash
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory\|TransformerFactory" src/freenet/client/filter/ --include="*.java"
```

For each hit: check whether external entity processing is explicitly disabled.
Safe pattern requires ALL of these to be set before parsing:
```java
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```
Any factory that doesn't set all three → manual review candidate.

- [ ] **Step 4: Sweep for CSS/JS resource loading bypass**

```bash
grep -rn "src=\|href=\|url(" src/freenet/client/filter/ --include="*.java"
grep -rn "allowedScheme\|allowScheme\|isAllowed\|whitelist\|allowlist" src/freenet/client/filter/ --include="*.java"
```

Look for places where resource URLs are validated. Is every URL scheme checked?
Can `data:`, `javascript:`, `blob:`, `vbscript:` schemes pass through?

- [ ] **Step 5: Sweep for MIME type / content-type confusion**

```bash
grep -rn "getContentType\|getMimeType\|content-type\|Content-Type" src/freenet/client/filter/ --include="*.java" -i
grep -rn "sniff\|detect\|guess" src/freenet/client/filter/ --include="*.java" -i
```

Look for any path where MIME type is determined from untrusted content without strict validation.
Type confusion can allow a malicious freesite to deliver HTML disguised as an image.

- [ ] **Step 6: Record all candidates for Task 2**

List every file:line flagged in steps 1–5 that is NOT an obvious false positive.

---

## Task 2: client/filter — Manual Deep Review

- [ ] **Step 1: Read the main filter entry points**

```bash
grep -rn "class.*Filter\|implements.*Filter\|public.*filter\|public.*sanitize\|public.*process" src/freenet/client/filter/ --include="*.java" | grep -v "test\|Test"
```

Identify the primary classes (e.g. `ContentFilter`, `HTMLFilter`, `CSSFilter`).
Read each one in full. Understand: what input does it accept? What does it guarantee about output?

- [ ] **Step 2: Trace every Task 1 candidate through the call graph**

For each file:line flagged in Task 1:
- Read the full method containing the hit
- Trace back to where the input originates — is it from Freenet content (untrusted)?
- Trace forward to where the output goes — does it reach the browser or network?
- If both: this is a real finding. Assess severity:
  - **Critical:** leads to clearnet request (IP leak / de-anonymization)
  - **High:** leads to arbitrary JS execution in browser
  - **Medium:** leads to rendering of attacker-controlled content with limited impact
  - **Low:** defence-in-depth gap, no direct exploitability shown

- [ ] **Step 3: Check for filter bypass via nested encoding**

Manually search for cases where input is decoded once before filtering but the browser
would decode it again (double-encoding bypass). Look for:
```bash
grep -rn "decode\|unescape\|percent\|entity" src/freenet/client/filter/ --include="*.java" -i
```
Verify that decoding and filtering happen in the correct order and that no second decode occurs post-filter.

- [ ] **Step 4: Record confirmed findings**

For each confirmed vulnerability:
- Critical or High → add to `~/fred-private-disclosure.md`
- Medium or Low → add to `docs/superpowers/specs/2026-03-31-security-audit-findings-public.md`

---

## Task 3: crypt — Static Sweep (58 files)

**Files:** `src/freenet/crypt/`

> **False-positive warning:** BouncyCastle and custom implementations are common here.
> Algorithm name string matches must be verified against actual usage — a string `"AES/ECB"`
> in a comment or test is not a vulnerability.

- [ ] **Step 1: Sweep for weak or broken algorithms**

```bash
grep -rn '"MD5"\|"SHA-1"\|"SHA1"\|"DES"\|"RC4"\|"RC2"\|"Blowfish"' src/freenet/crypt/ --include="*.java"
grep -rn '"AES/ECB\|/ECB/' src/freenet/crypt/ --include="*.java"
grep -rn 'ECBBlockCipher\|ECBMode' src/freenet/crypt/ --include="*.java"
```

For each hit: is this in production code (not a test or comment)?
Is it used for security purposes (key derivation, data encryption, MAC) or non-security purposes (e.g. content addressing where collision resistance is not required)?
MD5/SHA1 for content-addressing CHK keys is likely intentional and not a vulnerability.

- [ ] **Step 2: Sweep for insecure randomness**

```bash
grep -rn "new Random()\|Math\.random()" src/freenet/crypt/ --include="*.java"
grep -rn "new Random()\|Math\.random()" src/freenet/node/ --include="*.java"
grep -rn "new Random()\|Math\.random()" src/freenet/io/ --include="*.java"
```

`java.util.Random` and `Math.random()` are NOT cryptographically secure.
Any use in key generation, nonce generation, session tokens, or routing decisions is a finding.

- [ ] **Step 3: Sweep for hardcoded keys or IVs**

```bash
grep -rn "byte\[\].*=.*{.*0x\|new byte\[\].*{.*0x" src/freenet/crypt/ --include="*.java"
grep -rn "hardcoded\|static.*key\|static.*iv\|static.*nonce\|static.*salt" src/freenet/crypt/ --include="*.java" -i
grep -rn "\"[A-Za-z0-9+/]{32,}\"" src/freenet/crypt/ --include="*.java"
```

Any static/hardcoded key material used for encryption or signing is Critical.

- [ ] **Step 4: Sweep for IV/nonce reuse**

```bash
grep -rn "static.*IV\|static.*iv\|reuse.*iv\|iv.*reuse\|new byte\[.*\].*iv\|IvParameterSpec" src/freenet/crypt/ --include="*.java" -i
grep -rn "GCMParameterSpec\|CCMParameterSpec\|OCBParameter" src/freenet/crypt/ --include="*.java"
```

IVs/nonces in GCM, CCM, OCB, CTR modes MUST be unique per encryption. A counter that resets,
a static IV, or an IV derived without sufficient entropy is Critical.

- [ ] **Step 5: Sweep for SecureRandom seeding issues**

```bash
grep -rn "SecureRandom\|setSeed\|generateSeed" src/freenet/crypt/ --include="*.java"
```

Verify `SecureRandom` is not seeded with low-entropy input. Using `setSeed()` with predictable
values (e.g. `System.currentTimeMillis()`) is High severity.

- [ ] **Step 6: Record all candidates for Task 4**

---

## Task 4: crypt — Manual Deep Review

- [ ] **Step 1: Trace the key derivation chain**

Find the primary key derivation function(s):
```bash
grep -rn "deriveKey\|HKDF\|PBKDF\|KDF\|KeySpec\|SecretKeyFactory" src/freenet/crypt/ --include="*.java"
```

For each: read the full derivation. Is input entropy sufficient? Is a salt used?
Is the output key space adequate for the algorithm? Is the derivation reversible?

- [ ] **Step 2: Audit AEAD usage (GCM/OCB/CCM)**

```bash
grep -rn "AEADBlockCipher\|GCMBlockCipher\|OCBBlockCipher\|AEADParameters\|GCMParameterSpec" src/freenet/crypt/ --include="*.java"
```

For each AEAD cipher:
- Is the nonce unique per message? (Nonce reuse in GCM/OCB is catastrophic — key recovery possible)
- Is the AAD (additional authenticated data) correctly bound?
- Is the authentication tag verified before any plaintext is used?

- [ ] **Step 3: Check DSA/RSA/ECDSA signature usage**

```bash
grep -rn "Signature\|DSA\|RSA\|ECDSA\|signData\|verifyData\|sign(\|verify(" src/freenet/crypt/ --include="*.java"
```

For each signature operation:
- Is the signature verified before the signed data is acted on?
- Is the public key pinned or loaded from a trusted source?
- Is DSA used with a random k-value (static k → private key recovery)?

- [ ] **Step 4: Record confirmed findings**

---

## Task 5: clients/http — Static Sweep (116 files)

**Files:** `src/freenet/clients/http/`

The local web interface runs on localhost but processes content fetched from Freenet (untrusted).
CSRF is the primary concern — a malicious freesite could trigger local HTTP requests.

- [ ] **Step 1: Sweep for CSRF token handling**

```bash
grep -rn "formPassword\|csrf\|token\|nonce" src/freenet/clients/http/ --include="*.java" -i
grep -rn "POST\|handlePost\|processPost" src/freenet/clients/http/ --include="*.java" -i
```

Find every POST handler. For each: does it validate a CSRF token before acting?
Note any POST handler that acts on state without token validation → High/Critical.

- [ ] **Step 2: Sweep for cross-origin isolation**

```bash
grep -rn "Cross-Origin\|COOP\|COEP\|CORP\|Access-Control" src/freenet/clients/http/ --include="*.java" -i
grep -rn "addHeader\|setHeader\|responseHeaders" src/freenet/clients/http/ --include="*.java" -i
```

Build 1502 added cross-origin isolation. Verify these headers are present on all responses:
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp`

Any response path that omits them → Medium.

- [ ] **Step 3: Sweep for XSS in HTML generation**

```bash
grep -rn "\.append(\|\.write(\|HTMLNode\|addChild\|getContent(" src/freenet/clients/http/ --include="*.java" | grep -v "//.*append\|//.*write"
grep -rn "\+ \"<\|\"<a \|\"<img \|\"<script" src/freenet/clients/http/ --include="*.java"
```

For each: is the value being appended user-controlled or Freenet-content-derived?
Is it HTML-escaped before insertion? Unescaped user-controlled HTML → High.

- [ ] **Step 4: Sweep for open redirect**

```bash
grep -rn "sendRedirect\|Location:\|response\.redirect\|301\|302\|303" src/freenet/clients/http/ --include="*.java"
grep -rn "redirect\|Redirect" src/freenet/clients/http/ --include="*.java"
```

For each redirect: is the target URL validated to be a local or Freenet URL?
A redirect to an arbitrary URL could be used to leak a referer header with sensitive info → Medium.

- [ ] **Step 5: Sweep for path traversal in file serving**

```bash
grep -rn "new File(\|Paths\.get(\|FileInputStream(\|FileOutputStream(" src/freenet/clients/http/ --include="*.java"
grep -rn "\.\./\|path.*concat\|path.*append\|canonicalPath" src/freenet/clients/http/ --include="*.java"
```

For each: is the path constructed from request parameters? Is it canonicalized and confined
to expected directories before use? Any `../` that escapes the data directory → High.

- [ ] **Step 6: Sweep for information disclosure**

```bash
grep -rn "printStackTrace\|getStackTrace\|exception\.getMessage\|e\.toString()" src/freenet/clients/http/ --include="*.java"
grep -rn "serverVersion\|Server:\|X-Powered-By" src/freenet/clients/http/ --include="*.java" -i
```

Stack traces or version strings in HTTP responses reveal implementation details → Low/Medium.

- [ ] **Step 7: Record all candidates for Task 6**

---

## Task 6: clients/http — Manual Deep Review

- [ ] **Step 1: Audit the CSRF token implementation end-to-end**

Find the class that generates and validates the form password/CSRF token.
Read it completely. Verify:
- Token is cryptographically random (not sequential, not time-based)
- Token is bound to the session (not global/static)
- Token is checked on every state-changing POST, not just some
- Token is not present in GET parameters (logged in server logs)

- [ ] **Step 2: Audit the ToadletContext / request handling pipeline**

```bash
grep -rn "class.*Toadlet\|ToadletContext\|handleMethodGET\|handleMethodPOST" src/freenet/clients/http/ --include="*.java"
```

Read the base Toadlet class and one or two concrete implementations.
Look for: is authentication checked consistently? Are there any endpoints that skip CSRF or auth checks?

- [ ] **Step 3: Verify fproxy Content-Security-Policy**

```bash
grep -rn "Content-Security-Policy\|CSP\|script-src\|default-src" src/freenet/clients/http/ --include="*.java" -i
```

A strong CSP prevents XSS even if sanitization fails. If absent or permissive → Medium.

- [ ] **Step 4: Record confirmed findings**

---

## Task 7: clients/fcp — Static Sweep (143 files)

**Files:** `src/freenet/clients/fcp/`

FCP is the protocol used by external client applications. It's network-facing and parses untrusted messages. Primary concerns: message injection, parser bugs, authentication bypass, path traversal.

- [ ] **Step 1: Sweep for XML/message parsing — XXE**

```bash
grep -rn "DocumentBuilderFactory\|SAXParserFactory\|XMLInputFactory\|XMLReader\|SAXBuilder" src/freenet/clients/fcp/ --include="*.java"
```

For each factory instantiation, verify external entity processing is disabled (same check as Task 1 Step 3).

- [ ] **Step 2: Sweep for path traversal in FCP file operations**

```bash
grep -rn "new File(\|Paths\.get(\|PersistentTempFileBucket\|diskDir\|downloadTo\|saveTo" src/freenet/clients/fcp/ --include="*.java"
```

FCP allows inserting and retrieving files. If a client can specify arbitrary paths,
it could write files outside the expected download directory → High/Critical.

- [ ] **Step 3: Sweep for authentication and authorization**

```bash
grep -rn "restricted\|fullAccess\|checkAccess\|isAuthorized\|password\|auth" src/freenet/clients/fcp/ --include="*.java" -i
grep -rn "FCPServer\|listenOn\|bind\|localhost\|127\.0\.0\.1" src/freenet/clients/fcp/ --include="*.java"
```

FCP should only bind to localhost by default. Verify:
- Default bind address is loopback only
- If network-accessible FCP is enabled, is authentication enforced?
- Is there a privilege separation between restricted and full-access connections?

- [ ] **Step 4: Sweep for command injection via message fields**

```bash
grep -rn "Runtime\|ProcessBuilder\|exec(\|shell\|cmd" src/freenet/clients/fcp/ --include="*.java" -i
```

Any exec() call triggered from FCP message content → Critical.

- [ ] **Step 5: Sweep for integer overflow in length fields**

```bash
grep -rn "DataLength\|payloadLength\|readInt\|readLong\|allocate(" src/freenet/clients/fcp/ --include="*.java"
```

FCP messages contain length fields. Negative or very large values could cause:
- Negative array allocation (exception DoS)
- Integer overflow leading to under-allocation then buffer overread
- OOM via large allocation

For each: is the length validated against a sane maximum before allocating?

- [ ] **Step 6: Record all candidates for Task 8**

---

## Task 8: clients/fcp — Manual Deep Review

- [ ] **Step 1: Trace the FCP message parsing entry point**

```bash
grep -rn "FCPMessage\|parseMessage\|readMessage\|FCPConnection" src/freenet/clients/fcp/ --include="*.java" | grep "class\|static\|public"
```

Read the primary message parsing class. Trace the path from raw bytes → parsed message → handler dispatch.
Look for: what happens with malformed messages? Is there a length cap? Can a single connection consume unbounded memory?

- [ ] **Step 2: Audit file path handling in download/upload operations**

Find the class handling `ClientGet` and `ClientPut` FCP messages.
Read the path handling in full. Verify that:
- Paths are canonicalized with `getCanonicalPath()`
- The canonical path is checked to start with an allowed base directory
- Symlink traversal is considered (canonicalization resolves symlinks on most JVMs)

- [ ] **Step 3: Record confirmed findings**

---

## Task 9: node/updater — Full Review (11 files)

**Files:** `src/freenet/node/updater/`

The auto-updater downloads and installs new node versions. A compromised or spoofed update
is an RCE that persists across restarts. This subsystem is small enough for a full read.

- [ ] **Step 1: Read all 11 files in the updater**

```bash
find src/freenet/node/updater -name "*.java" | sort
```

Read each file. While reading, note:
- Where is the update downloaded from? (Should be a Freenet key, not a clearnet URL)
- How is the update signature verified?
- What keys are trusted for signing?
- Is the key list hardcoded, pinned, or fetched dynamically?
- Is there a rollback mechanism? Could an attacker serve an old vulnerable version?

- [ ] **Step 2: Trace the signature verification chain**

```bash
grep -rn "verify\|signature\|sign\|PublicKey\|Certificate" src/freenet/node/updater/ --include="*.java" -i
```

Read the full signature check. Verify:
- Signature is verified BEFORE the new jar is loaded/executed
- The verified jar is not writable between verification and execution
- The public key used for verification is pinned (not fetched from the update itself)

- [ ] **Step 3: Check for TOCTOU (time-of-check/time-of-use)**

Between signature verification and jar execution, can the file be replaced?
Look for any gap between `verify(file)` and `exec(file)` where the file path is used
but not re-verified. On Linux this requires write access to the temp directory but is worth noting.

- [ ] **Step 4: Verify update source is Freenet, not clearnet**

```bash
grep -rn "http://\|https://\|URL\|HttpURLConnection" src/freenet/node/updater/ --include="*.java"
```

Any clearnet URL in the updater → Critical (update integrity depends on TLS, not Freenet's guarantees).

- [ ] **Step 5: Record confirmed findings**

---

## Task 10: pluginmanager — Full Review (45 files)

**Files:** `src/freenet/pluginmanager/`

Plugins run in the same JVM as fred. A malicious or compromised plugin has full access to the
JVM, all node data, and the host OS. This is the primary RCE and JVM escape surface.

- [ ] **Step 1: Sweep for class loading from untrusted sources**

```bash
grep -rn "ClassLoader\|URLClassLoader\|loadClass\|defineClass\|Class\.forName" src/freenet/pluginmanager/ --include="*.java"
```

For each: where does the class data come from? Is it a Freenet key (content-addressed)?
Is the plugin jar signature verified before loading?

- [ ] **Step 2: Sweep for Runtime.exec / ProcessBuilder**

```bash
grep -rn "Runtime\.getRuntime\|Runtime\.exec\|ProcessBuilder\|Process\b" src/freenet/pluginmanager/ --include="*.java"
```

Any exec within pluginmanager that is triggered by plugin input → Critical.

- [ ] **Step 3: Sweep for ScriptEngine / Reflection**

```bash
grep -rn "ScriptEngine\|ScriptEngineManager\|Nashorn\|Rhino\|Groovy\|eval(" src/freenet/pluginmanager/ --include="*.java"
grep -rn "\.invoke(\|\.newInstance(\|getDeclaredMethod\|setAccessible(true)" src/freenet/pluginmanager/ --include="*.java"
```

A ScriptEngine executing untrusted plugin-supplied script → Critical.
`setAccessible(true)` on private fields/methods via reflection can bypass encapsulation.

- [ ] **Step 4: Audit plugin sandboxing (SecurityManager)**

```bash
grep -rn "SecurityManager\|Policy\|Permission\|checkPermission\|AccessController" src/freenet/pluginmanager/ --include="*.java"
```

Java SecurityManager was deprecated in Java 17 and removed in Java 24. If fred relied on it for
plugin sandboxing, that protection may now be absent. Check:
- Is there any sandbox boundary enforced on plugin code?
- If SecurityManager-based, is there a fallback for newer JVMs?
- If no sandbox exists, is this documented as a known limitation?

- [ ] **Step 5: Check plugin signature verification**

```bash
grep -rn "verify\|signature\|JarSigner\|JarFile\|manifest\|Manifest" src/freenet/pluginmanager/ --include="*.java" -i
```

Are plugins signature-verified before loading? What keys are trusted?
Can a user be socially engineered into loading an unsigned plugin via the UI?

- [ ] **Step 6: Sweep for native code loading**

```bash
grep -rn "System\.load(\|System\.loadLibrary(\|native " src/freenet/pluginmanager/ --include="*.java"
```

A plugin that loads a native library escapes the JVM entirely → Critical.

- [ ] **Step 7: Record confirmed findings**

---

## Task 11: io / node — Static Sweep (54 + 127 files)

**Files:** `src/freenet/io/`, `src/freenet/node/` (top-level only, not subdirectories already covered)

- [ ] **Step 1: Sweep for unbounded buffer allocation (DoS / OOM)**

```bash
grep -rn "new byte\[\|ByteBuffer\.allocate(\|readFully\|read.*length" src/freenet/io/ --include="*.java"
grep -rn "new byte\[\|ByteBuffer\.allocate(\|readFully\|read.*length" src/freenet/node/ --include="*.java"
```

For each allocation from a network-supplied length field:
- Is the length validated against `MAX_PACKET_SIZE` or equivalent before allocating?
- Can an adversary send a 2GB length field to cause OOM?

- [ ] **Step 2: Sweep for peer authentication bypass**

```bash
grep -rn "authenticate\|handshake\|verifyPeer\|peerIdentity\|nodeIdentity" src/freenet/io/ --include="*.java"
grep -rn "authenticate\|handshake\|verifyPeer\|peerIdentity\|nodeIdentity" src/freenet/node/ --include="*.java"
```

Look for: can a peer skip the handshake and send routing/data messages directly?
Is identity verified before messages are processed?

- [ ] **Step 3: Sweep for integer overflow in packet handling**

```bash
grep -rn "packetSize\|fragmentSize\|offset.*length\|length.*offset\|int.*length\s*=" src/freenet/io/ --include="*.java"
```

In Java, array indices are int. If `offset + length` overflows int (both legitimate but sum > 2^31),
the result is negative → `ArrayIndexOutOfBoundsException` or incorrect range used.
Look for any arithmetic on packet offsets/lengths without overflow checks.

- [ ] **Step 4: Sweep for clearnet leaks in node**

```bash
grep -rn "new URL(\|HttpURLConnection\|InetAddress\.getByName(\|openConnection" src/freenet/node/ --include="*.java"
```

Node code should never make outbound clearnet connections based on content.
Seednodes and update fetches should go through Freenet.
Any clearnet fetch from node/ triggered by received packet content → Critical.

- [ ] **Step 5: Sweep for serialization / deserialization**

```bash
grep -rn "ObjectInputStream\|ObjectOutputStream\|readObject(\|writeObject(" src/freenet/io/ --include="*.java"
grep -rn "ObjectInputStream\|ObjectOutputStream\|readObject(\|writeObject(" src/freenet/node/ --include="*.java"
```

Java deserialization of untrusted data is a classic RCE vector. Any `ObjectInputStream` reading
from network data → Critical (requires manual confirmation of data origin).

- [ ] **Step 6: Sweep for native / JNI**

```bash
grep -rn "System\.load\|System\.loadLibrary\|native " src/freenet/io/ --include="*.java"
grep -rn "System\.load\|System\.loadLibrary\|native " src/freenet/node/ --include="*.java"
```

Document any native method declarations and verify they are not reachable from untrusted input.

- [ ] **Step 7: Record all candidates for Task 12**

---

## Task 12: io / node — Manual Deep Review

- [ ] **Step 1: Audit the packet receive and dispatch path**

```bash
grep -rn "receivePacket\|processIncoming\|packetReceived\|handlePacket" src/freenet/io/ --include="*.java"
```

Read the packet receive pipeline end-to-end. Verify:
- Packet length is validated before any buffer is allocated
- Peer identity is verified before the packet payload is acted on
- Malformed packets throw a contained exception, not one that propagates to crash the node

- [ ] **Step 2: Audit the probe / diagnostic endpoint**

```bash
find src/freenet/node/probe -name "*.java"
grep -rn "probe\|Probe" src/freenet/node/ --include="*.java" | head -20
```

The probe subsystem allows network-level queries. Check:
- Can probe requests be used to enumerate information about the local node or its peers?
- Is there rate limiting on probe requests?
- Does probing reveal information useful for de-anonymization?

- [ ] **Step 3: Record confirmed findings**

---

## Task 13: Final Review, Document Finalization, and Commit

- [ ] **Step 1: Cross-check all findings against NEWS.md**

For every finding in both documents, verify it is not already fixed in builds 1500–1503.
Remove any finding with "Already fixed: Yes" from the private document.
Add a note "fixed in build NNNN" to any public finding that was partially addressed.

- [ ] **Step 2: Review private disclosure for completeness and accuracy**

For each finding in `~/fred-private-disclosure.md`:
- Is the file:line correct and still present in the `next` branch?
- Is the attack scenario realistic, not speculative?
- Is the F2F impact assessment correct?
- Is the suggested fix direction sound without being prescriptive?

Remove or downgrade any finding where the exploitability cannot be demonstrated from the code alone.

- [ ] **Step 3: Review public report for tone and completeness**

For each entry in `docs/superpowers/specs/2026-03-31-security-audit-findings-public.md`:
- Is it framed as a "hardening opportunity", not an alarm?
- Is the fix direction actionable?
- Does it accurately reflect severity?

- [ ] **Step 4: Commit the public report**

```bash
git add docs/superpowers/specs/2026-03-31-security-audit-findings-public.md
git commit -m "docs: add security audit public hardening report (2026-03-31)"
```

- [ ] **Step 5: Send private disclosure**

Send `~/fred-private-disclosure.md` content to ArneBab via:
- **Primary:** IRC FLIP DM
- **Alternative:** Freemail to ArneBab
- **Backup (if no response in 1 week):** SecRabbit on #freenet at irc.libera.chat

Do NOT send via clearnet email. Do NOT post publicly before acknowledgement.

- [ ] **Step 6: File public bugs**

For each entry in the public report, file a bug at bugs.hyphanet.org referencing the report.
Title format: `[Security Hardening] <short title from report>`
