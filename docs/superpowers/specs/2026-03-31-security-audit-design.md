# Freenet (fred) Security Audit — Design Spec

**Date:** 2026-03-31
**Branch:** `next` (latest active development branch)
**Auditor:** BlubSkye (contributing to Hyphanet community)
**Disclosure recipient:** ArneBab (Hyphanet lead) via IRC FLIP DM or Freemail

---

## Purpose

Perform a comprehensive security audit of the hyphanet/fred codebase to identify vulnerabilities,
with responsible disclosure of critical/high findings to Hyphanet leadership and public reporting
of medium/low findings to the project bugtracker.

Freenet users can be in genuinely dangerous situations (censorship, persecution). False negatives
(missed critical bugs) are more dangerous than spending extra time — the audit prioritises
thoroughness over speed.

---

## Codebase Reference

- **Repo:** github.com/hyphanet/fred, `next` branch
- **Latest release at audit time:** build 1506 (early 2026)
- **Cross-reference:** All findings must be checked against `NEWS.md` and release notes to confirm
  they have not already been fixed. Do not report already-patched vulnerabilities as new findings.
- **Crypto library:** Much of the cryptography uses BouncyCastle or custom implementations
  (common in older Freenet code). Naive pattern matches on algorithm names may produce false
  positives — always verify actual usage context.

---

## Scope

### In scope

All Java source under `src/freenet/`, covering:

| Subsystem | Path | Primary risk class |
|-----------|------|--------------------|
| Content filter | `src/freenet/client/filter/` | Clearnet leak, XSS |
| Cryptography | `src/freenet/crypt/` | Crypto misuse, weak primitives |
| HTTP interface | `src/freenet/clients/http/` | CSRF, XSS, session fixation |
| FCP protocol | `src/freenet/clients/fcp/` | Protocol injection, parser bugs |
| Auto-updater | `src/freenet/node/updater/` | Supply chain / RCE via update |
| Plugin manager | `src/freenet/pluginmanager/` | RCE, JVM escape surface |
| Network I/O & node | `src/freenet/io/`, `src/freenet/node/` | DoS, peer spoofing, packet exploits |

### Optional extension (time permitting)

High-usage official plugins (Web of Trust, Freemail) run in the same JVM as fred and represent
additional RCE surface. A quick sweep of their repos is a worthwhile follow-on but is not required
for this first-pass audit of core fred.

### Out of scope

- Known-unfixable Sybil/opennet attacks (acknowledged in `SECURITY.md`)
- UI cosmetics, performance, code style
- Third-party libraries in `lib/`

---

## Vulnerability Classes

Static sweep patterns per class:

| Class | Patterns |
|-------|----------|
| Clearnet leak | `URL`, `HttpURLConnection`, `InetAddress`, `Socket` with external hosts; `java.net` outside node comms |
| XSS / HTML injection | Unescaped output in HTML generation, direct string concat into HTML |
| Crypto misuse | `MD5`, `SHA1`, `DES`, `ECB` mode, `new SecureRandom()` misuse, hardcoded keys/IVs, `Math.random()` in security contexts |
| Deserialization / RCE | `ObjectInputStream`, `Runtime.exec`, `ProcessBuilder`, `ScriptEngine`, `Class.forName` + `newInstance`, reflection on untrusted classes |
| CSRF | Form handlers lacking token validation |
| Path traversal | `new File(userInput)`, string concat into file paths |
| XXE | `DocumentBuilderFactory` without disabling external entities |
| Native / JVM escape | `System.load`, `System.loadLibrary`, JNI calls |

---

## Methodology

### Phase 1 — Static sweep (per subsystem)
Pattern-based grep across the subsystem for each vulnerability class. Records file, line, pattern
matched, and brief context note.

**Important false-positive notes:**
- The content filter (`client/filter`) contains custom escaping and sanitization logic that may
  look unsafe in a naive grep but is intentional and hardened. All flagged items must be read in
  full context before recording as a finding.
- The auto-updater has been hardened over time with key pinning and update key rotation. Pattern
  matches on "weak" signature patterns require careful review against the actual verification flow.
- BouncyCastle and custom crypto implementations are prevalent — algorithm name matches alone are
  insufficient; verify the full call chain.

### Phase 2 — Manual deep review
For every flagged item from Phase 1 plus known-risky architectural areas:
- Key derivation logic
- Update signature verification (including key pinning and rotation)
- Plugin class loading and sandboxing
- Peer authentication

Each finding assessed for exploitability and real-world impact against a Freenet user in a hostile
environment. Dynamic testing (fuzzing FCP, feeding malicious freesite content through the filter,
crafted inserts to test clearnet leak paths) is noted as a valuable complement but is out of scope
for this static-focused first pass.

### Subsystem priority order
1. `client/filter` — rendered in browser, highest de-anonymization risk
2. `crypt` — all anonymity depends on correct crypto
3. `clients/http` — processes untrusted Freenet content
4. `clients/fcp` — network-facing, parses untrusted messages
5. `node/updater` — auto-update with signature verification
6. `pluginmanager` — loads and executes third-party code
7. `io` / `node` — large network I/O parsing attack surface

---

## Severity Scale

| Severity | Definition |
|----------|-----------|
| Critical | Direct de-anonymization, unauthenticated RCE, or JVM escape |
| High | Exploitable with effort; significant privacy or integrity impact |
| Medium | Requires local access, user interaction, or chaining to exploit |
| Low | Hardening opportunity, best-practice deviation |

F2F (friend-to-friend) mode impact escalates severity by one level — there are no known unfixable
identification attacks against F2F mode, so any issue affecting it is treated more seriously.

---

## Output Documents

### 1. Private disclosure (NOT committed to repo)
Filename: `private-disclosure.md` (kept locally, sent to ArneBab via IRC FLIP or Freemail)
**Do not send via clearnet email unless no other option exists.**
Backup contact if ArneBab is unavailable: SecRabbit on IRC (#freenet at irc.libera.chat).

Structure per finding:
```
## Finding N: [Short title]
- Severity: Critical / High
- Subsystem: e.g. client/filter
- File(s): src/freenet/...
- Description: What the vulnerability is
- Attack scenario: How an adversary would exploit it
- F2F impact: Yes / No
- Suggested fix direction: (guidance only, not a patch)
- Already fixed in NEWS.md: Yes / No (confirm before sending)
```

Contains: Critical and High severity findings only.
Ordered: Critical → High, then by subsystem.

### 2. Public report (committed to repo)
Path: `docs/superpowers/specs/2026-03-31-security-audit-findings-public.md`

Medium and low severity findings are framed as **hardening opportunities** to help the community
without causing alarm. Language should be constructive and specific.

Structure per finding:
```
## Hardening Opportunity N: [Short title]
- Severity: Medium / Low
- Subsystem / File(s)
- Description
- Suggested fix direction
```

Contains: Medium and Low severity findings only.
Ordered: Medium → Low, then by subsystem.

---

## Responsible Disclosure Process

1. Complete audit and draft both documents.
2. Cross-reference all findings against `NEWS.md` — remove any already patched in build 1506 or earlier.
3. Self-review private disclosure: verify each finding is reproducible from the code, no speculation.
4. Send private disclosure to ArneBab via IRC FLIP DM or Freemail. Avoid clearnet channels.
5. If no response within one week, follow up once; if still no response, try SecRabbit on IRC as backup.
6. Wait for acknowledgement before any public discussion of critical/high findings.
7. Commit and publish the public report.
8. File individual bugs at bugs.hyphanet.org for each medium/low finding, referencing the public report.
