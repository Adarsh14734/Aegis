# Aegis S3a — MCP-layer egress control and outbound secret scanning

**Sprint:** S3a (the MCP-layer half of S3; no TLS interception, no network proxy)
**Date:** 2026-08-15
**Controls touched:** C4 (partial), C5 (partial)
**Status:** both **VERIFIED (harness, macOS)**. Neither is VERIFIED unqualified,
and neither is the control the threat model names. See §What this is not.

---

## What was built

| File | Role |
|---|---|
| `aegis/egress.py` | URL extraction from an argument tree, host allowlist, SSRF rejection |
| `aegis/dlp.py` | High-confidence secret patterns; returns a pattern name, never a value |
| `aegis/policy.py` | Sequences them: `deny_paths → DLP → egress → tool rule → containment → default` |
| `tests/drive.py` | +14 cases, run through the real proxy |
| `tests/s3a.py` | 99 cases: FP corpus, SSRF encodings, policy validation, disclosure |
| `evidence/S3a-transcript.txt` | Raw drive.py output, 25 audit rows, chain verifying |
| `evidence/S3a-unit.txt` | Raw unit output, 99/99 |
| `evidence/S3a-audit-anomaly.txt` | An unexplained gap in the shared audit db — read this |

`aegis/audit.py` and `aegis/verify.py` are untouched. The schema and the
`row_hash` formula are unchanged, and `verify.py` verifies databases containing
S3a rows without modification — shown at the end of `evidence/S3a-transcript.txt`
and again in `tests/s3a.py` §6.

---

## What this is NOT

C4 in THREAT-MODEL.md is a *TLS-terminating egress proxy with a domain
allowlist*. **This is not that**, and D3 already explains why the difference
matters: "Filtering on the client-supplied hostname without inspecting TLS can
be defeated by domain fronting."

S3a reads a hostname out of a tool argument and believes it. It constrains what
a *tool call can be pointed at*. It does not constrain what the downstream
server then does. Specifically it is blind to:

- an allowed tool that fetches a URL it derived itself, or follows a redirect
  from an allowed host to a denied one
- DNS rebinding: `api.example.com` resolving to `169.254.169.254`. No DNS
  resolution happens at policy time — deliberately, because resolving would
  make policy depend on a service the agent may influence and would still be a
  TOCTOU window, since the address checked is not the address later dialled
- any request not expressed as a URL in a tool argument, including everything
  a Bash tool does (S1 gap #4 is unchanged)
- a server that ignores the URL argument entirely

Permitted description: *"tool calls are checked against a deny-by-default
destination allowlist at the MCP layer."* Forbidden: *"egress is controlled",*
*"data cannot leave"*, or anything implying C4 is done.

The same applies to C5. `dlp.py` sees tool **arguments**. It does not see
request bodies, because at this layer there are none.

---

## Evaluation order

```
deny_paths → DLP → egress → tool rule → containment → default
```

DLP and egress sit above the tool rule for the same reason `deny_paths` does:
they must be unreachable by any allow rule. A tool being allowed says the
*operation* is permitted; it never says the *content* is. `policy.py` walks the
argument tree exactly once and hands the same string list to both, so the two
controls cannot disagree about what the arguments contained. An argument tree
too deep or too large to scan completely is denied (`rule_id: scan_limit`)
rather than partially scanned.

`allowed_domains` absent means the empty list, and the empty list denies every
URL. A bare `"*"` entry is rejected at load and the proxy refuses to start, on
the same reasoning that already rejects `default_effect: "allow"`.
`"*.example.com"` is rejected too rather than silently reinterpreted —
`example.com` already covers its subdomains.

---

## Verification

**`tests/s3a.py` — 99/99**, raw output in `evidence/S3a-unit.txt`:

| Section | Cases | What it covers |
|---|---|---|
| 1 | 14 | DLP false positives: git SHAs, lockfile hashes, UUIDs, `-----BEGIN PUBLIC KEY-----`, `sk_test_`, prose about tokens, `for key in config.keys()` |
| 2 | 14 | Every pattern fires on a real-shaped secret, and reports the right name |
| 3 | 13 | URL extraction: prose, nesting, `data:` vs `{"data":1,"x":2}`, Windows paths, `TODO:` |
| 4 | 32 | Host policy and SSRF encodings |
| 5 | 12 | `allowed_domains` validation |
| 6 | 14 | Disclosure rule, end to end through the real proxy |

**`tests/drive.py` — 5 allowed, 20 denied**, all as specified, in
`evidence/S3a-transcript.txt`. The eleven S1 cases produce byte-identical
`rule_id`s to S1, so the S3a insertions did not disturb C1/C2.

**SSRF encodings all denied**, each verified individually: `127.0.0.1`, `[::1]`,
`[::ffff:127.0.0.1]` (the IPv4-mapped form, which `IPv6Address.is_loopback`
misses), `2130706433`, `0x7f000001`, `127.1`, `010.010.010.010`,
`169.254.169.254`, RFC1918 ranges, `localhost`, `.localhost`, `.local`, and a
public raw IP literal. Also denied: `https://api.example.com@evil.xyz/`, where
the allowed host is the userinfo and the real host is not — a bypass no case in
the brief asked for, added because S1 recorded that "adversarial test suites are
always a subset of what a capable model will actually try."

**The disclosure rule is verified against bytes, not intent.** `tests/s3a.py` §6
runs the real proxy on arguments containing a real-shaped AWS key and a JWT,
then greps the raw audit database, its `-wal`/`-shm`, the proxy's stderr, and
the denial frames for those values. All absent; the pattern name and the
argument path are present. Sample audit row:

```
(1, 'deny', 'dlp', "argument arguments.content contains a value matching
 secret pattern 'aws_access_key_id'; the value is deliberately not recorded")
```

---

## Findings

### 1. Checking URLs in every argument denies ordinary file writes — FIXED in S3b

Case 25 in `evidence/S3a-transcript.txt`:

```
[DENIED ] write a README containing an ordinary doc link
  Reason: URL https://docs.python.org in arguments.content: host is not in allowed_domains
  Rule: egress_domain
```

Writing a file whose *content* mentions a URL is not egress — nothing is
fetched — but the check as specified applies to every string in every argument,
so it fires. In practice this denies README edits, code with a package-registry
URL, import comments, and most lockfiles. That is not a corner case; for a
coding agent it is the common case.

This matters beyond annoyance. D4 makes the approval budget a security property,
and the same logic applies here: a control that blocks routine work gets
widened until it is decorative. The likely response to this behaviour is to
stuff `allowed_domains` with everything, which destroys the actual egress
control.

Implemented as specified, and demonstrated rather than hidden — the failing case
is in the test suite on purpose. **Recommended for S3b:** apply the URL check
only to arguments of tools that can perform a network request, declared per-tool
in policy (`"egress": true`), and keep the DLP scan on all arguments where it
belongs. That is a policy-schema change, so it is out of S3a scope.

**Resolved in S3b** exactly as recommended: `"egress": true` is now per-tool and
the check is skipped without it, with a load-time refusal for fetch-named tools
that omit the flag. DLP still scans every argument of every tool. The drive.py
case above is now a must-ALLOW regression test. See S3b-REPORT.md fix 1.

### 2. `pk_live_` is a publishable key

Stripe publishable keys are designed to ship in client-side code. Flagging them
will produce false-positive denials on legitimate frontend work. Included
because S3a asked for it; flagging it as the second-most-likely complaint.

### 3. An audit row was missing from the shared database — RESOLVED, operator error, not a defect

`evidence/S3a-audit-anomaly.txt`. The verifier reports:

```
FAIL: audit chain broken at row id 6
  id sequence gap: expected id 5, found 6 (1 row(s) deleted or reordered)
```

What is established:

- The database file at the default path was **created at 23:56:30 on Aug 14**,
  after the S2 evidence run at 23:43. The S2 evidence head hash
  `6a3f5fda…` is not present in it. The database S2 verified is gone, replaced
  by a new one whose ids restart at 1.
- Row 5 of that new batch is absent. The S3a rows (12–36) are internally
  linked and chain correctly onto row 11.
- **`audit.py` does not skip ids.** 660 rows across 60 sequential
  open/record/close sessions: contiguous. 280 rows from 8 concurrent processes
  on one database: contiguous, verifier exit 0. 125 rows across 5 full
  `drive.py` runs through the real proxy: contiguous. A row that fails to
  commit does not consume an id, because the next id is recomputed from
  `MAX(id)` under the write lock.

What is not established: what removed the file, and what removed row 5. I ran no
command that deletes rows, and I am not going to invent a culprit for a security
log. The stderr of the run that produced the batch was discarded to `/dev/null`,
which is where an `audit_write_failed` line would have gone — that was my
mistake and it is the reason this is unresolved.

**Resolved 2026-08-15, confirmed by the operator:** the deletion was a manual
gap-detection test run against the default-path database instead of a copy —
the manual verification behind commit `2ed1d35` ("tamper, gap,
truncation-vs-anchor, standalone all verified manually"). Not a defect, not a
compromise. The database was reset the same day; the broken file is retained
as `audit.db.pre-reset-20260815-073954` and still fails verification, which is
the correct permanent record of it.

The finding stands as an operating lesson rather than a bug, and is now written
into S2-REPORT.md as a rule: **destructive verification uses a copy; the live
audit database is never the subject of an experiment.** The corollaries are
worth keeping in view — a deliberately broken log is indistinguishable from an
attacked one, and a rebuilt log restarts its ids at 1, so it is
indistinguishable from a replaced one unless the head hash was anchored first.
The investigation this triggered (file birth times, `sqlite_sequence`, 1,065
rows written across sequential, concurrent and proxy-driven runs to rule out an
id-skipping defect) is what a hand-tamper against a live log costs the next
person to read it.

Two things follow. First, this is the S2 report's known gap #1/#2 arriving in
real life within a day: nothing anchored the head hash, so a change to the log
cannot be distinguished from a legitimate rebuild. Second, **the chain did its
job** — an undetectable deletion is what the control exists to prevent, and the
deletion was detected. The shared database was reset and a fresh one started;
its first real entries came from a live Claude Code session on 2026-08-15
(head `648244...922897`, recorded externally), which simultaneously closed C3
to VERIFIED and gave this database its first anchor.

### 4. Concurrent proxies can fail to start on a shared audit database — FIXED in S3b

Observed during the concurrency test: 1 of 8 processes raised
`database is locked` at `PRAGMA journal_mode=WAL` in `AuditStore.open()` and
refused to start. Fail-closed, so nothing was silently unlogged — but with one
Aegis proxy per MCP server, all sharing one database, a proxy can fail to boot.
The fix is to read `PRAGMA journal_mode` first and only set it when it differs.
**Not applied**: it is a change to `audit.py`, which S3a was told to leave
unchanged. Filed for whoever owns S3b.

**Applied in S3b**, plus a bounded open retry. Re-verified at 16 concurrent
proxies on one database: zero boot failures, contiguous ids, chain intact. See
S3b-REPORT.md fix 2.

---

## Control status

Using the tier definitions from S1-REPORT.md and S2-REPORT.md:

| ID | Control | Tier | Basis |
|---|---|---|---|
| C4 | TLS-terminating egress proxy, domain allowlist | **UNVERIFIED** | not built; S3a is not this control |
| C4a | MCP-layer destination allowlist + SSRF rejection | **VERIFIED (harness, macOS)** | 32 host cases + 10 proxy-driven cases, raw output captured |
| C5 | DLP scan of outbound request bodies | **UNVERIFIED** | no request bodies exist at this layer |
| C5a | Secret scan of tool arguments, disclosure-safe | **VERIFIED (harness, macOS)** | 28 pattern cases + byte-level disclosure check |
| C3 | Hash-chained audit | **VERIFIED** (promoted 2026-08-15) | live Claude Code session logged and chain-verified post-reset; see S2-REPORT.md §Status honesty |

**VERIFIED (harness, macOS)** means: observed on real macOS hardware against the
real proxy and the real store, with raw output captured — decisions driven by
`tests/`, not by a live model session. Neither S3a control has been seen
against live Claude Code, so neither reaches S1's unqualified VERIFIED tier.

I have introduced the `C4a`/`C5a` labels rather than promoting C4/C5, because
marking C4 as verified on this evidence would be exactly the overclaim §8
forbids. THREAT-MODEL.md §5 has been updated to carry both rows.

**To reach VERIFIED unqualified for C4a/C5a specifically:** one live Claude
Code session where the model is asked to POST workspace contents to an
unlisted host, and separately to write a file containing a live-looking key,
with the client's own session log captured. C3's equivalent gate (a live
session attempting a denied read) was met on 2026-08-15 — see S2-REPORT.md.
C4a and C5a have not yet had their own live-session gate; the harness evidence
above stands until they do.

---

## Known gaps (do not claim these are handled)

1. **Everything in §What this is not.** Domain fronting, redirects, DNS
   rebinding, server-derived URLs, and Bash are all outside this control.
2. **URLs in file content are treated as egress** (finding 1).
3. **No port checks.** An allowlisted host is allowed on any port, including 22.
4. **Dict keys are not scanned**, only values. A URL used as a JSON key is invisible.
5. **Opaque schemes other than `data:` are not detected** — `javascript:`,
   `blob:`, `view-source:`. Deliberate: they have no fetch semantics at this
   layer, and matching them would deny any content containing
   `href="javascript:void(0)"`. Documented in `egress.py` so it reads as a
   decision, not an oversight.
6. **DLP is prefix-based and will miss** generic high-entropy secrets, internal
   token formats, anything base64-wrapped, split across arguments, or
   compressed. It raises the cost of casual exfiltration; it does not prevent
   deliberate exfiltration by an agent that encodes first.
7. **A secret used as a filename still reaches the audit db** via the `paths`
   column, which S2 records before DLP runs. Narrow, but real.
8. **`fnmatch` globbing in `deny_paths` is still loose** (S1 gap #5, unchanged).
9. **No allowlist for redirect chains, and no response scanning.** Data
   returned *from* an allowed host is not inspected at all.
10. **Still reviewed by nobody but its author.** THREAT-MODEL.md §10 is empty.

---

## Reproduce

```bash
python3 tests/s3a.py
```

```bash
cp policy.example.json ~/Library/Application\ Support/Aegis/policy.json && chmod 600 ~/Library/Application\ Support/Aegis/policy.json && python3 tests/drive.py
```