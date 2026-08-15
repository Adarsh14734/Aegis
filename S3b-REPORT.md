# Aegis S3b — three scoped fixes from S3a findings

**Sprint:** S3b
**Date:** 2026-08-15
**Scope:** repairs only. No new controls, no TLS interception, no approvals, no UI.
**Status:** all three fixes **VERIFIED (harness, macOS)**. No control changes tier.

---

## What changed

| File | Change |
|---|---|
| `aegis/policy.py` | `"egress": true` per tool; refuses to load a fetch-named tool that omits it |
| `aegis/audit.py` | WAL pragma read-before-write, bounded open retry, `write_head_anchor()` |
| `aegis/proxy.py` | writes the anchor on clean shutdown |
| `aegis/verify.py` | reads the anchor automatically, reports which source it used |
| `policy.example.json` | `fetch` now declares `"egress": true` |
| `tests/drive.py` | README case flipped to must-ALLOW; +2 S3b cases; policy precondition check |
| `tests/s3b.py` | new: 60 cases across the three fixes |

**Controls are unchanged.** C4a and C5a keep the scope and the tier they had in
S3a-REPORT.md. Fix 1 narrows where C4a applies, which makes it *less* far-reaching,
not more; fixes 2 and 3 are robustness and ergonomics on C3. Nothing here earns
a promotion and nothing here is a new claim.

---

## Fix 1 — egress applies only to tools that fetch

`"egress": true` in a `tool_rules` entry turns on URL extraction and the domain
allowlist for that tool. Without it the egress step is skipped entirely.

**Absence means false.** Non-fetching tools are the overwhelming majority, and
S3a's universal check is what denied `write_file` on a README containing
`https://docs.python.org` — a URL in a payload is not a destination, and
treating it as one is the failure D4 warns about: a control that blocks routine
work gets widened until it is decorative.

That default is dangerous in exactly one direction: a tool that *does* fetch and
silently loses its flag loses its destination check. So a policy is **refused at
load** if any tool name contains `fetch`, `http`, `request`, `curl`, `browse`,
`download`, `web`, `url` or `api` (case-insensitive) and does not state
`"egress"` either way:

```
tool_rules entries 'web_search' have names suggesting they make network
requests but do not declare "egress". Add "egress": true to apply the
destination allowlist, or "egress": false to state explicitly that the tool
does not fetch. Refusing to start rather than guess.
```

This is a spelling check on names, not a capability check — **Aegis cannot know
what a tool does**. It catches the realistic accident: a renamed tool, a
newly added one, a hand-edited policy. A network tool named `summarize_page`
still slips through with no egress check and no warning. That is the same class
of gap as S3a's "server-derived requests are invisible", and it is not closed.

**DLP is unchanged and still scans every argument of every tool.** A secret in a
write payload is a disclosure regardless of destination — the file it lands in
is read by something eventually, and `write_file` to a workspace is how a key
gets staged for a later exfiltration that Aegis never sees. Verified explicitly:
`tests/s3b.py` asserts DLP still fires on the non-egress `write_file` path and
on the egress `fetch` path, and `tests/drive.py` carries a live case for each.

---

## Fix 2 — WAL pragma race on concurrent boot

S3a finding 4: 1 of 8 concurrently booting proxies died at
`PRAGMA journal_mode=WAL` with `database is locked`. SQLite takes a brief
exclusive lock for that pragma and returns SQLITE_BUSY immediately rather than
honouring `busy_timeout`, so `timeout=10.0` on the connection did not help.

Two changes in `AuditStore.open()`:

1. **Read `PRAGMA journal_mode` before setting it.** The read takes no write
   lock, and on an existing WAL database the write is a no-op. This removes the
   pragma from the steady-state path entirely — it now runs once, on creation.
2. **Bounded retry with backoff** around the whole open, 8 attempts from 50ms
   doubling to a 1s cap, for `locked`/`busy` only. Every other error still
   fails immediately.

The retry is **bounded on purpose**. Waiting indefinitely for the audit log is
fail-open wearing a hat; after the attempts are exhausted the proxy still
refuses to start. The connection is closed on the failure path so a retry never
inherits a half-configured handle.

**Verified with 16 concurrent proxies against one database** (`tests/s3b.py`
§FIX 2): 16 × 12 calls in 0.4s, every proxy exited 0, zero boot failures, no
`database is locked` anywhere in stderr, all 192 rows written, id sequence
contiguous, chain verifies, database still in WAL.

The row_hash formula, the schema and row semantics are untouched. Databases
written by the S2 and S3a code verify identically under the S3b verifier —
checked against four pre-S3b databases (25, 125, 25 rows, and the known-broken
archived one, which still fails at row 6 as it should).

---

## Fix 3 — head anchor on clean shutdown

On `stopped`, the proxy writes `aegis-head.txt` beside the database, mode 0600,
via `os.replace` so a reader never sees a half-written file:

```
# Aegis audit head anchor. Written on clean shutdown.
# NOT tamper-proof: an attacker who can rewrite the database can
# rewrite this file too. Keep a copy somewhere Aegis cannot write.
db=audit.db
head_id=27
head_hash=2ed2a2ad2b98c059570b2661624f7aca60b88d22fae28c6a7210fda28443be88
written_at=1786779745.808
```

`verify.py` uses it automatically when `--expect-head` is absent and names the
source in its output:

```
anchor: /…/aegis-head.txt (written next to the db; not tamper-proof)
anchor verified at row 27
```

`--no-anchor` ignores it. An explicit `--expect-head` always wins.

### This does not solve truncation detection

**A local anchor file is defeated by an attacker who can write both files.** They
sit in the same directory, owned by the same user, and nothing signs the anchor.
Truncating the log and rewriting the anchor is two edits instead of one. That is
the entire security value: it raises effort, and it catches the *accidental*
cases — a half-copied database, a restored backup, a rolled-back filesystem,
something truncating the log without knowing the anchor exists.

It does not make the log tamper-proof, it does not detect a competent local
attacker, and it must not be described as closing S2 gap #2. Real truncation
detection needs the head hash somewhere Aegis cannot write. `verify.py` says so
in its own output on every successful run, so the limitation travels with the
tool rather than living only here.

### Two design points that came out of testing

**The anchor is checked as a prefix, not as equality.** A stale anchor is normal:
another proxy may still be running, or a proxy may be killed before it updates
the file. So the check is that the anchored hash is still present *at its
recorded id* — the anchored prefix must be intact, and rows may only have been
appended. Demanding equality would fire on ordinary operation, and an alarm that
fires on ordinary operation gets muted. `--expect-head` keeps S2's strict
equality, because it asserts what the head is *now*; the two anchors mean
different things and are checked differently on purpose.

**The anchor records which database it describes.** The default directory holds
more than one — `audit.db` and the archived `audit.db.pre-reset-20260815-073954`.
An anchor whose `db=` does not match the file being verified is ignored, with
`anchor: none` reported. Without this guard, S2's `tamper.py` would have started
failing: it copies databases into a directory that now also contains an anchor,
and cases C and D depend on there being no anchor in play.

**A corrupted anchor is an error, not an absence.** A missing file is normal and
ignored. A file that exists but cannot be parsed exits 1 — present-but-broken is
suspicious, and silently ignoring it would be the fail-open reading.

The anchor's head is read under `BEGIN IMMEDIATE` so a concurrent proxy cannot
commit a row between the read and the write.

---

## Verification

| Suite | Result |
|---|---|
| `tests/s3b.py` | **60/60** — `evidence/S3b-suite.txt` |
| `tests/drive.py` | **6 allowed, 21 denied**, as specified — `evidence/S3b-transcript.txt` |
| `tests/s3a.py` | 99/99, unchanged |
| `tests/tamper.py` | 10/10, unchanged |
| pre-S3b databases | verify identically under the S3b verifier |

`tests/s3b.py` covers: 10 evaluation cases for the egress flag, 11 refused
policies, 8 accepted declarations, 15 ordinary tool names needing no flag, 4
non-boolean rejections, 8 concurrency assertions, and 20 anchor assertions
including truncation, wholesale rewrite, growth past a stale anchor, a corrupt
anchor, and an anchor naming a different database.

One case in that suite is a **limitation, not a pass**: the same truncation that
the anchor catches is invisible with `--no-anchor`, and the suite asserts exit 0
there. Both lines are in the raw output so the boundary is visible.

**Tier: VERIFIED (harness, macOS)** for all three fixes — observed on real macOS
hardware against the real proxy, store and verifier, raw output captured,
decisions driven by `tests/` rather than a live model session. Per S1's
definition none of this reaches unqualified VERIFIED, and no control's tier
changes as a result of S3b.

Incidentally, the live database at the default path now contains two real
`read_text_file` denials on `.env` from a Claude Code session on 2026-08-15 —
the real filesystem server's tool name, which the mock never emits. That is C1
working in production, but it is not the S2/S3a live gate: no client session log
was captured, so it stays anecdote rather than evidence.

---

## Known gaps (unchanged or newly introduced)

1. **The egress flag is a name heuristic away from silence.** A fetching tool
   whose name matches none of the nine hints gets no egress check and no
   warning. Reconciling against a live `tools/list` — S1 gap #9 — would be the
   real fix.
2. **The anchor is local and unsigned** (above). S2 gap #2 is narrowed, not closed.
3. **The anchor is only written on clean shutdown.** A killed proxy leaves it
   stale. Harmless by design, since staleness reads as growth, but it means the
   anchor lags the log by however much a crashed session wrote.
4. **Retry exhaustion is still a boot failure.** Under heavy enough contention a
   proxy refuses to start. Correct, but it is a denial of service on the agent,
   not on Aegis.
5. Everything in S3a-REPORT.md §What this is not still holds: no TLS
   interception, no redirect following, no DNS rebinding defence, no response
   scanning, Bash entirely outside the boundary.
6. **Still reviewed by nobody but its author.** THREAT-MODEL.md §10 is empty.

---

## Reproduce

```bash
python3 tests/s3b.py
```

```bash
cp policy.example.json ~/Library/Application\ Support/Aegis/policy.json && chmod 600 ~/Library/Application\ Support/Aegis/policy.json && python3 tests/drive.py
```
