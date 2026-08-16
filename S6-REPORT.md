# Aegis S6 — desktop viewer

**Sprint:** S6
**Date:** 2026-08-16 (revised 2026-08-17)
**Scope:** the UI only. No new controls.
**Status:** frontend **VERIFIED (harness, macOS)**. The Rust backend and the
approval bridge are **UNVERIFIED — they have never been compiled or run**,
because there is no Rust toolchain on this machine.

---

## What was built

`ui/`, a Tauri v2 app: React + TypeScript frontend, Rust backend, fixed
1000×700, light mode only.

| File | Role |
|---|---|
| `ui/src/lib/translate.ts` | Audit rows → ordinary language. The heart of the brief |
| `ui/src/screens/*.tsx` | Status, Activity, Approvals, Data flow |
| `ui/src/styles.css` | Tokens transcribed from `design/Aegis.dc.html` and `design/_ds/` |
| `ui/src/api.ts` | The only path out of the UI: two Tauri commands |
| `ui/src-tauri/src/audit.rs` | Read-only SQLite; chain check delegated to `verify.py` |
| `ui/src/screens/DataFlow.tsx` | States what the audit log cannot answer, rather than tabulating it |
| `ui/src-tauri/src/policy.rs` | Read-only `policy.json` |
| `ui/src-tauri/src/main.rs` | `snapshot()` and `resolve_approval()`, nothing else |
| `ui/bridge/aegis-approval-bridge.py` | The pty supervisor that lets a window answer a tty prompt |
| `ui/src/devFixture.ts` | Browser layout harness, banner-marked, unreachable from the app |

No file in `aegis/` was touched — confirmed by `git status aegis/` being empty.

---

## It is a viewer

`audit.db` is opened with `SQLITE_OPEN_READ_ONLY`, so a write fails at the
SQLite layer rather than relying on this code never attempting one. Grepping
the Rust for write verbs returns only the read-only open. `audit.py` remains
the single writer.

Chain integrity is **not** recomputed in the UI. It shells out to
`aegis/verify.py` and reports the exit code. A third implementation of the hash
rule would be a third thing to keep in agreement, and `verify.py` is already
the authority with its own deliberate second copy (S2).

When the chain does not verify, a deep-red banner sits above everything on
every screen, carrying the verifier's own message. Rows are still shown —
hiding them would remove the operator's only view of what happened — but
never as if trustworthy: *"Everything below is still shown, but it can no
longer be trusted to be complete or unedited."* When the verifier cannot be run
at all, that is reported as "could not be checked", not as intact.

No `localStorage`, `sessionStorage` or `indexedDB` anywhere. Screen selection
lives in React state and resets on launch.

---

## Plain English

The brief: `deny_paths` becomes "opening your saved passwords file". The
translation layer covers every rule_id `aegis/*.py` can write, and a test
asserts that **no rule_id and no snake_case token ever reaches the screen** for
any of them:

| Audit row | What the user reads |
|---|---|
| `deny` / `deny_paths` / `.env` | Aegis stopped an agent from opening a file that holds your passwords and keys. |
| `deny` / `deny_paths` / `.aws/credentials` | …from opening your saved cloud credentials. |
| `deny` / `dlp` | …from putting a password or key into a file it was writing. |
| `deny` / `egress_domain` | …from sending something to a website that is not on your list. |
| `deny` / `killswitch` | …from doing anything at all, because you pressed stop. |
| `deny` / `bulk_operation` | …from touching 14 files at once. |
| `allow` + `substituted credential handle(s)` | An agent used one of your saved logins without ever seeing it. |
| `redact` / `credential_redacted` | Aegis removed one of your saved logins from a reply before an agent could see it. |
| `allow` + `copied to trash` | An agent changed 3 files in ~/Projects/Atlas and Aegis kept a copy of each. |

### "An agent", not "Claude", and not `read_file`

Rendering the Approvals card produced *"read_file wants to read 4 files"* — the
same snake_case jargon the rule_id table exists to remove. The design says
"Claude wants to…", but **the audit database never records which agent called
a tool**: one proxy sits in front of one MCP server and no client identity
crosses the wire. Naming a product would be inventing a fact the log does not
contain.

So the sentences say "an agent", and the verb still comes from the tool, so
what happened is not lost. One of three deliberate departures from the
reference — see the known gaps.

---

## Screens

**Status** — one serif sentence derived only from the counters, then three
counters with "waiting" visually dominant (58px, cyan `--color-accent-700`)
against 24px for the other two; "stopped" turns `#8c1c2b` only when non-zero.
Then four rows from `policy.json`.

*Agents connected* is the weak one. The policy has no agent list, so the row
reads "6 tools allowed by your rules". It is honest and it is not what the
design asked for; see finding 2.

**Activity** — one row per audit row, newest first. Blocked rows in `#8c1c2b`
with a Blocked tag; waiting rows in cyan; everything else plain. The design's
footnote "Older days are kept for two weeks" was **removed**: nothing prunes
the audit log, so that line would have been a promise the code does not make.
It now reads "Aegis keeps every entry."

**Approvals** — a single card, never a queue, from the newest
`approval_prompt` row with no resolving row after it. That query is exact:
`proxy.py` writes the resolution immediately, so an unresolved prompt means a
proxy is blocked on a human right now. Buttons name the action. When no bridge
is running they are disabled with an explanation rather than silently inert.

**Data flow** — a statement, not a table. The audit log cannot say where an
allowed request went or how big it was, so the screen says that in one sentence
and gives the one number it does know: how many requests were allowed out.
See finding 1.

---

## Finding 1 — the audit log cannot answer "where did it go"

The Data flow screen asks four questions. The audit database can answer one.

Checked against the real database:

```
allowed egress:  id=14 fetch allow  reason='matched allow rule'
denied  egress:  id=16 fetch deny   reason='URL https://evil.xyz in arguments.url: …'
```

**The destination is recorded only when the request was blocked.** For a request
that actually left, the reason is `matched allow rule` and the host is nowhere.
There is no size column anywhere in the schema either.

The first revision rendered the table anyway, filling it with
`A request from fetch / Not recorded / Not recorded`, repeated. That was worse
than nothing: a table implies its columns are answerable, and a screenful of
them implies Aegis is watching traffic it cannot see. **The screen now states
the limitation once and stops** — a sentence, one honest count (how many
requests were allowed out, which the log does know), and two rows marked *Not
recorded*. It stays in the nav.

The row-builder that fed the table has been deleted rather than left dormant,
so nobody wires it back up before the data exists. It returns with the schema
change: `audit.py` would need to record destination host and byte count on
allowed egress, which touches the hash-chained row format and so needs care.
Filed for S8.

## Finding 2 — "Agents connected" has no source

The design's Status table lists "Claude, Cursor". Nothing in `policy.json` or
`audit.db` records which agent is connected. The row shows a tool count
instead. Same root cause as finding 1: identity is not captured anywhere.

## Finding 3 — the approval bridge is real new attack surface

Answering a `/dev/tty` prompt from a window requires something to type on that
terminal. `bridge/aegis-approval-bridge.py` allocates a pty, starts the proxy
inside it with the real JSON-RPC pipes still on stdin/stdout, and exposes a
0600 unix socket that accepts exactly two answers.

`approval.py`, `proxy.py` and `audit.py` are unmodified and unaware. The
decision, the timeout, the audit rows and the fail-closed behaviour are all
still theirs.

What it costs, stated plainly:

1. **Anything that can write to the socket can approve.** The socket is 0600
   and owned by the user — the same boundary the agent runs inside. An agent
   that can run local commands as you can approve its own request.
   THREAT-MODEL.md §7.1 already concedes malware on the host; this lowers the
   bar from "malware" to "any code running as you".
2. **It weakens the tty guarantee.** Part of C7's value was that the answer
   arrived on a channel the agent does not control. With the bridge running
   that is no longer strictly true.
3. **It cannot authenticate the asker.** It checks that a prompt is actually
   waiting, so a stale click cannot answer a later request, but it cannot tell
   the Aegis window from anything else on the machine.

Mitigations: socket 0600 in the data directory; only the bytes `y` and `n` can
ever reach the terminal, and nothing from the request is echoed there; it
refuses when no prompt is waiting; it exits with the proxy. It is **off unless
started**, and without it the Approvals screen degrades honestly.

---

## Verification

| What | Result |
|---|---|
| `npm run build` (tsc --noEmit + vite) | passes, 0 errors |
| `npm test` — plain-English layer | **10/10** |
| Four screens rendered at 1000×700 | checked against `design/Aegis.dc.html` |
| Chain-failure state | rendered against the real `evidence/S2-tampered-audit.db` output |
| Verifier path resolution | checked at all four binary locations |
| SQL in `audit.rs` | each query run against the real `audit.db` |
| `localStorage` / `sessionStorage` | none |
| Write path to `audit.db` | none; read-only flag only |
| `git status aegis/` | empty |
| **Rust backend compiled** | **NEVER — no toolchain** |
| **Approval bridge executed** | **NEVER — see below** |

**Tier: VERIFIED (harness, macOS)** for the frontend only, per S1's definition:
real hardware, real build, real rendering, decisions driven by `tests/` rather
than a live session. **UNVERIFIED** for everything behind the Tauri boundary.

### What "never compiled" means here

`cargo` and `rustc` are absent (`cargo --version` → not found). Tauri v2 cannot
build without them. So:

- `main.rs`, `audit.rs`, `policy.rs` have **never been compiled**. They may not
  build. Type errors, a wrong `rusqlite` API, a bad Tauri v2 signature — none
  of it would show up in anything run so far.
- The four screens were verified against a **browser harness** with sample
  rows, not against the Rust `snapshot()` command.
- What *is* independently verified is that the SQL those commands run returns
  what the UI expects: every query in `audit.rs` was executed against the real
  `audit.db` and returns the shapes the TypeScript types declare.

To close it: install Rust, then `npm run tauri dev`. Expect to fix compile
errors — treat the first successful launch as the real verification, not this
report.

### The approval bridge is unverified for a specific reason

The bridge needs a child process with a controlling pty while its stdin and
stdout stay on pipes. **Two independent attempts at that mechanism hung with no
output in this environment** — `setsid` + `TIOCSCTTY` in `preexec_fn` during
S5, and `pty.fork()` again here. The same limitation is why S5's C7 end-to-end
check is a manual procedure.

The bridge is therefore written to the design that should work and has **not
been run once**. It is the least trustworthy file in this sprint. Do not enable
it without testing it, and do not assume the buttons work until you have seen
them work.

---

## Revision, 2026-08-17 — three fixes

**1. The verifier was never found.** `verify_chain` guessed a fixed depth above
the executable (`ancestors().nth(4)`), which resolved to `ui/aegis/verify.py` —
a path that does not exist. Every launch would have shown "could not check its
own record". A fixed depth was always going to be wrong for at least one of
`cargo run`, `tauri dev` and a bundled `.app`, since each nests the binary
differently.

Replaced with a search: `AEGIS_HOME` when it actually contains the verifier,
then walk up from the executable, then from the working directory. A stale
`AEGIS_HOME` is ignored rather than silently used, because "the verifier is
missing" and "the verifier is somewhere else" should not look the same on
screen. Checked against all four binary locations — the old code failed all
four, the new code resolves all four to `/Users/adarsh/code/aegis/aegis/verify.py`.

The banner still fires. Replicating `verify_chain` end to end against
`evidence/S2-tampered-audit.db` gives exit 1 and *"The record of what happened
has been altered — Audit chain broken at row id 3"*; against the live database,
exit 0 and no banner; against a missing file, *"Aegis could not check its own
record."*

**Caught while verifying it:** the banner was printing the verifier's whole
message, which meant 64-character hashes and `rule_id='deny_paths'` on screen —
exactly the jargon this UI exists to remove. It now shows the verifier's first
line only, uppercased, with the debugging tail dropped; two tests cover it,
including the case where something upstream flattens the newlines.

**2. Duplicate window controls.** Tauri draws native traffic lights and the
React sidebar drew a decorative set underneath them. The decorative set is
deleted; the space it occupied is kept as a spacer, because `titleBarStyle:
Overlay` floats the real buttons over that corner.

**3. Data flow overstated what Aegis knows.** See finding 1 — the table is
replaced by a single honest statement.

---

## Known gaps

1. **The Rust half has never been compiled or run** (§Verification).
2. **The bridge has never been executed** and may not work at all.
3. **Data flow cannot say where anything went** (finding 1). The screen now
   says so plainly instead of tabulating nothing, but the capability is still
   missing and the design still implies knowledge Aegis does not have.
4. **No agent identity anywhere** (finding 2).
5. **Three departures from the reference**, all deliberate: "an agent" instead
   of a product name, the removal of the two-week retention claim, and Data
   flow as a statement rather than a table.
6. **Polling at 2s**, not a file watcher: simple, but a prompt can sit up to two
   seconds before the window shows it, against a 120s approval timeout.
7. **No icon.** `ui/src-tauri/icons/` is empty, so packaging will fail until one
   is added.
8. **The window is fixed 1000×700 and light-only**, as specified. There is no
   dark mode and no accessibility pass — no keyboard navigation testing, no
   contrast audit, no VoiceOver check.
9. **Still reviewed by nobody but its author.** THREAT-MODEL.md §10 is empty.

---

## Reproduce

```bash
cd ui && npm install && npm run build && npm test
```

```bash
cd ui && npx vite preview --port 4173
```
