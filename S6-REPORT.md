# Aegis S6 — desktop viewer

**Sprint:** S6
**Date:** 2026-08-16 (revised 2026-08-17)
**Scope:** the UI only. No new controls.
**Status:** frontend **VERIFIED (harness, macOS)**. The Rust backend is
**UNVERIFIED — it has never been compiled**, because there is no Rust toolchain
on this machine. The approval bridge was **removed**, not shipped: see
§Removed — the approval bridge.

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
| `ui/src-tauri/src/main.rs` | One command, `snapshot()`. Nothing that writes |
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
proxy is blocked on a human right now.

**The buttons are permanently disabled and say why.** This window cannot answer
an approval; the request is answered at the terminal the proxy runs in. They
are kept visible rather than hidden because the labels are what tell you what
the answer would do — a disabled control that explains itself is honest, an
enabled one that silently does nothing is not.

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

## Finding 3 — the approval bridge was removed

It is described in §Removed — the approval bridge. In short: it was never once
executed, it rested on a mechanism that has never worked in this environment,
and its own header claimed a safety check the code did not contain. Deleting it
was cheaper than any of the alternatives.

## Removed — the approval bridge

`ui/bridge/aegis-approval-bridge.py` and the Tauri `resolve_approval` command
that called it are **deleted**. They are not disabled, not feature-flagged,
not left dormant. Three reasons, and any one of them would have been enough.

**1. It had never been executed. Not once.** Asked directly whether it was
verified, the answer was that until that moment it had never even been parsed —
`python3 -m py_compile` was run on it for the first time while answering the
question. No test in the repo referenced it. Nothing had ever allocated its
pty, opened its socket, or typed a byte on a terminal through it. The full path
— button → `resolve_approval` → unix socket → bridge → pty → `approval.py` →
audit rows — had never carried a single byte, and the Rust half could not even
be compiled here to try.

**2. It rested on a mechanism that has failed in this environment every time.**
Giving a child process a controlling pty while its stdin and stdout stay on
pipes has now hung, with no output at all, three times:

| Attempt | Sprint | Result |
|---|---|---|
| `os.setsid()` + `TIOCSCTTY` in `preexec_fn` | S5 | hung, no output |
| `pty.fork()` probe | S6, before writing the bridge | hung, no output |
| the bridge itself | S6 | never run, and built on `pty.fork` |

The third line is the honest one: it was written to a design that should work,
against a primitive that has not worked here yet. That is the same shape as
S5's first controlling-terminal attempt, which was also written before it was
tried — except S5 caught it with a test and this had no test to catch it.

**3. Its header claimed a safety check the code did not implement.** The file
said *"The prompt_id is checked against the pending prompt so a stale click
cannot answer a later request."* The Rust sent a `prompt_id`; the bridge's
`handle()` never read it. `grep prompt_id` over the bridge matched only that
sentence. The single guard was "some prompt is waiting", so a click could have
answered a *different* request than the one on screen — approving something the
operator never saw. That claim had also been copied into this report.

A security component that has never run, cannot be run here, and whose
documentation overstated its own protections is not something to ship behind a
flag. It was cheaper to delete it than to leave it for someone to find and
trust.

### What this costs

Nothing that existed before S6. C7 still works exactly as S5 verified it: the
prompt appears on the proxy's controlling terminal, a human answers there, and
`approval.py` records who resolved it. The Approvals screen shows the waiting
request and points at that terminal.

### What it would take to build it properly

A UI approval path stays **unbuilt**. Two things are needed before one ships:

1. **A pty mechanism that actually works** — demonstrated on the target
   machine, with a test that fails if it regresses. Not written and assumed.
   Everything else depends on this and it has never once succeeded here.
2. **A real `prompt_id` check.** The bridge must confirm the answer it is
   about to type belongs to the prompt the window displayed. That means the
   bridge reading the audit database to learn which prompt is live, which turns
   it from "writes two bytes to a terminal" into "reads the audit log as well"
   — a wider component than the one that was deleted, and a design decision
   rather than a patch.

The attack surface analysis that was here still applies to anything built to
this shape, and should be re-read first: any process able to write the socket
can approve, which on a single-user machine means any code running as you —
lowering THREAT-MODEL.md §7.1's bar from "malware on the host" to "any code
running as you". C7's value came partly from the answer arriving on a channel
the agent does not control, and a socket gives that channel away.

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
| Approval bridge | **deleted**, never having been executed |

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

### The approval bridge is gone

See §Removed — the approval bridge. It was never run, and it is no longer in
the tree to be run. The same pty limitation is why S5's C7 end-to-end check is
still a manual procedure.

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
2. **There is no UI approval path.** The bridge was removed; approvals are
   answered at the proxy's terminal. Rebuilding it needs a working pty
   mechanism and a real prompt_id check (§Removed).
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
