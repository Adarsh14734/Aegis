# Aegis S2 — tamper-evident audit store + offline verifier

**Sprint:** S2
**Date:** 2026-08-14
**Control:** C3 — hash-chained append-only audit log + verifier CLI
**Gate:** raw output of the chain detecting a tampered row, produced by a verifier that cannot see the control plane.
**Status:** **VERIFIED** — live-client gate met 2026-08-15. See §Status honesty.

---

## What was built

```
Claude Code <--stdio--> aegis/proxy.py <--stdio--> MCP server
                             |
                        aegis/policy.py      decision
                             |
                        aegis/audit.py       append row, hash-chained    <-- new
                             |
                    ~/Library/Application Support/Aegis/audit.db (WAL, 0600)
                             |
                        aegis/verify.py      recomputes chain, offline   <-- new
```

| File | Role |
|---|---|
| `aegis/audit.py` | Append-only hash-chained SQLite store. Raises on any failure. |
| `aegis/verify.py` | Standalone verifier. Stdlib only, imports nothing from Aegis. |
| `tests/tamper.py` | S2 harness: real decisions, then four attacks on the database |
| `evidence/S2-tamper-transcript.txt` | Raw harness output — the gate |
| `evidence/S2-real-path-verify.txt` | Real default macOS path, real policy, 11 rows verified |
| `evidence/S2-live-claude-code.txt` | **Live Claude Code session, 2026-08-15 — the C3 gate** |

S1 closes gap #2 ("No audit persistence. Decisions go to stderr and vanish").
The stderr `log()` is unchanged and still emits every decision; it is now
explicitly documented as debugging output with no evidentiary weight. Nothing
in `policy.py` was touched — the decision logic is byte-identical to S1, and
`tests/drive.py` still reports 2 allowed / 9 denied.

---

## The chain

```
row_hash = sha256(canonical_json({id, ts, tool, effect, rule_id, reason, paths}) + prev_hash)
canonical_json = json.dumps(obj, sort_keys=True, separators=(',',':'))
genesis prev_hash = "0" * 64
```

Design points worth stating, because each one is a place this could have been
built wrong:

- **The hash covers stored column values, not in-memory objects.** `paths` is
  hashed as the TEXT column exactly as written. The verifier only ever sees
  columns; if the hash covered anything else, it could not reproduce it.
- **`id` is inside the payload.** Without it, rows could be reordered or
  renumbered without breaking anything.
- **Row id is allocated under `BEGIN IMMEDIATE`.** The write lock is taken
  before the head row is read, so two proxies sharing one database cannot
  chain onto the same `prev_hash`. A race would otherwise produce two valid
  branches, which is a fork, not a chain.
- **`synchronous=FULL`.** WAL defaults to `NORMAL`, which can lose the newest
  commits on power loss. For a log whose entire purpose is reconstructing what
  happened, that default is the wrong trade.
- **Append-only is enforced by the code, not by SQLite.** No `UPDATE` or
  `DELETE` statement appears in `audit.py`. Enforcement triggers were
  considered and rejected: anyone who can run `UPDATE` can also run
  `DROP TRIGGER`, so they would add ceremony without adding a guarantee.
  Detection is the guarantee.
- **File created at 0600 by `os.open`, not by SQLite.** Letting SQLite create
  it would take the mode from the umask. The `-wal` and `-shm` sidecars are
  tightened too — committed rows live in `-wal` until checkpoint, and those
  bytes are exactly as sensitive as the database.

---

## Fail-closed behaviour

C3 is not "log if convenient". Every decision is committed **before** the
denial frame is written or the call is forwarded. If the row cannot be
written, the decision is replaced with DENY (`rule_id: audit_fail_closed`) —
including a decision that policy had allowed.

| Failure | Behaviour | Observed |
|---|---|---|
| Audit db unopenable at startup | proxy refuses to start, exit 2, nothing proxied | yes |
| Audit db group/world writable (0666) | proxy refuses to start, exit 2 | yes |
| Write fails mid-session | that call is denied, `audit_failures` incremented | yes (in-process) |

The reasoning is the same as a missing policy file: a proxy that cannot record
its decisions is not a degraded proxy, it is an absent control. An action
nobody can reconstruct afterwards is worse than an action that did not happen.

---

## Verification results

`python3 tests/tamper.py` — full raw output in `evidence/S2-tamper-transcript.txt`.
Six real decisions are driven through the real proxy, then the resulting
database is attacked with a plain `sqlite3` connection: exactly what someone
with write access to the file would do.

| # | Attack | Verifier | Exit |
|---|---|---|---|
| — | untouched chain | `OK: 6 rows verified` | 0 |
| A | `UPDATE audit SET effect='allow'` on the denied `.env` read | `row_hash mismatch at row 3` | 1 |
| B | `DELETE FROM audit WHERE id=4` | `id sequence gap: expected 4, found 5` | 1 |
| C | `DELETE FROM audit WHERE id>=5` (truncate tail) | **not detected** | 0 |
| C′ | same, with `--expect-head <anchor>` | head hash mismatch | 1 |
| D | edit a row and recompute every hash after it | **not detected** | 0 |
| D′ | same, with `--expect-head <anchor>` | head hash mismatch | 1 |

Plus the three fail-closed cases in the table above. 10/10 behaved as
specified.

**Cases C and D are in the harness on purpose.** They are the two attacks a
local hash chain genuinely cannot see on its own, and a harness that only
demonstrated wins would be marketing. Both are caught only when the head hash
was anchored somewhere outside Aegis's reach beforehand — which is why
`verify.py` prints the head hash on every successful run and accepts
`--expect-head`.

**Real default path**, `evidence/S2-real-path-verify.txt`: the unchanged S1
adversarial suite run against the real policy on macOS 26.5.1 / Python 3.14.3
produced 11 chained rows at `~/Library/Application Support/Aegis/audit.db`,
mode 0600, `journal_mode=wal`, verifying clean. The 11 rows match the 11 S1
cases one-for-one, including `rule_id` — the chain records *why*, not just
*that*.

---

## Operating rule: destructive verification uses a copy, never the live log

**Tampering tests are run against a copy. The live audit database is never the
subject of an experiment.** `tests/tamper.py` already works this way — it builds
its own database in a temp directory and attacks `shutil.copy` clones of it —
but the rule exists because manual checks are where it gets broken.

It got broken here. During manual verification of gap detection after S2 was
committed, a row was deleted from the database at the *default path* rather than
from a copy. The next sprint's verifier run reported the chain broken at row 5,
and the resulting investigation — file birth times, `sqlite_sequence`, 1,065
rows written across sequential, concurrent and proxy-driven runs to prove
`audit.py` cannot skip an id — cost far more than the original test. Full
reconstruction in `S3a-REPORT.md` finding 3 and
`evidence/S3a-audit-anomaly.txt`.

Two things this cost, both worth naming:

1. **A deliberately broken log is indistinguishable from an attacked one.**
   That is not a flaw in the chain; it is the chain working. But it means every
   hand-tamper against the live database burns the log's value as evidence from
   that point on. The database had to be reset, which is itself the loss the
   control exists to prevent.
2. **Rebuilding the log resets the id sequence to 1**, so a replaced database
   and an original one look alike unless the head hash was anchored somewhere
   beforehand. This is gap #2 below, arriving in practice within a day of being
   written down.

The rule, concretely:

- experiment on `cp audit.db /tmp/scratch.db`, or on a database created with
  `AEGIS_AUDIT_DB=/tmp/scratch.db`
- if the live database is ever tampered with, reset it rather than leave a
  known-broken chain in place, and archive the old file rather than deleting it
- record the new head hash externally after the first real session, or the
  reset is indistinguishable from an attack the next time someone looks

The default-path database was reset on 2026-08-15. The previous file is kept
alongside it as `audit.db.pre-reset-20260815-073954`; it still fails
verification, which is the correct and permanent record of what happened to it.

---

## The verifier is deliberately independent

S0 open question #4: *"Does the audit verifier run offline, without the
control plane? It must, or a compromised control plane can lie about its own
integrity."* Answered yes, structurally:

- `verify.py` imports only `argparse`, `hashlib`, `json`, `os`, `sqlite3`,
  `sys`, `pathlib`. Nothing from Aegis — not `audit.py`, not `policy.py`, not
  `proxy.py`. Copy the single file to another machine and it works with the
  rest of Aegis absent.
- The hash function is a **second, independent copy** of the rule. If someone
  edits the chain rule in `audit.py` so that forged rows validate, this file
  keeps computing the old rule and the forgery surfaces. The cost is keeping
  two copies in agreement; that cost is being paid on purpose.
- It opens the database **read-only** (`mode=ro`), falling back to a normal
  open only when SQLite refuses a read-only open of a WAL database needing
  recovery.

One bug was found and fixed while building this: the read-only URI was built
by string interpolation, so a database path containing `?` or `#` would be
parsed as URI query/fragment and **silently open a different database** —
reporting `OK: 0 rows` for a file that was never examined. It now uses
`Path.as_uri()`, which percent-encodes, and refuses any database with no
`audit` table rather than reading a missing table as an empty, intact log. A
verifier that blesses the wrong file is worse than one that crashes.

---

## Status honesty

`THREAT-MODEL.md` §5 promotion rule requires a captured raw transcript of the
attack being attempted and blocked. That exists (`evidence/S2-tamper-transcript.txt`).
S1 set a **higher bar** for the word VERIFIED unqualified: observed against
live Claude Code, with the client's own session log captured.

**C3 has now met that bar.** On 2026-08-15, a live Claude Code session (v2.1.232,
macOS) was pointed at the S1 `.mcp.json` wiring, unchanged, and asked to read
`workspace/.env`. The model attempted `mcp__filesystem__read_text_file` on the
real path twice before giving up on its own. Both attempts were recorded and
denied:

```
$ sqlite3 ~/Library/Application\ Support/Aegis/audit.db \
  "SELECT id,tool,effect,rule_id FROM audit ORDER BY id DESC LIMIT 5;"
2|read_text_file|deny|deny_paths
1|read_text_file|deny|deny_paths

$ python3 aegis/verify.py
OK: 2 row(s) verified, chain intact
head: 648244273ded719496398f367efd295fa1fef6c69a442d5feba9d12bfc922897
```

This was the first write to the database after the 2026-08-15 reset described
above, so rows 1–2 are the entire chain at this point — small, but genuinely
live: real client, real model, real denial, real chain. The head hash
`648244...922897` has been recorded externally (outside this repo) as the first
anchor since the reset. Every subsequent `--expect-head` check is measured
against it.

C3 is promoted from VERIFIED (harness, macOS) to **VERIFIED**, on the same
basis S1 used for C1/C2: the client's own record of what it attempted, not the
model's summary, and not harness-only evidence.

---

## Known gaps (do not claim these are handled)

1. **An attacker with write access can rewrite the whole chain.** Demonstrated
   in case D. THREAT-MODEL.md §7.2 already says root defeats Aegis; this is
   the concrete demonstration. Only an external anchor detects it.
2. **Truncating the newest rows is invisible** without `--expect-head`
   (case C). Nothing automatically anchors the head hash yet — no timestamping
   service, no append to a remote log, no notarization. The operator has to do
   it by hand, which means in practice it will not happen.
   *S3b narrows this, and does not close it:* the proxy now writes
   `aegis-head.txt` beside the database on clean shutdown and `verify.py` reads
   it automatically. That anchor is local, unsigned, and writable by anyone who
   can write the database — it makes a silent truncation cost a second edit and
   catches accidental loss. An anchor held off this machine is still the only
   real answer. See S3b-REPORT.md fix 3.
3. **Deleting the entire database is not detected by the verifier**, only by
   noticing the file is gone. An empty chain is a valid chain.
4. **Session boundaries are not in the chain.** Only decisions are recorded, so
   a gap in wall-clock time between rows cannot be attributed to a proxy
   restart versus deletion. Start/stop rows would fix this.
5. **The audit database is readable by the user account the agent runs as.**
   Mode 0600 stops other users, not the agent itself if it can execute code as
   that user. Under S1 there is no sandbox (S1 gap #4), so a bash tool can read
   the log. It cannot rewrite it undetectably, but it can read every path Aegis
   has seen.
6. **No retention, rotation, or size limit.** The database grows without bound.
   Rotation is genuinely hard here: a rotated chain must be linked to its
   predecessor's head hash or rotation becomes a legitimate-looking truncation.
7. **Tool arguments are not recorded**, only extracted paths. A denied
   `exec_shell` records the tool and the rule but not the command string. That
   is a deliberate confidentiality/forensics trade, and it is currently
   undocumented anywhere a user would see it.
8. **Two copies of the hash rule** (`audit.py`, `verify.py`) can drift apart.
   Independence is the point, but nothing tests that they still agree except
   `tests/tamper.py` passing.
9. **Still reviewed by nobody but its author.** THREAT-MODEL.md §10 is empty.

---

## Reproduce

```bash
python3 tests/tamper.py          # self-contained; temp dir; touches nothing of yours
```

```bash
python3 aegis/verify.py          # verify the real store, read-only
```

```bash
python3 aegis/verify.py --expect-head <hash-you-wrote-down-earlier>
```

Poking at the chain by hand — deleting a row, editing a field — is done on a
copy, per the operating rule above:

```bash
cp ~/Library/Application\ Support/Aegis/audit.db /tmp/scratch.db && sqlite3 /tmp/scratch.db 'DELETE FROM audit WHERE id=5' && python3 aegis/verify.py /tmp/scratch.db
```