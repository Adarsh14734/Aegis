# Aegis S2 — tamper-evident audit store + offline verifier

**Sprint:** S2
**Date:** 2026-08-14
**Control:** C3 — hash-chained append-only audit log + verifier CLI
**Gate:** raw output of the chain detecting a tampered row, produced by a verifier that cannot see the control plane.
**Status:** **VERIFIED (harness, macOS)** — the live-client tier is not yet met. See §Status honesty.

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
But S1 set a **higher bar** for the word VERIFIED unqualified: observed against
live Claude Code, with the client's own session log captured.

C3 has not met that bar. Everything here was observed on real macOS hardware
against the real proxy, the real store and the real default path — but the
decisions came from `tests/drive.py` and `tests/tamper.py`, not from a live
model session. C3 is therefore recorded as **VERIFIED (harness, macOS)**.

**To close it to full VERIFIED**, one thing is missing: run a live Claude Code
session through the proxy (the S1 `.mcp.json` wiring, unchanged), then verify
the chain and confirm the model's attempts appear as rows with the right
`rule_id`. That is a ten-minute interactive session, not a build task.

---

## Known gaps (do not claim these are handled)

1. **An attacker with write access can rewrite the whole chain.** Demonstrated
   in case D. THREAT-MODEL.md §7.2 already says root defeats Aegis; this is
   the concrete demonstration. Only an external anchor detects it.
2. **Truncating the newest rows is invisible** without `--expect-head`
   (case C). Nothing automatically anchors the head hash yet — no timestamping
   service, no append to a remote log, no notarization. The operator has to do
   it by hand, which means in practice it will not happen.
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
python3 aegis/verify.py          # verify the real store
python3 aegis/verify.py --expect-head <hash-you-wrote-down-earlier>
```
