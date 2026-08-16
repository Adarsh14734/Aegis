# Aegis S5 — human in the loop, and recovery

**Sprint:** S5
**Date:** 2026-08-15
**Controls:** C7 approval loop · C8 bulk threshold · C9 soft delete · C10 kill switch
**Status:** all four **VERIFIED (harness, macOS)**, with one path in C7 —
a human answering on a live proxy's controlling terminal — **UNVERIFIED**.
Suite: **80 passed, 0 failed, 1 NOT RUN**, exit 1.

> **Correction, 2026-08-15.** The first revision of this report claimed
> "76 passed, 0 failed". Run from an interactive terminal the suite actually
> reported **71 passed, 5 failed, 1 NOT RUN**. Two defects, both now fixed:
>
> 1. **`ask_no_tty` never fired.** The absence of a terminal was discovered by
>    the prompt going unanswered, not detected before prompting — so a headless
>    call stalled for the full timeout and was recorded as `approval_timeout`.
>    Wrong on both counts: a per-call stall in headless use, and an audit trail
>    that could not tell "nobody was present" from "a human declined to answer".
> 2. **The suite tested different things depending on how it was launched.** It
>    ran the proxy without a new session, so from a terminal the proxy inherited
>    that terminal and the ASK prompted the person running the tests; from a
>    non-interactive shell there was no terminal at all. My environment had no
>    controlling tty, so the no-tty path passed there and failed for the
>    operator. The reported figure came from the only environment in which it
>    was true.
>
> Post-fix the suite reports 80/0/1 in **both** environments, verified by
> re-running it under `pty.spawn` with a real controlling terminal.
> `edit_file` has also moved from `ask` to `allow`, so the budget numbers below
> have been re-measured.

---

## What was built

| File | Role |
|---|---|
| `aegis/approval.py` | C7. Prompt on `/dev/tty`, timeout to deny, no-tty to deny |
| `aegis/killswitch.py` | C10. Presence-of-a-file stop button, `aegis-stop` / `aegis-resume` |
| `aegis/trash.py` | C9. Stage copies before destructive calls, `aegis-restore` |
| `aegis/policy.py` | Kill switch first, bulk threshold, `destructive`, ASK stops collapsing |
| `aegis/proxy.py` | Resolve ASK, stage trash, both before the audit write and the forward |
| `bin/aegis-stop`, `bin/aegis-resume`, `bin/aegis-restore` | CLI entry points |
| `tests/s5.py` | 77 checks |
| `tests/approval_budget.py` | Measures the D4 rate rather than asserting it |
| `tests/manual/approval-check.md` | The one C7 path that cannot be automated here |
| `evidence/S5-suite.txt` | 80 passed, 0 failed, **1 NOT RUN**, exit 1 (no controlling tty) |
| `evidence/S5-suite-with-tty.txt` | Same suite under a real controlling terminal: 80/0/1 |
| `evidence/S5-approval-budget.txt` | Raw budget measurement |

---

## Evaluation order

```
killswitch → deny_paths → DLP → egress → credentials → tool rule
   → containment → bulk threshold → ASK → allow
```

Two placements carry weight:

**The kill switch is first**, ahead of `deny_paths`. When a human has hit stop,
Aegis should not be evaluating rules at all, and the recorded reason should be
"stopped" rather than whichever rule the call happened to trip. Verified
directly: with the switch engaged, a call that would otherwise be denied by
`deny_paths` is denied with `rule_id: killswitch`.

**The bulk threshold sits above every path that can return ALLOW**, so an allow
rule cannot skip it — the explicit requirement. It sits *below* the deny checks
on purpose: a call policy already refuses should be refused, not put in front of
a human. Escalating a denial into a prompt spends approval budget on calls whose
answer is already known, which is how prompts get clicked through unread (T5).
Verified: `purge` (a deny rule) with 11 paths is denied with
`rule_id: tool_rules.purge`, not escalated; a path outside the workspace with 11
paths denies on containment rather than prompting.

---

## C7 — approval

`ask_behavior` now defaults to `"prompt"`. `"deny"` survives as an explicit
opt-out for headless deployments; `"allow"` is still refused at load, because a
policy that auto-approves its own ASK rules has written an allow rule and got
the label wrong.

The prompt goes to `/dev/tty` — never stdin or stdout. stdout is the JSON-RPC
channel and a stray byte corrupts the protocol; stdin carries client frames.
`/dev/tty` is the controlling terminal regardless of how those are redirected,
which is the property the control needs.

Everything that is not an explicit yes is a denial:

| Outcome | rule_id |
|---|---|
| human answers `y` / `yes` / `Y` | `approval_granted` |
| human answers anything else, or an empty line | `approval_denied` |
| terminal closes (EOF) | `approval_denied` |
| nobody answers within the timeout (default 120s) | `approval_timeout` |
| no controlling terminal at all | `ask_no_tty`, **immediately** |
| the prompt row cannot be audited | `audit_fail_closed` |

There is no setting that turns an unanswered prompt into an approval.

**The absence of a terminal is detected before prompting**, by opening
`/dev/tty` with `O_NOCTTY` and confirming `isatty()` — probing for a terminal
must never have the side effect of acquiring one. The first version discovered
the absence by nobody answering, which was wrong twice over: it stalled every
headless call for the full timeout, and it recorded `approval_timeout`, putting
a claim in the audit trail — that a person saw this and let it lapse — that was
not true. `ask_no_tty` and `approval_timeout` are different facts and get
different rule_ids. Measured post-fix: **0.10s** to deny, against a 2s timeout.

**Audit.** A row is written *before* prompting (`approval_prompt`, effect
`ask`), so a proxy killed mid-prompt still shows that a human was asked and
never answered. A second row records the resolution, the rule_id above, and who
resolved it — `user@host via /dev/ttys004`, or `timeout`. That is provenance,
not authentication: anyone who can write to that terminal can answer, and Aegis
cannot tell them apart.

**A real bug this surfaced.** The first wiring ran `resolve_ask` entirely in an
executor thread, which meant `store.record()` was called from a thread that did
not own the SQLite connection. Every ASK died with `SQLite objects created in a
thread can only be used in that same thread` and fell through to
`audit_fail_closed` — fail-closed, correctly, but C7 was completely broken and
only an end-to-end test caught it. Fixed by keeping every audit write on the
event-loop thread and sending only the terminal I/O to the executor. The
alternative — relaxing `check_same_thread` and adding a lock — would have meant
editing the S2 audit store to suit a caller, and the store is what everything
else's integrity rests on, so the caller bends instead.

---

## C8 — bulk threshold

`bulk_threshold`, default 10. A call whose extracted paths exceed it escalates
to ASK with `rule_id: bulk_operation`, regardless of the tool's own rule. This
is T1 insurance: the confused agent that globs too widely. Path count is the
only signal available at this layer that separates "edit a file" from "rewrite
the project".

Verified at the boundary (10 allowed, 11 escalates), against an explicit allow
rule, at other thresholds, and against non-integer / zero / negative / boolean
values which are refused at load.

---

## C9 — soft delete

For a tool rule declaring `"destructive": true`, every path is copied into
`trash_dir` before the call is forwarded. Snapshots are
`<trash>/<YYYYmmdd-HHMMSS-pid-ms>/files/<full original path>` plus a
`manifest.json`. Keeping the whole path structure makes restore unambiguous and
stops two files with the same basename colliding.

**A failed copy denies the call.** The control's promise is that a destructive
action only proceeds once it is recoverable, so "could not make it recoverable"
has exactly one safe answer. Verified against a read-only trash directory: the
call is denied with `rule_id: trash_failed` and the target is untouched.

A path that does not exist is recorded as `missing` rather than failing — you
cannot lose what was not there, and denying deletion of an absent file would be
a confusing false positive.

Two load-time refusals, because both silently do nothing useful: declaring a
destructive tool with no `trash_dir`, and pointing `trash_dir` inside a
workspace root, where the agent could delete its own undo history.

`aegis-restore list` and `aegis-restore restore <id>`. Restore never overwrites
without `--force` — the whole point is not destroying things by surprise, and
that applies to the recovery path too. No retention or expiry, as specified:
the trash grows until a human clears it.

**Scope.** On the real MCP filesystem server this control currently has nothing
to protect: that server exposes no delete tool at all, and deletion happens
through Bash, which never crosses this proxy (S1-REPORT.md's structural
limitation, S1 gap #4). C9 is ready for a server that does expose one.

---

## C10 — kill switch

A file named `KILLSWITCH` in the Aegis data directory, beside `audit.db`.
Present means every tool call is denied.

A file rather than a policy key, because the policy is parsed and cached at
startup and a running proxy would not notice an edit. The kill switch has to
work on an agent that is *already misbehaving*, which means taking effect on the
very next call with nothing restarted. Verified: engaged mid-session, the very
next call through a running proxy is denied, and a freshly started proxy is
denied too — it is a file, not process state.

Presence is the whole signal; contents are advisory. A truncated or empty file
still stops the agent, because the only failure mode that matters is failing to
stop. An error while checking counts as engaged.

**Cost: 1.3 µs per call**, one `stat()`, measured over 20,000 iterations. Not
cached — caching would create a window in which the switch is thrown and calls
still run, which is the one thing it exists to prevent.

**Scope, plainly.** This stops tool calls crossing this proxy. It does not kill
the agent process, does not revoke a credential already handed to an MCP server
in S4, and does nothing about anything outside the MCP channel (§7.6). It is a
stop button on one pipe.

---

## Approval budget — D4

D4: *"Target: fewer than 5 approval prompts per hour of agent work. Above that,
T5 (approval fatigue) defeats C7."* Measured, not asserted —
`tests/approval_budget.py`, raw output in `evidence/S5-approval-budget.txt`.

**On `tests/drive.py`:** 27 calls → 7 allow, 19 deny, **1 ask** (`move_file`).
That is 3.7 prompts per 100 tool calls:

| Tool-call rate | Prompts/hour | |
|---|---|---|
| 20/hour | 0.7 | within budget |
| 60/hour | 2.2 | within budget |
| 120/hour | 4.4 | within budget, barely |
| 300/hour | 11.1 | **over** |

**That ratio is not a session rate**, and it should not be quoted as one.
`drive.py` is an adversarial suite: 19 of its 27 calls are denials, which is
nothing like a working session. The real rate is driven by how often the
prompting tools actually get used.

### The `edit_file` change

The first measurement found the default policy **over budget in any realistic
session**. `edit_file` was marked `"ask"`, so it prompted on every edit — and
for a coding agent that is among the most frequent operations. At a 10% share
and 60 calls/hour that is 12 prompts/hour; at 25%, 30/hour.

The cause was historical: `edit_file` was marked `"ask"` in S1 when ASK
collapsed to DENY, so the marking meant "refuse this, and flag it for later".
When S5 made ASK actually prompt, the same marking silently became "interrupt
the human on every edit", and nobody re-examined it.

`edit_file` is now `"allow"` with `"within": ["<workspace>"]` — the same
treatment as `write_file`, which was already allowed and is not a weaker
operation. What is given up is per-edit confirmation; what is kept is
containment, deny_paths, DLP and the bulk threshold, all of which still apply to
every edit.

### Re-measured

Prompting tools are now `move_file`, plus any call exceeding the bulk threshold
of 10 paths.

| Share of calls that prompt | 60 calls/hour | 120 calls/hour |
|---|---|---|
| 1% | 0.6 | 1.2 |
| 2% | 1.2 | 2.4 |
| 5% | 3.0 | **6.0** |
| 10% | **6.0** | **12.0** |

Renames and >10-path calls are occasional rather than routine, so the realistic
band is low single-digit percentages: **0.6–3.0 prompts/hour, inside D4's budget
of 5.** On `drive.py` the figure is 1 prompt in 27 calls, unchanged, because
that suite's single ASK was always `move_file`.

**Where it still leaves the budget:** a session dominated by bulk operations —
a refactor touching many files, a large `read_multiple_files` — prompts once per
call over the threshold, and nothing caps or coalesces that. Raising
`bulk_threshold` trades the T1 protection away, so the real fix is session-scoped
approval ("yes, and don't ask again for this tool this session"). That is a
standing authorization, which is a new control rather than a tweak, and it is
not in S5.

---

## Verification

| Suite | Result | Exit |
|---|---|---|
| `tests/s5.py` (no controlling tty) | **80 passed, 0 failed, 1 NOT RUN** | 1 |
| `tests/s5.py` (real controlling tty, via `pty.spawn`) | **80 passed, 0 failed, 1 NOT RUN** | 1 |
| `tests/s4.py` | 65 passed, 0 failed, 2 NOT RUN | 1 |
| `tests/s3b.py` | 60/60 | 0 |
| `tests/s3a.py` | 99/99 | 0 |
| `tests/tamper.py` | 10/10 | 0 |
| `tests/drive.py` | 6 allowed / 21 denied | 0 |

`tests/s5.py` §3 drives a **real pty** — `pty.openpty()`, real `select`, real
character device — for the prompt text, path listing, rule naming, timeout
consequence, resolver identity, and every answer form (`y`, `yes`, `Y`, `n`,
empty, garbage, silence). §4 covers the no-terminal denial end to end through
the proxy, including the audit rows.

**Not established: a human answering on a live proxy's controlling terminal.**
Giving a subprocess a controlling tty while its stdin and stdout are pipes —
`setsid` then `TIOCSCTTY` in `preexec_fn` — hung with no output across several
attempts on macOS 26.5.1 / Python 3.14.3. Rather than ship a flaky test or fake
the terminal, it is `tests/manual/approval-check.md` and the suite records it
via `mark_unverified()`, printing it in the summary and exiting non-zero. A
skipped check that reads as green is the failure mode this project keeps
finding in itself.

**Tier: VERIFIED (harness, macOS)** for all four controls, per S1's definition —
real macOS hardware, real proxy, real store and verifier, raw output captured,
decisions driven by `tests/` rather than a live model session. None reaches
unqualified VERIFIED, which needs a live Claude Code session with the client's
own log captured.

---

## Findings

### 1. A test of mine nearly stopped your real agent

`tests/s5.py` engages the kill switch. The first version resolved its path from
`AEGIS_AUDIT_DB`, which was set for the *subprocesses* but not for the test
process itself — so the in-process checks engaged the switch at
`~/Library/Application Support/Aegis/KILLSWITCH`, your real data directory. The
`finally` block released it and no stray file survived, but a crash between the
two would have left your real agent silently stopped with no obvious cause.

Fixed by setting `AEGIS_AUDIT_DB` in the test process before any path is
resolved, plus a hard guard that refuses to run if the resolved kill-switch path
is outside the temp lab. This is the third time in this project a test has
reached for real state — S2's deleted audit row, S4's keychain, now this. The
pattern is worth naming: **a control that acts on the real system needs its test
harness pinned to a sandbox before the first line of test code runs, not
alongside it.**

### 2. C9 protects nothing on the server you actually run

The real MCP filesystem server exposes no delete tool. Deletion goes through
Bash, outside the proxy entirely. C9 is correct and tested, and on your current
setup it will never fire.

### 3. Approval provenance is not authentication

The audit records `user@host via /dev/ttys004`. Anyone able to write to that
terminal can approve, including a process the agent started if it shares the
terminal. Aegis cannot distinguish them. The record says which terminal
answered, not which human.

---

## Known gaps (do not claim these are handled)

1. **Bulk-heavy sessions still exceed the D4 budget.** A refactor touching many
   files prompts once per call over the threshold, with no coalescing
   (§Approval budget). `edit_file` is fixed; this is not.
2. **No session-scoped approvals**, so every prompt is per call. This is the
   remaining fix for the point above.
3. **C7 end to end with a human is unverified** (§Verification).
4. **The kill switch stops this proxy only** — not the agent process, not
   already-issued credentials, not Bash.
5. **Approvals serialize the client→server pump.** While a prompt is open, later
   tool calls queue behind it. Deliberate — two prompts competing for one
   terminal is how the wrong one gets approved — but a slow human stalls the
   agent.
6. **The trash grows without bound.** No retention, as specified. Nothing warns
   when it gets large, and it holds full copies of whatever was deleted,
   inheriting the sensitivity of the originals at mode 0700.
7. **C9 covers paths named in arguments only** — not what the server does with
   them, and not in-place truncation by a tool not marked destructive.
8. **`destructive` is hand-declared**, with no load-time guard for
   delete-sounding tool names (S3b added one for `egress`; this has no
   equivalent).
9. **Still reviewed by nobody but its author.** THREAT-MODEL.md §10 is empty.

---

## Reproduce

Expect **exit 1** with `1 NOT RUN` — correct, not a broken suite:

```bash
python3 tests/s5.py
```

```bash
python3 tests/approval_budget.py
```

```bash
./bin/aegis-stop "testing" && ./bin/aegis-resume
```
