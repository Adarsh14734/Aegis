# Aegis S10 — the Permissions screen

**Sprint:** S10
**Date:** 2026-08-19
**Scope:** a user changes what an agent may touch from the UI, without editing
JSON. No new control; a new **write path** to the file every control rests on.
**Status:** the write path is **VERIFIED (harness, macOS)**. The Tauri window
itself is **UNVERIFIED — compiled, never clicked**, and that is a weaker claim
than the rest of this report. See §The UI half.
Suite: **86 passed, 0 failed, 0 NOT RUN**, exit 0. Every prior suite unchanged.
**Revised 2026-08-23:** three bugs found by clicking through the built app. See
§Found by clicking.

---

## The thing this sprint is actually about

Not the screen. The screen is a list of buttons. S10 is the first code in Aegis
that **writes policy.json**, and THREAT-MODEL.md A7 says of that file:
*"Compromise it and every other control falls."* Until now it was written once
by `aegis init` and otherwise only by a human with an editor.

So the design question was never "how do I render three buttons", it was "what
must be impossible for the thing behind them". Five gates, in the order they
run, all in `aegis/policyedit.py`:

| Gate | Refuses when |
|---|---|
| The audit chain must verify | the tamper-evident log is broken |
| The document must load | the proxy would reject it at startup |
| Widening must be confirmed | a change grants access and nobody said so |
| The location must be right | the policy would land in a workspace root, or outside the data dir |
| The change must be recordable | the audit write fails |

Every one is proved by trying it in `tests/s10.py`. The interesting checks in
this sprint are all refusals.

---

## Where the logic lives, and why not in Rust

`aegis/policyedit.py` holds the entire write path. The Tauri command in
`ui/src-tauri/src/permissions.rs` shells out to `aegis policy` and decides
nothing.

That is S6's precedent — the UI already shells out to `verify.py` rather than
reimplementing the hash rule — applied for two reasons:

- **The validation that matters is "would the proxy reject this?"** The only
  truthful way to answer it is to call the proxy's own loader. `validate()` runs
  `Policy(doc, path)` — the same class `proxy.py` calls at startup — so the
  answer is a fact rather than a prediction. A Rust reimplementation would be a
  second decision engine that can drift, and the drift shows up as the UI
  permitting what the proxy refuses, or the reverse.
- **Python can be tested here.** The suite drives real files, a real audit
  database and the real loader. Rust would be logic whose only coverage is a
  screenshot.

The gates therefore apply identically whether the call came from the window or
from a terminal, and `permissions.rs` cannot skip them because it does not
implement them.

---

## Allow / Ask / Deny had to become real first

The brief asked for folder rows reading Allow / Ask / Deny. Allow and Deny map
onto `workspace_roots` and `deny_paths` exactly. **Ask did not exist.** The
policy engine had `ask_behavior` (global) and per-*tool* `effect: ask`; nothing
per folder.

A screen offering an Ask button against an engine that cannot express it would
be a lie of exactly the kind this project spends its reports avoiding. So
`folder_rules` was added to `policy.py`:

```json
"folder_rules": [{"path": "/Users/you/Taxes", "effect": "ask"}]
```

Four properties, each asserted against `Policy.evaluate` rather than against the
document — the test is what the engine *does*, not what the file says:

- **Absent means the empty tuple, and the empty tuple changes nothing.** Every
  policy written before S10 evaluates exactly as it did. This is the first
  sprint to touch the decision chain since S5, and a default that altered
  behaviour would silently reinterpret nine sprints of verified policies.
- **`deny_paths` still wins.** A folder set to Allow does not unblock `.env`.
  Otherwise the UI could widen the strongest rule in the file by adding a
  folder.
- **Longest match wins**, so a Deny subfolder inside an Allow folder denies
  without denying its parent. That is the case a shallower implementation gets
  wrong.
- **Ask reuses C7 entirely.** The prompt, the timeout-to-deny and the no-tty
  denial are S5's, untouched. `folder_rules` only decides that a human should be
  asked, never how the asking works.

`aegis init` and every existing policy are unaffected: `tests/drive.py`,
`s3a`, `s5` and the rest report their documented figures.

### One thing the editor does NOT do

Setting an already-unreachable folder to Deny writes **no rule**. It is already
denied by containment, and adding an entry would grow a policy full of lines
that change nothing. The suite asserts the no-op and asserts that denying a
folder which *was* allowed does write one.

---

## Widening is the asymmetry the whole screen turns on

```
$ aegis policy set-folder ~/Robotics allow
REFUSING: this grants access and has not been confirmed.
  Robotics: Deny -> Allow (Can read and change your Robotics folder)
  Confirm the grant explicitly to proceed. Removing access needs no
  confirmation; adding it does.
```

Granting needs `--confirm-grant`, and the refusal names the grant in the same
sentence the user will read on the row. Removing access goes straight through: a
user who narrows in a hurry has lost nothing they cannot restore, and a user who
widens in a hurry has.

Three changes count as widening, and the suite checks each: `Deny -> Allow`,
`Deny -> Ask` (narrower than Allow, still a grant), and **removing a deny-list
entry** — the widest change available, since that list is checked before
everything else.

---

## Plain English, and a screen that reads as sentences

`Can read and change your Robotics folder`, never `filesystem.read`. Same
discipline as S6's translate layer, and the suite greps the whole snapshot for
`tool_rules`, `rule_id` and friends. A `rule_id` is not a decision anyone can
make.

The deny list is explained rather than listed —
`Never open anything matching .env, in any folder` — and the screen carries the
session note on every render.

---

## Editing is switched off when the record is broken

If `verify.py` reports a broken chain, the screen is read-only and says why, and
the write path refuses even if called directly:

```
REFUSING: the audit chain does not verify, so Aegis will not also change
the rules.
  FAIL: audit chain broken at row id 1 …
  An edit made while the record cannot be trusted is an edit nobody can
  reconstruct. Investigate the log first.
```

Changing the rules while the record of what happened cannot be trusted would
compound the problem rather than fix it.

---

## What gets audited

`rule_id: policy_edited`, one row per change, recording **what changed** and not
the file:

```
1|ask  |policy_edited|granted: Robotics: Deny -> Allow (Can read and change your Robotics folder)…
2|ask  |policy_edited|granted: Taxes: Deny -> Ask (Must ask you first before touching your Taxes folder)…
3|allow|policy_edited|changed: Robotics: Allow -> Deny (Cannot open your Robotics folder at all)…
```

A grant records `effect: ask` and the word `granted:`; a narrowing records
`allow` and `changed:`. The row is written **before** the file, so a crash
between the two leaves evidence that a change was attempted rather than a
changed file nobody logged.

The whole policy is never copied in. A policy names private paths, and a log
that copied the file on every edit would be a second place those paths live —
the suite asserts no row exceeds 600 characters and that `tool_rules` never
appears.

---

## A running proxy does not pick the change up

`Policy.load()` runs once at proxy startup and the result is cached for the
process. That is deliberate — a policy that could change mid-session is a policy
an agent could race — and the cost is that an edit needs a restart.

The user is told at edit time, on the screen, and in the audit row. But "I was
told" and "it is currently happening" are different facts, and only one can be
checked. So `aegis doctor` compares each running proxy's elapsed run time
against the age of the newest `policy_edited` row:

```
[ FAIL ] Policy edits have reached the running proxy
           last edit 2026-08-19 20:14:02 (12s ago): changed: Taxes: Deny -> Ask
           pid 41988 has been running 31s — longer than that — so it is still
             enforcing the policy it read at startup
           Restart your agent. Aegis loads the policy once per session on
             purpose (a policy that could change mid-session is a policy an
             agent could race), and the cost is that an edit needs a restart.
```

Verified both ways in `tests/s10.py` §8, against a real proxy process.

---

## The UI half

**S6's largest gap is closed as a side effect: the Rust backend compiles.**
S6-REPORT.md recorded `cargo --version → not found` and shipped `main.rs`,
`audit.rs` and `policy.rs` having never been built. `cargo` and `rustc` are now
installed, and `cargo check --offline` finishes clean — for the S6 code *and*
for S10's `permissions.rs`.

| What | Result |
|---|---|
| `cargo check` (S6 backend + S10 commands) | **passes** — first time any of it has compiled |
| `npm run build` (tsc --noEmit + vite) | passes, 0 errors |
| `npm test` (S6 plain-English layer + the date regression) | 12/12 |
| The window opened and clicked | **never** |

So the UI is **compiled, not exercised**. That is a real step up from S6's
"never compiled" and it is not the same as working. Nobody has clicked a button
on the Permissions screen; what has been verified is the seam beneath it, which
is where every gate lives.

---

## Verification

| Suite | Result | Exit |
|---|---|---|
| `tests/s10.py` | **86 passed, 0 failed, 0 NOT RUN** | 0 |
| `tests/s9c.py` | 62 passed, 0 failed | 0 |
| `tests/s9.py` | 94 passed, 0 failed | 0 |
| `tests/s8.py` | 109 passed, 0 failed | 0 |
| `tests/s7.py` | 141 passed, 0 failed | 0 |
| `tests/s5.py` | 80 passed, 0 failed, 1 NOT RUN | 1 |
| `tests/s4.py` | 67 passed, 0 failed, 2 NOT RUN | 1 |
| `tests/s3b.py` | 60/60 | 0 |
| `tests/s3a.py` | 99/99 | 0 |
| `tests/tamper.py` | 10/10 | 0 |
| `tests/drive.py` | 4 allowed, 23 denied | 0 |

**Tier: VERIFIED (harness, macOS)** for the write path, per S1's definition —
real files, a real audit database, a real proxy process, the real loader, raw
output captured, driven by `tests/` rather than a live session.

**UNVERIFIED for the window.** Compiled is not clicked.

---

## Finding 1 — the demo caught a bug the suite could not

The suite passed 69/69 while `assert_writable_location` was broken. Running the
demonstration on a raw `mktemp -d /tmp/...` path produced:

```
REFUSING: the policy file is /private/tmp/…/policy.json, which is not in the
Aegis data directory (/tmp/…). This editor only writes there.
```

macOS symlinks `/tmp → /private/tmp` and `/var → /private/var`. The check
resolved the policy path and **not** the data directory, so on any machine whose
data directory is reached through a symlink it refused every legitimate write.

The suite missed it because `labguard.pin()` hands out an already-resolved lab,
so both sides matched by construction. This is the same bug S9's sandbox profile
had, for the same reason, and it is the second time a path comparison has been
written with one side resolved.

Both sides are now resolved and there is a regression test for it — which, on
this machine, exercises the real symlinked `/tmp`. The general lesson is worth
more than the fix: **a harness that constructs its inputs cleanly cannot see
bugs that only appear in messy inputs**, and a demo on a real path is not
redundant with a passing suite.

---

## Found by clicking — three bugs the suite could not see

The app was built and used. Three defects surfaced that 70 passing checks had
not, and the first one is the most instructive.

### 1. The selector never moved — the write was failing, not the display

Clicking Ask or Deny left the highlight on Allow. The suspicion was a stale
read. It was not: **the write genuinely failed every time**, and the selector
was being honest.

`plan_folder` removed the folder from `workspace_roots` when setting Ask or
Deny. For a policy with a single working folder — which is exactly what `aegis
init` writes — that emptied the list, and `Policy` refused the document with
*"workspace_roots must be a non-empty list"*. The gate did its job perfectly and
the feature was unusable for the default configuration.

Reproduced at the CLI seam in one command, which is the seam the screen uses:

```
$ aegis policy set-folder <the only workspace root> deny --json
{"written": false, "error": "REFUSING: the proxy would reject this policy at
 startup, so it is not being written.\n  workspace_roots must be a non-empty list"}
```

**Fix:** the root stays in `workspace_roots` and the folder rule carries the
restriction. That is sound because folder rules are evaluated at containment
and Deny/Ask win there, and it is what lets someone shut their only folder
without first inventing a second one.

Two consequences had to be handled with it:

- **The folder then appeared twice on screen** — once as Allow from
  `workspace_roots`, once as Deny from `folder_rules`. `snapshot()` now emits
  one row per folder carrying its *effective* state, with `folder_effect()`
  deciding precedence in the one place it was already decided.
- **The kernel had to agree.** S9 derives writable roots from
  `workspace_roots`, so a folder denied in the UI would have stayed writable to
  a Bash tool inside the sandbox — the two layers disagreeing about a rule the
  user had just set. `profile_from_policy` now denies read and write for a Deny
  folder rule. An **Ask** folder is deliberately *not* kernel-denied: an
  approval a human grants has to be able to proceed, and a kernel rule cannot
  be asked.

The round trip is now asserted in `tests/s10.py` §9 — for each of Allow, Ask and
Deny: the write succeeds, the screen reads the new state back as exactly one
row, and `Policy.evaluate` enforces it.

### 2. Status and Activity disagreed — Status was right

Status said "Nothing has happened today" with 0/0/0 while Activity showed
blocked rows that looked like today's. Measured against the real database:

```
start_of_today() -> 2026-08-23 00:00:00 local   (matches Python's local midnight)
newest audit row -> 2026-08-22 18:08            (18.3 hours ago)
rows today: 0
```

The day boundary was **correct**. Activity fetches the most recent rows by id
with **no date filter**, and `formatTime` rendered every one of them as a bare
clock time — so a row from three days ago read as `6:08 pm` today. The screen
was dropping the day, not the query.

`formatTime` now returns a bare clock only for today, `Yesterday 6:08 pm` for
yesterday, and a dated form beyond that. The regression test asserts that a row
five days old does **not** match `/^\d{1,2}:\d{2} (am|pm)$/` — the exact shape
that made an old row look current.

### 3. A refusal rendered as body copy

The REFUSING message shared the success `note` and rendered as an unstyled
paragraph in the page flow, so the most important sentence on the screen — *your
change did not happen* — looked like a caption. Refusals now have their own
state and an `role="alert"` region with the deep red the Blocked tag uses,
`white-space: pre-wrap` so the loader's own second line keeps its structure, and
a Dismiss button.

### What this says about the testing

Bug 1 was reachable from the CLI in one command, and the suite had 70 checks
that never made it. Every one of them set a folder in a policy with **two or
more** roots, because the fixture had a workspace plus Robotics plus Taxes. The
default single-folder shape — the one `aegis init` produces for every new user —
was never exercised.

That is the same lesson as S10 finding 1 in a different costume: **a harness
that constructs convenient inputs cannot see bugs that only appear in the
default ones.** The fixtures were richer than reality and the extra richness hid
the defect.

Bug 2 was invisible to any test of either screen alone. Status was right,
Activity was right about ordering, and only holding them side by side showed the
contradiction.

### One flaky test, fixed

Adding §9 surfaced that §8's staleness check was a coin toss: it recorded a
policy edit, started a proxy immediately, and compared the two ages against
`ps -o etime=`, which has one-second granularity. The gap was ~0.1s. It had been
passing by luck. There is now a 2.5s margin and it passes three runs in a row.

---

## Known gaps (do not claim these are handled)

1. ~~The Permissions screen has never been used by a human.~~ **It has now**,
   and it found three bugs (§Found by clicking) — one of which made the feature
   unusable in the default single-folder configuration. What remains untested by
   a person: the confirmation dialog, the locked-when-chain-broken state, and
   the deny-list controls.
2. **The UI cannot add a folder.** It edits the ones already in the policy. A
   folder picker means a native dialog, a path the user chose being handed to
   the write path, and its own verification.
3. **The Ask state depends on C7 having somewhere to prompt.** With
   `ask_behavior: "deny"` — the headless setting — a folder set to Ask denies
   instead of prompting. The screen does not currently say which mode the policy
   is in, so "Ask" can silently mean "Deny".
4. **Widening is confirmed, not authenticated.** Anyone who can reach the window
   or the CLI can confirm a grant. There is no second factor, and on a
   single-user machine that means any code running as you — the same caveat S5
   recorded for approvals and S6 for the removed bridge.
5. **`folder_rules` is new decision logic and has one sprint of testing.**
   Everything else in the chain has had between five and nine.
6. **No undo.** An edit is a write; the previous policy is not kept. `aegis
   init` takes a backup, this does not, and the audit row records the change but
   restoring is manual.
7. **The staleness check needs a `policy_edited` row.** A policy edited with a
   text editor is invisible to it — doctor compares against the log, not the
   file's mtime, so a hand edit shows as "no edit ever recorded".
8. **Still reviewed by nobody but its author.** THREAT-MODEL.md §10 is empty
   after eleven sprints.

---

## Reproduce

```bash
python3 tests/s10.py
```

```bash
aegis policy show
aegis policy set-folder ~/Robotics allow            # refused: unconfirmed grant
aegis policy set-folder ~/Robotics allow --confirm-grant
aegis policy set-folder ~/Robotics deny             # narrowing: no confirm needed
```

The UI half, as far as it goes:

```bash
cd ui && npm run build && npm test && (cd src-tauri && cargo check)
```
