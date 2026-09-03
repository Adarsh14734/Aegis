# Aegis S9 — the sandbox

**Sprint:** S9
**Date:** 2026-08-18
**Control:** C11 — constrain the agent's whole process tree, not just its MCP traffic
**Revised 2026-08-19 (S9b):** gap 7 closed — kernel denials now reach the audit
log as `sandbox_denied` rows, and `aegis doctor` reports sandbox status. See
§S9b.
**Revised 2026-08-19 (S9c):** gap 2 narrowed — `aegis init` offers to route the
client's own launch through `aegis run`, so the sandbox is the default rather
than an opt-in. See §S9c. Suite: **62 passed, 0 failed**.
**Status:** **VERIFIED (harness, macOS)**. Not unqualified VERIFIED: no live
Claude Code session has been run inside `aegis run`.
Suite: **94 passed, 0 failed, 0 NOT RUN**, exit 0. Every prior suite at its
documented figure.

---

## The gap this closes

S1 gap #4, repeated by every sprint since:

> Aegis mediates the MCP channel; a bash tool bypasses it entirely. Anything not
> spoken over this stdio pipe is outside the boundary — THREAT-MODEL.md §7.6.
> **Observed live:** three of four attempts on the secret went via Bash and were
> stopped by Claude Code's own permission rules, not by Aegis. Aegis alone would
> not have blocked them.

That sentence has been the honest caveat on every control for nine sprints. The
MCP layer sees the frames that cross one pipe; `npm install` running a
postinstall script, a `curl` in a shell, the agent's own native file tools, and
every subprocess of any of them, saw nothing at all.

C11 moves the same rules down to the kernel. `evidence/S9-kernel-enforcement.txt`
runs S1's own attempts inside `aegis run`:

```
$ cat $LAB/fake-home/.ssh/id_rsa
  cat: …/fake-home/.ssh/id_rsa: Operation not permitted        [exit 1]
$ python3 -c "print(open('…/.ssh/id_rsa').read())"
  Traceback … PermissionError                                  [exit 1]
$ cat $LAB/workspace/.env
  cat: …/workspace/.env: Operation not permitted               [exit 1]
$ cat $LAB/workspace/main.py
  ordinary source file                                         [exit 0]
$ echo new > $LAB/workspace/created.txt && echo WROTE-INSIDE
  WROTE-INSIDE                                                 [exit 0]
$ echo escape > /tmp/aegis-s9-escape.txt
  /bin/bash: /tmp/…: Operation not permitted                   [exit 1]
$ curl -s -w 'http=%{http_code}' https://evil.xyz/
  http=000                                                     [exit 0]
$ echo '{}' > $LAB/policy.json && echo REWROTE-POLICY
  /bin/bash: …/policy.json: Operation not permitted            [exit 1]
```

`Operation not permitted` is EPERM from the kernel. There is no Aegis in that
error, no policy layer, and nothing to ask a human about. The control preceding
it — the same files read successfully with no sandbox — is in the same file, so
a denial cannot be mistaken for an absence.

---

## Evaluating ASRT

D2: *"Wrap the vendor sandbox; do not rebuild it… Reimplementing kernel isolation
as a solo founder is a multi-month detour with a high chance of producing
something weaker."* The brief asked for that evaluation before any code, so it
was done first.

**`@anthropic-ai/sandbox-runtime` 0.0.73** (`srt`, Apache-2.0) is the
implementation D2 names — `sandbox-exec`/Seatbelt on macOS, bubblewrap on Linux,
network filtering via its own HTTP and SOCKS5 proxies. It was installed and
driven directly against files that exist, before a line of `aegis/sandbox.py`:

| Probe | Result |
|---|---|
| `cat` a denied file that exists | `Operation not permitted` |
| `cat` a denied file inside an allowed region | denied — deny beats allow, matching policy.py's precedence |
| `cat` an ordinary file in the workspace | works |
| write outside `allowWrite` | `Operation not permitted` |
| write inside | works |
| `curl` a non-allowlisted host | fails |
| `curl` an allowlisted host | 200 |
| invalid settings file | *it* refuses to run, and says it is refusing |
| exit code | passed through unchanged |

Its settings shape — `filesystem.{allowRead,denyRead,allowWrite,denyWrite}`,
`network.{allowedDomains,deniedDomains}` — maps onto policy.json without
distortion. **Decision: use it. Write no sandbox.** `aegis/sandbox.py` contains
no isolation logic and the suite asserts that (§1 greps it for hand-written
profile syntax and namespace calls).

**What that costs, stated because it is real.** ASRT is a Node package with four
dependencies and `node >= 20.11`, and `aegis-mcp` is a zero-dependency Python
package. pip cannot install it, so it is an externally-provisioned prerequisite
that `preflight()` detects and refuses without. That is a genuine widening of
what has to be present for a control to work, and it is not a widening of the
Python TCB — the kernel-facing code is Anthropic's, reviewed by people who do
this full time, which is the entire point of D2.

**One caveat worth knowing:** `srt --version` reports `1.0.0`, not the npm
package version (`0.0.73`). Anyone pinning a version by that string would be
pinning nothing.

---

## What was built

| File | Role |
|---|---|
| `aegis/sandbox.py` | policy.json → sandbox profile, digest, preflight, fail-closed establishment |
| `aegis/cli.py` | `aegis run -- <agent-command>`, `--deny-all-network`, `--print-profile` |
| `tests/s9.py` | 94 checks: real processes, real runtime, files that exist |
| `evidence/S9-suite.txt` | Suite output plus a regression run of every prior suite |
| `evidence/S9-kernel-enforcement.txt` | S1's own attempts, run inside `aegis run` |
| `aegis/violations.py` | **S9b.** Reads macOS sandbox violations; `sandbox_denied` rows |
| `evidence/S9b-violation-observability.txt` | **S9b.** What is and is not observable, measured |
| `evidence/S9b-suite.txt` | **S9b.** 94 checks plus a regression run |
| `aegis/launcher.py` | **S9c.** Launch wrappers, the shell shim, and effectiveness |
| `tests/s9c.py` | **S9c.** 62 checks, including a client genuinely confined by a wrapper |
| `evidence/S9c-default-sandbox.txt` | **S9c.** Before/after, and the bypass asserted |
| `evidence/S9c-suite.txt` | **S9c.** 62 checks plus a regression run |

`aegis/policy.py` is **unchanged** — no decision logic touched. S7's `init` and
`uninstall` are byte-identical. **`doctor` was changed in S9b**, on instruction,
to report sandbox status; S9 itself touched no S7 onboarding.

### One source of truth

The profile is generated from policy.json and nothing else, then written 0600
next to it and digested. From the real policy on this machine:

```json
{ "filesystem": {
    "denyRead":  ["/**/*.pem", "/**/.aws", "/**/.aws/**", "/**/.env",
                  "/**/.ssh", "/**/.ssh/**", "/**/id_rsa"],
    "allowWrite": ["/Users/adarsh/Library/Application Support/Aegis",
                   "/Users/adarsh/code/aegis-testlab/workspace"],
    "denyWrite": [ …the same deny patterns…,
                   "…/Aegis/KILLSWITCH", "…/Aegis/policy.json"] },
  "network": { "allowedDomains": ["api.example.com", "example.com"],
               "deniedDomains": [] } }
```

Two entries in `denyWrite` are not from `deny_paths` and are the reason the rest
of the design holds together:

- **policy.json.** The agent cannot rewrite the policy that constrains it. S1
  argued this structurally — the file sits outside every workspace root — and
  now the kernel enforces it (A7). Verified: the write fails with EPERM and
  `deny_paths` is unchanged afterwards.
- **KILLSWITCH.** The agent cannot delete the stop button. A kill switch an
  agent can remove is not a kill switch (C10). Verified: `rm -f` leaves the file
  in place.

The profile is regenerated on every launch, so an edited policy cannot leave
yesterday's rules in force. The suite asserts that a changed `deny_paths`
produces a different digest and that the new pattern is present.

---

## Finding 1 — the first translation enforced nothing, and looked right

The headline requirement is that a path denied in policy is denied by the
kernel. The first version of `_deny_globs` translated policy's `.env` into
`**/.env`, which is what ASRT's own README shows. The suite caught it
immediately: **`cat` of the ssh key succeeded inside the sandbox.**

Measured rather than guessed:

```
denyRead=["**/id_rsa","**/.env"]   cwd=/tmp/globtest      -> Operation not permitted
denyRead=["**/id_rsa","**/.env"]   cwd=~/code/aegis       -> KEYBYTES / ENVBYTES
denyRead=["/**/id_rsa","/**/.env"] cwd=~/code/aegis       -> Operation not permitted
```

**A relative glob in this runtime is rooted at the process's working directory,
not at the filesystem root.** So `**/.env` denies `.env` only under wherever the
agent happens to have been started, and `cat ~/.ssh/id_rsa` from a workspace in
`/tmp` sails straight through. Every pattern is now anchored as `/**/…`, which
the runtime does treat as filesystem-wide, and which is also the correct
translation of policy.py's semantics — it matches each pattern against the full
path *and* the basename, so a bare `.env` means "any file named .env, anywhere".

Two things are worth taking from this beyond the fix.

**The failure was silent and passed every structural check.** The profile was
valid, the runtime accepted it, `aegis run` reported a sandbox established with
seven read-denied patterns, and the audit row recorded a digest. Everything that
reads a file said yes. Only running `cat` said no. This is the same lesson S7's
doctor was built around and S8's TLS probe re-taught: a control is not verified
by its inputs looking plausible.

**A partial kernel rule is worse than none.** If the kernel denies less than the
MCP layer, the two layers disagree about what is forbidden and the weaker answer
is the one that decides — while the report claims both. `tests/s9.py` now carries
a regression guard asserting every deny pattern is absolute, which is the
specific shape of this bug rather than a general gesture at it.

A second, quieter version of the same class: paths were mixed between `/var/...`
and `/private/var/...` (macOS symlinks one to the other), because the policy path
was resolved and the data directory was not. Everything in the profile now goes
through one `_resolved()` helper, and the suite asserts every path equals its own
`resolve()`.

---

## The network residual

The brief asked that only the proxy's own egress path reach the network. **That
is not what was built, and it cannot be with this design.** Stated plainly:

The MCP proxy runs *inside* the sandbox, because the MCP client spawns it as a
child and inherits the confinement to it. Network filtering in ASRT is by
domain, applied to the whole sandbox — it cannot distinguish a request made by
`aegis/fetch.py` from one made by `curl` in a shell, because both are processes
in the same sandbox talking to the same filtering proxy. So:

- `allowedDomains` is set to policy's `allowed_domains`, and bash inside the
  sandbox **can** reach those same hosts. Observed, not assumed — the suite runs
  the curl and prints what happened (`200`).
- Everything else fails. `curl evil.xyz` returns `http=000`.
- `--deny-all-network` sets `allowedDomains: []`, which closes bash egress
  completely **and disables C4's egress with it**. Both halves verified.

What this is, honestly: before S9 a shell inside the agent could reach any host
on the internet. After S9 it can reach only the hosts policy already permits an
MCP tool to reach. That is a large reduction and it is not the same thing as
"only the proxy may reach the network".

Closing it properly means running the proxy *outside* the sandbox and giving the
sandboxed client a stdio relay to it over a permitted socket. That is a real
design, and S6's removed approval bridge is the reason it is not in this sprint:
a socket any process running as the user can talk to, built and shipped without
ever having been exercised, is precisely the mistake that report exists to
record. It needs its own sprint and its own gate.

### The data directory is writable, and what follows

`allowWrite` includes the Aegis data directory, because the proxy inside the
sandbox must write `audit.db` before every forwarded call (C3) and stage copies
into `trash_dir` (C9). A sandbox that denied it would take C1–C10 down with it —
the proxy fails closed and denies everything.

The consequence: bash inside the sandbox can also write there. `policy.json` and
`KILLSWITCH` are individually write-denied so A7 and C10 survive, but
**`audit.db` is writable from inside**. That is not new — S2 gap 1 has always
said an attacker with write access can rewrite the chain, and `verify.py`
detects edits while an external anchor is the only defence against a wholesale
rewrite. It is worth naming here because a reader could reasonably assume a
kernel sandbox protects the audit log, and it does not.

---

## Verification

| Suite | Result | Exit |
|---|---|---|
| `tests/s9.py` | **67 passed, 0 failed, 0 NOT RUN** | 0 |
| `tests/s8.py` | 109 passed, 0 failed | 0 |
| `tests/s7.py` | 138 passed, 0 failed | 0 |
| `tests/s5.py` | 80 passed, 0 failed, 1 NOT RUN | 1 |
| `tests/s4.py` | 67 passed, 0 failed, 2 NOT RUN | 1 |
| `tests/s3b.py` | 60/60 | 0 |
| `tests/s3a.py` | 99/99 | 0 |
| `tests/tamper.py` | 10/10 | 0 |

**Tier: VERIFIED (harness, macOS)** per S1's definition — real macOS hardware,
the real sandbox runtime, real processes, files that really exist, raw output
captured, driven by `tests/` rather than a live model session.

### The seven cases the brief named

| Case | Result |
|---|---|
| bash `cat` of a `deny_paths` file fails inside | EPERM, and the same denial via `python3 open()` — not specific to one program |
| bash `curl` to any host fails | non-allowlisted host fails; with `--deny-all-network` an allowlisted one fails too |
| a write outside `workspace_roots` fails | EPERM, and the file does not appear |
| a legitimate write inside succeeds | written and present on disk |
| the MCP proxy still functions inside | proxy speaks MCP, an allowed read is forwarded, a `deny_paths` read is denied with `AEGIS DENIED`, audit rows written from inside, chain verifies |
| `aegis run` refuses when the sandbox cannot be established | exit non-zero, nothing launched, `REFUSING TO LAUNCH`, refusal recorded as `sandbox_refused` |
| the profile matches policy.json and regenerates on change | asserted both directions, with the digest |

Both layers now cover a denied path, and the suite checks they agree: the MCP
layer answers `AEGIS DENIED … rule deny_paths` with an explanation the model can
act on, and the kernel answers EPERM to anything that tries another route.

### Fail-closed, and what it records

`aegis run` loads the policy, establishes the sandbox, records establishment with
the profile digest, and only then launches. Every failure before the launch
refuses and is recorded:

```
1|aegis run|allow|sandbox_established|sandbox established via srt on darwin; profile 57bd62b2…
```

There is no flag that turns a failed sandbox into an unconfined launch. Verified
paths: no runtime (`sandbox_refused`), unloadable policy, unavailable audit log,
runtime rejects the profile. The refusal message says why a fallback would be
worse — an agent that looks sandboxed and is not is worse than one nobody
believed was.

### Not established by this sprint

- **No live Claude Code session inside `aegis run`.** The gate would be: launch
  a real session sandboxed, tell the model to read a denied file, and capture the
  client's own log showing it failing at the kernel — and, separately, confirm
  the model's native file tools are confined too, which is the half no MCP-layer
  control could ever reach.
- **Linux.** The bubblewrap branch of `preflight()` exists and has never
  executed. Nothing here has run on Linux.
- **Windows.** ASRT supports it via a dedicated user account and WFP filters;
  `preflight()` refuses outright rather than pretending.
- **That the sandbox holds against an attempt to escape it.** Nothing here
  attacks Seatbelt. §7.7 is inherited, not tested.

---

## S9b — closing gap 7: the kernel layer now reaches the audit log

S9 shipped C11 enforcing without observing. `cat ~/.ssh/id_rsa` failed with
EPERM, the agent saw it, and **no audit row existed**: the two strongest
controls did not meet. That is now closed for the part that is observable, and
stated plainly for the part that is not.

### ASRT's violation API is unreachable from what Aegis wraps

`@anthropic-ai/sandbox-runtime` has a real violation store
(`getViolationsForCommand`, `SandboxViolationStore`). It lives in the Node
**library**. Aegis wraps the `srt` **binary**, and `grep -c -i violation
dist/cli.js` is **0** — the CLI does not surface violations at all.

What ASRT's own macOS store does is spawn:

```
log stream --predicate '(eventMessage ENDSWITH "<session-suffix>")' --style compact
```

and filter for `Sandbox:` + `deny`. The *source* is the macOS unified log, which
is equally available to Aegis. `aegis/violations.py` reads that same source. It
writes no sandbox and contains no isolation logic; D2 is about not building a
sandbox, and reading an OS log is not building one.

### What is observable, measured rather than assumed

`evidence/S9b-violation-observability.txt` has the raw capture.

**Filesystem denials: fully observable.**

```
Sandbox: cat(7866) deny(1) file-read-data /private/tmp/.../.ssh/id_rsa
```

Process, pid, operation, full path. This is what `sandbox_denied` rows are made
of, and it is what the brief asked for.

**Blocked hosts: NOT observable. Aegis does not record them and does not
pretend to.** Two independent reasons, both measured:

1. A *domain* refusal never reaches the kernel. ASRT lets the sandbox reach its
   own loopback proxy and the proxy refuses the domain, so
   `curl https://evil.xyz/` returns `http=000` and the kernel logs **nothing**.
   One `network-outbound` line appeared in the whole capture and it was `nc`'s,
   not curl's.
2. A *raw socket* denial does reach the kernel, but as
   `network-outbound remote:*:443` — **port only, no hostname**, unrecoverable
   from the line.

So the brief's "path or host" is delivered as path. The host half is impossible
with this runtime, the `sandbox_closed` row says so in the log itself, and the
suite asserts that **no row ever mentions the blocked domain** — an audit log
that claimed to see hosts it cannot see would be worse than one admitting the
gap.

### Attribution is deliberately narrow, because the log is machine-wide

A five-second capture carried denials from `imagent`, `assistantd`,
`biomesyncd` and `triald` — macOS sandboxing its own daemons. Ordinary
processes also generate constant benign noise: `sysctl-read`, `mach-lookup` and
`iokit-open-user-client` outnumbered real denials in the capture.

Recording any of that would be inventing rows. So a line becomes a row only
when **the denied path matches a deny pattern in the profile Aegis generated
from policy.json** — the exact claim worth making, checked against our own
profile rather than guessed from process names. Everything else is counted and
reported in the `sandbox_closed` row, so the log says what it saw and could not
attribute instead of silently dropping it.

### What a session now records

```
1|aegis run     |allow|sandbox_established|… watching for kernel denials
2|sandbox:cat   |deny |sandbox_denied     |the kernel refused file-read-data on …/.ssh/id_rsa
3|sandbox:cat   |deny |sandbox_denied     |the kernel refused file-read-data on …/workspace/.env
4|aegis run     |allow|sandbox_closed     |2 kernel denial(s) recorded; 8 benign denial(s) ignored; …
```

Each denial row names the path, the process and pid, and says the denial was an
**OS-level EPERM, not a policy-engine decision** — the distinction is the whole
point of the row. `tool` carries `sandbox:<process>` rather than an MCP tool
name, so it cannot be misread as a tool that exists.

**No schema change.** `sandbox_denied` is a new `rule_id` under the existing v2
payload; the `row_hash` rule is untouched and the chain verifies with these rows
in it.

Rows are written on the main thread while the agent runs (drained once a
second), so a long session records denials as they happen. Only the log reader
is threaded — S5's SQLite lesson.

**Failure is non-fatal and visible.** If `log stream` cannot start, the session
still runs and the audit records that observation was unavailable and why. An
agent that refused to launch because a *log reader* failed would trade a working
control for a missing one.

### `aegis doctor` now reports the sandbox

A new check reports whether `srt` is present, whether the profile on disk
matches the current policy, and — on every run, in every state — that

> The sandbox applies ONLY to agents started with `aegis run`. An agent you
> launch any other way has no kernel boundary — its Bash, its subprocesses and
> its native file tools are unconstrained, exactly as they were before S9.

A missing runtime is a **WARN**: not having opted in is a configuration choice,
and `aegis run` refuses to launch without it, so it is a missing capability
rather than a silent hole. A profile that **disagrees with the policy** is a
**FAIL**, because that is a real inconsistency.

Doctor's NOT COVERED block was rewritten: Bash and native tools are no longer
listed as simply uncovered, since `aegis run` covers them. Two S7 assertions
checked the old wording and were updated to track the intent — both still assert
that Bash and the native tools are named.

---

## S9c — the sandbox as the default

S9 and S9b left C11 correct and unused. The boundary existed, the denials were
audited, and a user who installed Aegis and then opened Claude Code the way they
always had got **none of it**. Doctor said so on every run, which is honest and
is not protection.

### Two mechanisms, and they are not equally strong

**The wrapper**, offered by `aegis init`. A script in Aegis's own `bin`
directory, named after the client, that execs `aegis run -- <the real binary>`.
It applies in every shell, in scripts, and to anything resolving the client
through PATH.

**The shim**, printed by `aegis shell-init`. A shell function. Strictly weaker —
it applies only to shells that sourced it — and it exists because it needs no
PATH surgery.

Both are **advice, not enforcement**, in those words, in the code, in the
snippet's own comments and in doctor's output.

### Why the wrapper does not live next to the client

On this machine `claude` is `~/.local/bin/claude`. A wrapper called `claude`
written into that directory **overwrites the user's client**, and uninstall
would then have to restore a binary Aegis destroyed. Wrappers therefore live in
`<data dir>/bin`, and effectiveness depends on that directory coming first on
PATH.

That split is why `effective_status()` **resolves the name through PATH** rather
than checking a file exists. A wrapper nobody's PATH reaches is a file, not a
control — the same distinction S7's doctor was built around, and the suite
asserts both halves: with the directory behind, the wrapper exists and is
reported as *not* effective, naming PATH as the reason.

### It sandboxes, which is not the same as resolving

`tests/s9c.py` §3 runs a stand-in client that reports whether it can read a
denied file, and `evidence/S9c-default-sandbox.txt` shows it end to end:

```
BEFORE   $ claude --resume
           [client] I CAN read the ssh key

AFTER    $ claude --resume          (wrapper dir on PATH)
           [client] the ssh key is DENIED to me

BYPASS   $ /full/path/to/claude
           [client] I CAN read the ssh key
```

The third line is asserted by the suite, not merely described. A wrapper that
resolved correctly and did not confine would pass every structural check and be
worth nothing.

Two details that turned out to matter:

- **`AEGIS_SANDBOXED` prevents nesting.** `aegis run` sets it in the environment
  it launches; a wrapper or shim that sees it calls the real binary directly.
  Without it a sandboxed client that shells out to `claude` would apply a second
  profile to a process the outer sandbox had already confined.
- **The Aegis invocation is baked in at install time**, not written as
  `aegis run`. The wrapper already depends on its own directory being early on
  PATH; depending on `aegis` being there too means a reordered PATH turns the
  wrapper into "command not found" instead of a sandbox. Caught by the suite,
  which has no `aegis` console script on PATH at all.

### It is a choice, and declining is a real path

`--yes` answers this offer with **False**. Installing something that changes
what a user's `claude` command does is a larger thing to do to a machine than
editing a config file, and it does not happen on a default. Declining prints
what was not done and leaves the pre-S9c behaviour exactly: the sandbox is still
there via `aegis run`, and doctor keeps warning.

### Doctor stops warning when — and only when — it is real

A new check reports per client: wrapped, shim present, or neither, with the
reason. When at least one client resolves to an Aegis wrapper it passes, and the
sandbox check's standing line changes from

> The sandbox applies ONLY to agents started with `aegis run`…

to

> Your client's launch is routed through `aegis run`, so this applies to it by
> default. It does not apply to a client started by its full binary path, or one
> already running.

Being unwrapped is a **WARN, never a FAIL** — opting out is a choice, not a
broken installation — and the suite asserts that too. A warning that stays up
after the thing it warns about is fixed is how people learn to skip warnings.

### What remains impossible

Forcing an **already-running** process into a sandbox. On macOS that requires an
Endpoint Security entitlement, which Apple grants to registered organizations
and which no `pip install` can supply. Aegis can decide how a process starts; it
cannot reach into one that already has. A client open when Aegis was set up stays
unconfined until it is restarted.

THREAT-MODEL.md §7.6 is **narrowed, not removed**: from "any agent you start
yourself" to direct invocation of the real binary path, a shell that never
sourced the shim, a GUI launch that does not consult PATH, and processes already
running.

### Verification

**Tier: VERIFIED (harness, macOS)** — real wrappers, a real PATH, real
subprocesses, a real sandbox, with the client's confinement proved by a denied
read rather than by inspecting the wrapper text. Not unqualified VERIFIED: no
live Claude Code session has been started through a wrapper.

`tests/s9c.py`: **62 passed, 0 failed, 0 NOT RUN**. Everything runs against a
fake client on a fake PATH in a `labguard`-pinned lab, so the operator's real
`claude` and real wrapper directory are never touched — checked, and the real
`<data dir>/bin` does not exist after the run.

**One integration consequence worth naming:** adding a prompt to `aegis init`
broke S7's pty-driven interactive test, which answers a fixed list of questions
and hit EOF on the new one. That is the test doing its job — it detected a
changed prompt sequence — and it now answers the new question with "n", which
also covers declining interactively. S7 is 141/0.

---

## Known gaps (do not claim these are handled)

1. **A kernel escape defeats C11 entirely** (§7.7). It is now load-bearing: it is
   the reason `cat ~/.ssh/id_rsa` fails, and it is exactly as strong as
   `sandbox-exec` and the runtime driving it. Aegis would neither prevent nor
   notice a bypass.
2. ~~Only agents `aegis run` launches are confined.~~ **Narrowed in S9c**, not
   closed. When the user accepts the launch wrapper, typing the client's name
   sandboxes it. What still escapes: **invoking the real binary path directly**
   (a wrapper is a PATH entry, and PATH is advice), a shell that never sourced
   the shim, a GUI launch that does not consult PATH, and **any process already
   running** — which needs an Endpoint Security entitlement Apple grants to
   registered organizations and is not an engineering shortfall. Declining the
   offer leaves the original gap in full, and doctor keeps saying so.
3. ~~`aegis doctor` says nothing about the sandbox.~~ **Closed in S9b.** Doctor
   reports runtime presence, profile-vs-policy agreement, and that `aegis run`
   is required for any kernel enforcement. It still cannot detect that an agent
   is *currently* running unsandboxed — gap 2 — it can only say the boundary is
   opt-in.
4. **The network residual** (§The network residual): bash inside can reach
   policy's allowed domains. Only `--deny-all-network` closes it, at C4's cost.
5. **`audit.db` is writable from inside the sandbox**, necessarily. S2 gap 1,
   now with a kernel boundary around it that does not protect it.
6. **`aegis init` does not write the sandbox profile or mention `aegis run`.**
   Onboarding a stranger into C11 is a separate piece of work.
7. ~~No violation reporting.~~ **Closed in S9b** for filesystem denials (§S9b).
   What remains open, and is now the honest residual: **a blocked host is never
   recorded**, because a domain refusal happens in the sandbox runtime's proxy
   and never reaches the kernel log, and a raw-socket denial carries only a
   port. Also unrecorded: denials the kernel coalesces ("N duplicate reports"),
   so row count is not a reliable count of attempts; and any denial whose path
   does not match a policy deny pattern, which is counted in `sandbox_closed`
   but not itemised.
8. **Read is allow-by-default outside `deny_paths`.** The agent can read most of
   the filesystem — source, dotfiles not matching a deny pattern, other projects.
   Only writes and the named deny patterns are constrained. A read-deny posture
   would need enumerating everything an interpreter needs, which is how a sandbox
   becomes a compatibility problem and then gets switched off.
9. **The profile is trusted once written.** It is 0600 and regenerated per
   launch, but nothing re-checks it mid-session, and a root user can edit
   anything (§7.2).
10. **`srt --version` does not report the package version**, so version pinning
    on that string is meaningless.
11. **Violation observation is macOS-only.** `aegis/violations.py` reads the
    macOS unified log. On Linux the sandbox enforces and nothing is recorded
    about what it stopped; the session row says so rather than implying
    coverage.
12. **A harness reached real state again.** During S9b a shell loop failed to
    apply its `AEGIS_*` overrides and four `sandbox_established` rows (92–95)
    and a real `sandbox-profile.json` landed in the operator's actual data
    directory. The rows are honest records of real establishments, the chain
    verifies, and they were left in place — deleting rows from the live log is
    exactly what S2's operating rule forbids. This is the fifth time (S2, S3a,
    S4, S5, now this): **shell-level env plumbing is not a sandbox, and only the
    Python-level pinning in `tests/*.py` has ever held.**
13. **Still reviewed by nobody but its author.** THREAT-MODEL.md §10 is empty
    after ten sprints.

---

## Reproduce

```bash
npm install -g @anthropic-ai/sandbox-runtime && python3 tests/s9.py
```

The one worth watching, in a scratch directory with a policy that denies `.env`:

```bash
aegis run -- bash -c 'cat ~/.ssh/id_rsa; curl -s -m 5 https://evil.xyz/; echo x > /etc/x'
```

Without the runtime installed, to see the refusal:

```bash
AEGIS_SANDBOX_RUNTIME=/nonexistent aegis run -- echo should-not-run
```

---

# S9d — the recommended install path made the client unusable

Reported after accepting the S9c launch wrapper:

> `Remote Control disconnected — Session creation failed`
> `Auto-update failed`

`aegis init` writes `allowed_domains: []`. `sandbox.py` turns that into
`allowedDomains: []`. The sandbox then grants **zero reachable hosts**, so a
client started through the wrapper cannot reach its own API and does not work.
S9c made that wrapper the recommended path, so the recommendation broke the
thing it was protecting — and a control that does that gets uninstalled, taking
C1..C11 with it.

## Confirmed, not inferred

The mechanism, first, in isolation:

```
$ srt -s <allowedDomains: []> -c 'curl -m 12 https://api.anthropic.com/v1/messages'
curl: (56) CONNECT tunnel failed, response 403

$ srt -s <allowedDomains: ["api.anthropic.com"]> -c 'curl ... '
http=405            # the API answering a GET on a POST route: it arrived
```

Then the client itself, started inside an empty-allowlist profile:

```
denied, by count:      20  api.anthropic.com:443
                        2  http-intake.logs.us5.datadoghq.com:443
on screen:             ⏺ Remote Control disconnected — Session creation failed
```

and the same start with two hosts granted:

```
denied, by count:       4  mcp-proxy.anthropic.com:443
                        2  http-intake.logs.us5.datadoghq.com:443
on screen:             /rc active
```

Twenty refusals of `api.anthropic.com` in one start; none after. Full capture in
`evidence/S9d-client-endpoints.txt`.

**A correction to S9b while we are here.** `violations.py` says a domain refusal
"never reaches the kernel at all… Aegis cannot record the host". That is true of
the macOS unified log, which is what that module reads. It is **not** true of
the runtime's own debug stream:

```
[SandboxDebug] No matching config rule, denying: api.anthropic.com:443
```

The host and port are right there under `srt -d`. Recording blocked
destinations from that stream is possible and is not done today; S9b's gap is
narrower than it claims. Left open deliberately rather than fixed in passing —
it changes what the audit log contains, and that deserves its own sprint.

## The fix, and the key it did not use

A default allowlist for the detected client's own endpoints, offered when the
user accepts the wrapper. The alternative — prompting for domains at init —
asks a question nobody can answer: no user knows their client talks to
`downloads.claude.ai`. It produces a blank list and the same breakage.

The endpoints do **not** go in `allowed_domains`. That key is C4's egress
allowlist (`egress.py`, `fetch.py`), and a host listed there becomes fetchable
by the agent's own tools *through the proxy*. The client needing a socket is no
reason to hand the agent an allowlisted route to the Anthropic API.

So there is a new key:

| key | who reads it | what it grants |
|---|---|---|
| `allowed_domains` | `egress.py`, `fetch.py`, and the sandbox | where the agent's own tool calls may go |
| `sandbox_domains` | the sandbox, and nothing else | where the process tree may open a socket |

Both are validated by the same `_normalize_host_list`, so neither can say `*`,
`*.example.com`, or anything carrying a scheme or a path. There is no spelling
of "everything". `--deny-all-network` clears both.

## The endpoint table

In `launcher.py`, next to `KNOWN_CLIENTS`, each entry measured rather than read
off a page — `strings` on the client binary yields about forty hostnames, most
of them documentation links it never dials.

| host | for | required |
|---|---|---|
| `api.anthropic.com` | the API; no session starts without it | yes |
| `downloads.claude.ai` | version checks and auto-update | no |
| `mcp-proxy.anthropic.com` | hosted MCP connectors | no |

Deliberately absent:

- **`http-intake.logs.us5.datadoghq.com`**, the telemetry sink. Refused in every
  run above including the one where everything worked, so it is not needed to
  function. Opening a diagnostics route out of a sandbox somebody installed to
  reduce their exposure is not a default to pick for them. `aegis init` names it
  so the denial is not a mystery.
- **Everything for cursor, windsurf and cline.** Not measured here. Inventing
  plausible hostnames for a security allowlist is how an allowlist stops meaning
  anything; they get an empty list and a sentence saying so.

## What `aegis doctor` was not saying

The reported configuration **passed** doctor. The sandbox check compared the
profile to the policy, they matched exactly, and it reported PASS — a correct
profile for an unusable setup. Two changes:

- the sandbox check now names the reachable hosts instead of counting them, or
  says plainly that none are reachable;
- a new check FAILs on the exact combination that breaks: launch wrapped, zero
  reachable hosts. It quotes the symptom the user actually sees
  ("Session creation failed"), because that message looks like a client bug and
  is easy to blame on the client.

The digest requirement needed no special handling: `sandbox_domains` feeds
`profile_from_policy`, so `matches_policy` regenerates and the digest moves on
its own. `tests/s9.py` asserts it moves.

## Constraints held

`denyRead`, `denyWrite` and `deny_paths` are untouched — asserted directly by
comparing the two profiles' filesystem sections, modulo each profile
write-denying its own policy file. No blanket access is expressible. The
residual is unchanged and restated wherever the grant is: the sandbox cannot
tell the client's request from its Bash tool's, so anything in the tree can
reach these hosts. That is exactly why the list is three entries and not a
wildcard.

## Suites

| | before | after |
|---|---|---|
| s9 | 94 / 0 | **116 / 0** |
| s9c | 62 / 0 | 62 / 0 |

`s3a` 99, `s5` 80 (1 NOT RUN, the pre-existing manual pty approval test), `s7`
141, `s8` 109, `s10` 86 — all 0 failed.

## Still open

- **The mouse escape sequences (`^[[<65;184;57M`) are not this bug.** Startup was
  captured with the network open and closed; both emit `\x1b[?1004h` (focus
  events) and neither emits `?1002h`/`?1006h`, which is what an SGR wheel report
  requires. Identical either way, so the allowlist is not the cause. Not
  reproduced here and not explained.
- **The table is complete for a session start, Remote Control and the update
  check, and only for those.** A feature not exercised in those runs may dial
  something else. The runtime names it when it does, which is how this list was
  built and how it can be extended.
- **One transient `s9c` failure** was observed immediately after applying the
  change and did not reproduce in six subsequent runs. The failing assertion was
  not captured. `s9c` drives real `srt` launches and PATH resolution, so a timing
  flake is plausible, but it is unexplained rather than dismissed.

---

# S9e — the sandbox could not let a terminal be a terminal

Reported after S9c made the launch wrapper the default:

> `aegis run -- ~/.local/bin/claude`, then move the mouse. The prompt fills
> with `^[[<65;63;22M`. Running the client directly never does it.

An earlier pass dismissed this as unrelated to the sandbox, on two grounds that
were both wrong. "Startup captures with the network open and closed were
identical" — true, and irrelevant. "It emits `?1004h` but never `?1006h`" —
simply a bad capture; the client emits 1000, 1002, 1003 and 1006 every time.
`^[[<65;63;22M` is SGR mouse reporting and cannot appear unless 1006 was
enabled, which is exactly the argument that reopened this.

## Not the spawn, and a pty proxy would not have helped

`cli.py` runs `subprocess.Popen(wrapped, env=child_env)` with no stdio
redirection at all, so the child inherits the real terminal. Measured through a
real pty made a controlling terminal with `TIOCSCTTY`:

| | direct | `aegis run` | `srt` alone |
|---|---|---|---|
| `isatty(0)` | true | true | true |
| tty device | `/dev/ttys001` | `/dev/ttys001` | `/dev/ttys001` |
| `tcgetpgrp` | `12555` | **EPERM** | **EPERM** |
| `tcsetattr(raw)` | applied | **EPERM** | **EPERM** |
| `stty -a` | full output | *(nothing)* | *(nothing)* |

`aegis run` and `srt` alone are identical, so nothing `aegis run` does to the
process it spawns is implicated. And it is EPERM, not ENOTTY: a job-control
problem produces SIGTTOU or EIO, never EPERM. Allocating and proxying a pty
would have changed nothing, because the child's `tcsetattr` would then be made
on the proxy pty and refused for the same reason.

## The cause

```
$ srt -s <profile> -c 'stty -a'
stty: TIOCGETD: Operation not permitted
```

reproduced outside `srt` entirely by handing `sandbox-exec` a profile that
refuses ioctl. The runtime emits its pty rules — pseudo-tty access plus ioctl
and read/write on `/dev/ptmx` and `/dev/ttys*` — only when `allowPty` is set,
and `allowPty` is an optional **top-level boolean of the settings document
aegis/sandbox.py generates**. Aegis never set it.

So the whole chain: enabling mouse reporting is *output*, which the sandbox
never restricted; entering raw mode is an *ioctl*, which it did. The client
asks the terminal to report mouse movement and is then unable to enter a mode
where it can consume the reports. The tty driver, left in canonical+echo,
echoes them into the input line as text. Node's `setRawMode` failure is
swallowed by Ink, so there is no error anywhere — which is why this read as a
terminal problem rather than a sandbox setting.

Nothing appears in the macOS unified log either: a `log stream` filtered on
`Sandbox:` recorded zero denials across the whole window. This class of failure
is invisible to `aegis/violations.py` as well as to the user.

## The fix

A `sandbox_pty` policy key, default true, emitted as `allowPty`. A policy key
rather than `os.isatty()` at launch, on purpose: a document that varied with the
caller's terminal would have an unstable digest, and `aegis doctor` compares
that digest to decide whether the kernel is enforcing the current rules. It
would flap between a terminal and a piped run.

`aegis run` warns when the grant is off and it is attached to a terminal, and
`doctor` reports the state either way — because "your TUI will be broken" was
invisible until it bit.

## What it costs

Every S9 §3 kernel claim, re-run under the same policy with the grant off and
on — ssh key, `.env`, write outside roots, `policy.json`, network — behaves
identically. The `filesystem` and `network` sections of the two documents are
byte-identical and `allowPty` is the only key that differs; both asserted.

It is still a real capability: a process inside can open another terminal owned
by the same user. An unsandboxed agent could already do that, so this declines
to add a protection rather than removing one. That is a distinction, not an
absence, and the docstring says so.

## The test that would have caught it

`tests/s9.py` §3b allocates a real pty, makes it a controlling terminal with
`TIOCSCTTY`, and asks a child inside the sandbox whether it can enter raw mode.
Then it turns `sandbox_pty` off and asserts **the bug comes back, with EPERM
and an `isatty` that is still true** — a test that only proves the fixed state
cannot tell you the fix is what did it. Every kernel denial is re-run under the
granting profile in the same section.

Without a pty a suite cannot see this class of bug at all, which is why every
prior run was green.

While writing it, one check overwrote the lab's `policy.json`: `establish()`
writes to a single profile path, so two `Sandbox` objects alias the same file
and the last one written wins. The suite caught it, and it now asserts the lab
policy is intact after the check that is supposed to fail.

## Suites

| | before | after |
|---|---|---|
| s9 | 116 / 0 | **135 / 0** |
| s9c | 61 / 1 | 61 / 1 |

`s7` 141, `s10` 86, `s3a` 99, `s5` 80 (1 NOT RUN, the pre-existing manual pty
approval test), `s8` 109 — all 0 failed.

## A separate finding, recorded because it was measured here

`s9c`'s one failure is `labguard` reporting that the operator's real
`audit.db-wal` changed. The cause is not the suite. The violations observer
reads the **machine-wide** unified log and attributes a denial to the running
session whenever the denied path matches a deny pattern in that session's
profile; it does not check process ancestry. So one open `aegis run` session
records denials caused by entirely different sessions.

Measured: with one `aegis run -- claude` open, running `tests/s9.py` added ten
rows to the operator's real `audit.db`, carrying paths inside the test suite's
lab directory.

The row's claim — "a path this policy denies was denied by the kernel" — is
true. The implied claim, that this session's agent did it, is not established.
An earlier report called this a transient flake; that was wrong. Filed rather
than fixed in passing: it changes what the audit log means and deserves its own
sprint.

## Still open

- That every TUI is now correct under `aegis run`. What is established is that
  raw mode can be entered, which is the precondition all of them need.
- Linux. The rules measured here are Seatbelt's; the bubblewrap path was not
  tested on this machine.

---

# S9f — the client could not write its own state

Reported with S9d and S9e both in and working — the TUI renders, the terminal
is controllable, `api.anthropic.com` is reachable:

    API Error: 401 OAuth access token has expired
    Transcript writes are failing (permission denied — EPERM)
    /rc failed

The sandbox grants write access to the workspace roots, the Aegis data
directory and `/tmp`. A client's own state directory is none of those. So a
client routed through the S9c wrapper started, rendered, reached the API — and
then failed every request.

## Measured, and the control run first this time

The same client in the same directory with no sandbox at all had none of the
three symptoms and answered normally. That control is what separates "the
sandbox breaks it" from "the login is stale", and the first passes of this
investigation would have been misread without it.

Kernel refusals, read from the same unified log `violations.py` uses. One trap
cost a wasted pass: the binary is `~/.local/share/claude/versions/2.1.258`, so
the **process is named `2.1.258`** and a filter on `claude` finds nothing.

```
8x  file-write-create  ~/.claude/.oauth_refresh.lock     ← the 401
2x  file-write-create  ~/.claude/projects/<slug>         ← transcript EPERM
1x  file-write-mode    ~/.claude/sessions
7x  file-write-create  ~/.claude.json.lock
1x  network-bind       /private/tmp/cc-socks/<pid>.sock
```

| grant | 401 | transcript | /rc |
|---|---|---|---|
| unsandboxed control | no | no | no |
| today | **YES** | **YES** | **YES** |
| `~/.claude` alone | no | no | no |

`~/.claude` alone clears all three. `/rc` was failing **downstream of the
401** — the socket bind is still refused in the passing runs and remote control
works anyway, so no unix-socket grant is needed. `~/.claude.json` is not needed
either: its lock and temp siblings sit **directly in `$HOME`**, so granting it
would take a pattern in the home directory. The cost of leaving it out is that
what the client stores there does not persist between sandboxed launches, and
naming that cost is better than widening the grant to remove it.

## The fix, and the half that makes it defensible

`sandbox_state_paths` grants the directories; `sandbox_state_protect` carves
files back out of the grant. Both are read only by `sandbox.py`. `aegis init`
writes both from one measured table in `launcher.py`, showing each path with
what it is for.

`~/.claude` holds state, and it also holds two things that are not state:

| path | why it may not be writable |
|---|---|
| `settings.json` | can define **hooks** — shell commands the client runs. Write access is arbitrary code execution *outside* the sandbox at the next launch |
| `plugins/` | executable plugin code, same reasoning |
| `.credentials.json` | the OAuth token itself, on installs that do not use the Keychain |

`denyWrite` beats `allowWrite` in the runtime, and that was verified rather
than taken from the documentation — with the files created *outside* the
sandbox first, so the test is not trivially satisfied by their absence. A shell
inside cannot create, append to, truncate, delete or rename any of them;
contents byte-identical afterwards; ordinary state files in the same directory
stay writable.

**The home directory cannot be granted.** `Policy` raises rather than loading a
`sandbox_state_paths` naming `~` or `/`, and patterns are refused in both keys.
The grant can only ever be a directory somebody can read off the page.

## Where the credentials actually are

`~/.claude.json`'s `oauthAccount` is account **metadata** — email, display
name, org UUID, billing tier. Every string value in the file was scanned for
token shapes; the only long opaque values are `userID` and `machineID`, which
are identifiers. The token itself is in the **macOS Keychain** on this machine
(`Claude Code-credentials`; existence checked, value never read).
`~/.claude/.credentials.json` is absent here but is the documented location
where the Keychain is not used, and `~/.claude/sessions/*.key` exists at 0600.

## The residual, stated rather than elided — THREAT-MODEL.md §7.11

- The grant is **not client-specific**. The sandbox cannot tell the client's
  write from its Bash tool's, exactly as it cannot tell their network requests
  apart. Anything in the tree can write the granted directories, including the
  session's own transcripts.
- **Reading is not restricted and could not be** — the client must read its own
  settings and credentials to start. This is not new: read has been
  allow-by-default in this runtime since S9, so the agent could already read
  that directory before S9f granted writes to it. **S9f adds modification, not
  exposure.**
- An install keeping its token in a file rather than the Keychain therefore has
  that file readable by the sandboxed tree. Aegis does not change that; listing
  it in `deny_paths` closes it, at the cost of the client being unable to
  authenticate.

## doctor

A **FAIL** for wrapper-installed-with-no-state-granted, quoting the 401 and the
EPERM the user actually sees — neither of which looks like an Aegis problem,
which is the whole reason the check exists. And a **WARN** rather than PASS when
paths are granted with nothing protected: an empty `sandbox_state_protect` is
the dangerous configuration, not a neutral one.

## Suites

| | before | after |
|---|---|---|
| s9 | 135 / 0 | **167 / 0** |
| s9c | 61 / 1 | 61 / 1 |

`s7` 141, `s10` 86, `s3a` 99, `s5` 80 (1 NOT RUN, pre-existing), `s8` 109 — all
0 failed. The s9c failure is the machine-wide observer trip documented in S9e,
caused by an open `aegis run` session, not by this change.

`tests/s9.py` §3c drives the granting profile at the kernel: the state file is
written, `settings.json` survives append, truncate, delete and rename, the
plugins directory refuses new code, a credentials file cannot be created — and
reading `settings.json` still works, asserted deliberately so the residual
cannot change without someone noticing.

## Still open

- That `~/.claude` is sufficient for every Claude Code feature. It is
  sufficient for session start, token refresh, transcripts and remote control,
  measured. Anything not exercised in those runs may need something else; the
  kernel names it when it does.
- cursor, windsurf and cline. Not measured; they get an empty list and a
  sentence, the same rule as the endpoint table.
- Linux. These are Seatbelt denials.

---

# S9g — the denial notices made the session unreadable

Reported once S9d/S9e/S9f had made a wrapped client actually work:

> every `[aegis] kernel denied file-read-metadata ...` line is drawn on top of
> the TUI's own output, interleaving mid-line. A single denied file can emit
> dozens of these during one turn.

`aegis run` printed one line per denial to stderr while the child ran. Against
a batch command that is exactly right — it is how S9b made the kernel boundary
visible at all. Against a full-screen client it is unusable: the client owns
the alternate screen and repaints continuously, so each line lands mid-frame,
and both the client and the notices become unreadable.

## The fix is display only

**Nothing about what is recorded changes.** The audit write happens first and
unconditionally; the display decision is consulted afterwards and cannot skip
it. `tests/s9.py` asserts a quiet run and a verbose run over the same script
produce **identical `sandbox_denied` rows**, because that is the property the
change had to preserve and the one that would be easiest to break by accident.

Per-denial lines are suppressed only when both `stderr` and `stdin` are
terminals:

| | |
|---|---|
| `stderr` is not a tty | output is piped or redirected; nothing to interleave with. Stream, as before. |
| `stdin` is not a tty | the child cannot be a full-screen client — one needs a terminal to read keys from. Stream. |
| both are ttys | a human is sitting in front of a program that may be drawing on this screen. Write to the file. |

So pipelines, CI and `aegis run … 2>log` behave exactly as they did.
`--verbose-denials`, or `AEGIS_VERBOSE_DENIALS=1`, forces streaming back on: it
was genuinely useful for debugging and is not being taken away.

The startup banner and the exit summary stay. The banner gains one line naming
the file, said once before the child takes the screen — without it the file is
a place nobody knows to look — and the summary says how many lines were held
back.

```
[aegis] Kernel denials go to the audit log and to …/denials.log — this is an
        interactive terminal, so they are not printed here where they would
        land on top of your client. `tail -f` that file, or use --verbose-denials.
done
[aegis] 6 kernel denial(s) recorded; 3 other sandbox denial(s) seen but not attributable…
[aegis] 6 denial line(s) were written to …/denials.log rather than to this terminal.
```

## The file

`DenialLog` in `violations.py`: append-only, 0600, timestamped, size-rotated at
1 MB keeping three old files, at `<data dir>/denials.log` with
`AEGIS_DENIAL_LOG` as an override.

It **never raises at the caller**. A logging failure must not end a sandboxed
session — the session is the thing with value, and the audit database has
already recorded the denial by the time this is reached. The first failure is
remembered so the exit summary can say the file is incomplete, rather than
letting an empty file imply nothing happened.

It is documented as a convenience for tailing and explicitly **not** evidence:
not hash-chained, and a copy of what the audit log already holds. Describing it
as a record would be a second source of truth that nothing verifies.

## Suites

| | before | after |
|---|---|---|
| s9 | 167 / 0 | **187 / 0** |
| s9c | 61 / 1 | 61 / 1 |

`s10` 86, `s5` 80 (1 NOT RUN, pre-existing) — 0 failed. The s9c failure is the
machine-wide observer trip documented in S9e.

The twenty new checks include a real-pty block: `aegis run` on an actual
terminal, asserting the rows are still recorded, the lines are not on screen,
the banner and summary still print, and that the flag and the environment
variable each restore streaming. **A captured-pipe test cannot see this bug at
all** — `isatty()` answers "no" to a pipe — which is why the suite was green
while the terminal was unusable. Same shape as S9e: the harness could not
produce the condition the bug needs.

## Still open

- The rotation is size-based and unconditional. A session that denies enough to
  roll the file three times loses the oldest lines; the audit log still has
  every one of them, which is why that is acceptable.
- Nothing tails the file for the user. `tail -f` is named in the banner rather
  than wrapped in a subcommand.

---

# S9h — two places the recommended flow stopped short

Neither is a security defect. Both are the difference between a control that
exists and a control that is on.

## 1. The PATH line was left as homework

`aegis init` wrote the launch wrappers and then printed *"add this line to your
shell rc"*. Most people do not, `aegis doctor` then correctly reports the client
as unsandboxed, and the whole flow ends one manual edit short of working. The
work was done; the step that makes any of it take effect was handed back.

It is now offered, in the shape every other write here uses — show the exact
file, show the exact bytes, ask, back up first — plus one rule this file needs
on its own: **never write it twice**.

`launcher.py` picks the file the shell actually reads:

| shell | file | note |
|---|---|---|
| zsh | `~/.zshrc` | |
| bash | `~/.bash_profile` on macOS if it exists, else `~/.bashrc` | a macOS Terminal tab is a **login** shell and never reads `.bashrc`; writing there produces a line that is never executed |
| fish | `~/.config/fish/config.fish` | and different syntax — `set -gx PATH "…" $PATH`, because fish cannot parse an `export` |
| anything else | `~/.profile` | which every POSIX shell reads |

Idempotence is checked **by directory, not by matching Aegis's own line**. A
user who wrote their own export, or who ran `aegis shell-init` — whose shim
contains the same PATH line — has already done this, and appending a second copy
would be Aegis adding noise to a file it does not own.

### Two things the first draft got wrong

**It would have edited the operator's real shell rc from the test suite.** The
confirm defaulted to True and `--wrap-clients` reached it, so
`aegis init --yes --wrap-clients` appended to `~/.zshrc`. `tests/s9c.py` does
not fake `HOME`, and labguard does not watch rc files, so nothing would have
caught it. The confirm now defaults to **False** and the append needs its own
flag, `--path-line`. `_offer_launch_wrapping` already defaults its own confirm
to False because "installing a launch wrapper is not something to do to
someone's machine on a default"; a shell rc is more personal than that, so it
does not ride on `--wrap-clients`. The suite asserts a bare
`--yes --wrap-clients` leaves the file byte-identical.

**It offered only to someone installing a wrapper for the first time.** The
gate was `installed`, so a user re-running `aegis init` because their client is
still unsandboxed — a wrapper that already exists, therefore "unchanged" —
never saw the offer. That is the one person who needs it. Now gated on
`covered`, the same correction S9d and S9f each needed for the same reason.

### What uninstall does with it

Nothing, deliberately. `aegis uninstall` restores MCP configuration and the
wrappers it wrote; restoring a whole shell rc from a backup would revert
unrelated edits the user has made since, which is the destructive-by-surprise
behaviour this codebase refuses elsewhere. The line is marker-anchored and the
init output says removal is manual.

## 2. A clean install reported FAIL

`aegis doctor` reported **FAIL** for "MCP configuration points at the proxy"
when no MCP server was configured at all. That is an ordinary state — somebody
who wants the kernel sandbox and no MCP mediation has nothing to route — and a
red FAIL on a clean install reads as broken software, which is how people learn
to ignore the report.

The distinction that matters is between **having nothing** and **having
something unprotected**:

| state | before | after |
|---|---|---|
| no server configured anywhere | FAIL | **SKIP**, with one sentence saying the OS sandbox still applies and does not depend on MCP |
| a config file exists with no servers in it | FAIL | **SKIP** — same state |
| servers configured, none through Aegis | FAIL | FAIL, unchanged |

The test is on **servers, not config files**: a `.mcp.json` containing an empty
`mcpServers` is "nothing to route", not a broken install. The PROOF check
follows the same split — no server to probe is a SKIP saying it proves nothing
about a layer you are not using, while a server that exists and is not wrapped
stays a FAIL, because its tool calls are unmediated and unrecorded.

A clean sandbox-only install now ends with "All checks passed."

## Suites

| | before | after |
|---|---|---|
| s9 | 187 / 0 | 187 / 0 |
| s9c | 62 / 0 | **96 / 0** |

`s7` 141, `s10` 86 — 0 failed. No deny list is touched; neither change goes near
profile generation.

Note that s9c's baseline is 62/0 here rather than the 61/1 of the previous three
sprints. The difference is that no `aegis run` session was open during this run,
which confirms the S9e diagnosis of that failure: the violations observer is
machine-wide and records other sessions' denials into the operator's real audit
log. It remains filed and unfixed.

## Still open

- The PATH line is offered only when a wrapper is present and the directory is
  not already reachable. A user who declines is told how to do it by hand, and
  nothing asks again on a later run.
- `aegis uninstall` leaves the line. Marker-anchored removal would be safe to
  add; restoring the file would not.

---

# S9i — the MCP layer verified end to end, and what that exposed

Half the architecture had never been exercised outside the test suite.
`aegis doctor` had always reported *"PROOF: a real tool call is denied and
recorded"* as **not attempted**, because no MCP server was ever configured in a
real project. The policy proxy — C1 and C2, the thing that mediates MCP tool
calls — was unproven on a real installation.

It is now. A genuine `@modelcontextprotocol/server-filesystem` was configured in
a test project, routed through `aegis proxy` by `aegis init`, and driven.
Full capture in `evidence/S9i-mcp-end-to-end.txt`.

## The proxy works

**PROOF passes**, for the first time:

```
[  ok  ] PROOF: a real tool call is denied and recorded
           it answered: AEGIS DENIED
           audit row 1 appeared (was 0): tool=read_text_file effect=deny rule=deny_paths
           the chain still verifies with that row in it
```

**The refusal is the proxy's**, established by discrimination rather than
assertion. doctor's probe uses a path outside the filesystem server's own root,
which that server would refuse by itself — so the probe alone cannot tell the
two apart. The discriminator is a path *inside* the server's allowed root that
only the policy denies, driven over raw JSON-RPC with no client and no model:

| | `<project>/.env` |
|---|---|
| direct to the server | `allowed: TOKEN=proof-env-secret` |
| through `aegis proxy` | `AEGIS DENIED … Reason: path matches deny rule '.env'` |

The server reads it happily; only the proxy refuses. A benign file passes
through the proxy unchanged, so it is not simply blocking everything.

**The two denial kinds are distinguishable** in one verifying chain:
`tool=read_text_file rule_id=deny_paths` for the proxy, `tool=sandbox:cat
rule_id=sandbox_denied` for the kernel, with different language in the reason.

## What that exposed

```
[  ok  ] MCP configuration points at the proxy
[  ok  ] No client is still running the old wiring
[  ok  ] PROOF: a real tool call is denied and recorded

$ claude mcp list
filesystem: … -m aegis.proxy -- npx … - Pending approval (run `claude` to approve)
```

The client had never connected. **Nothing was being mediated, and the report
said everything was fine.** Both green checks were green for the wrong reason:

- **PROOF launches the server itself.** It proves the proxy works when run. It
  says nothing about whether the client is using it — there is no client in
  that test.
- **"No client is still running the old wiring"** looks for a process running
  the *unwrapped* command. A server nobody launched is not running at all, so it
  passes **vacuously** — the strongest possible pass for the weakest possible
  reason.

The cause is reasonable behaviour on the client's side: Claude Code holds
project-scoped `.mcp.json` servers at "Pending approval" until accepted, since
a repository should not be able to run arbitrary commands. `aegis init` changes
the command, so a server approved before may need approving again.

## The fix: routed is not connected

`_check_server_live` asks whether a process matching the routed server is
actually running behind a proxy right now — resolution, not configuration. The
same evidence class S9c settled on for the launch wrapper: a wrapper nobody's
PATH reaches is a file, and a server config nobody's client launched is a file
too.

| state | status |
|---|---|
| server running behind the proxy | **PASS** — the only state actually proven |
| routed, not running, a client *is* running | **WARN**, naming approval and restart |
| routed, not running, no client running | SKIP — nothing could have connected |
| nothing routed here | SKIP |
| process table unreadable | WARN |

WARN and not FAIL because `.mcp.json` is project-scoped: a user whose client has
a *different* project open is in a completely ordinary state, and a red FAIL
there is the S9h mistake repeated. The wording says that first, then the real
causes.

## A bug in the fix, recorded because it was measured

The first version reused `CLIENT_HINTS` to answer "is a client running?" and
reported **`CursorUIViewService`** — an Apple input-method helper with nothing
to do with the Cursor editor. `CLIENT_HINTS` is a loose substring match, right
where it is used (walking the ancestry of a process already known to be a
server) and wrong across the whole process table.

Client detection now matches the executable path in the three shapes a client
actually takes: an app bundle, a binary on PATH, and the CLI's
**version-numbered** binary (`~/.local/share/claude/versions/2.1.258`) — whose
basename is a number, which is why an obvious filter on "claude" finds nothing.
The same trap S9f hit when a process filter missed every denial.

## Suites

| | before | after |
|---|---|---|
| s9 | 187 / 0 | 187 / 0 |
| s9c | 96 / 0 | **115 / 0** |

`s7` 141, `s10` 86 — 0 failed. The new checks stub the process table, so all
five branches are deterministic rather than depending on what happens to be
running on the machine.

## Still open

- **A real client session, with the server approved and connected, denying a
  tool call end to end.** The server was left at "Pending approval": accepting
  it writes a project entry into the operator's `~/.claude.json`, and every
  claim above was provable without it. The raw JSON-RPC test is stronger
  evidence anyway — it removes the client and the model, the two things that
  could otherwise have done the refusing.
- **Other MCP clients.** Only Claude Code's approval behaviour was observed.
- **The fingerprint match can miss.** It is the same heuristic
  `_check_stale_clients` uses and is described as one.

---

# S9j — whose denial is this?

Filed across S9e, S9h and S9i and left unfixed each time: the violations
observer reads the **machine-wide** unified log, so a running `aegis run`
session recorded kernel denials caused by other processes as its own.

Since S9b a line became a `sandbox_denied` row whenever its path matched a deny
pattern in this session's profile. Nothing checked that this session's process
tree was what the kernel refused. The row's claim — *a path this policy denies
was denied by the kernel* — was true. The implied claim, *this session's agent
did it*, was never established. For a product whose central claim is a
tamper-evident audit log, that is the wrong kind of imprecision, and it is about
to be cited as evidence.

Full capture: `evidence/S9j-denial-attribution.txt`.

## Reproduced

Session A runs `bash -c 'sleep 22'` and touches nothing. Session B is a separate
sandbox reading a denied ssh key. A's audit log gains a `sandbox_denied` row for
a file A never went near.

## Pid ancestry does not work, measured before building anything

The obvious idea — the line carries a pid, `aegis run` knows the pid it
launched, walk between them:

```
the sandboxed command finished 0.10s after it started
the denied process was pid 10531
still in the process table ~6s later (when the observer drains)? False
```

The line had not reached `log stream` before the process exited. Every
short-lived denial — `cat`, `curl`, an interpreter startup, which is most of
them — would be unattributable, and pid reuse makes the residual worse rather
than better. Rejected on evidence.

## The anchor that was already in the log

The runtime tags every rule it emits, and macOS prints that tag on its own line
directly after the violation:

```
Sandbox: cat(10178) deny(1) file-read-data /…/.ssh/id_rsa
CMD64_Y2F0IC9wcml2YXRl…_END__srv5ti0e3_SBX
```

The base64 is the sandboxed command — a string Aegis computes, because Aegis
chose it. Measured: `--style compact`, which `violations.py` already uses,
carries it (so this is a parser change, not a capture change); the pairing is a
strict `vTvTvT…` alternation; denials from outside any sandbox-runtime session
carry no tag; and **two concurrent sandboxes denying the same file produce
different tags** — the bug and its discriminator in one capture.

## Two bugs found while building it

**The runtime was silently rewriting the command.** `srt` has its own `-c` flag
and parses options anywhere on the line, so `aegis run -- bash -c '<script>'`
was read as the *runtime's* `-c`: `bash` was dropped and the script ran under
the runtime's own shell. It worked, which is why nothing noticed — but the
process tree was not the one the operator asked for. `Sandbox.wrap()` now emits
`--` first, which is a correctness fix independent of attribution and is what
makes the recorded command equal the command.

**The first attempt was worse than the bug.** A plain space-joined prefix
classified the session's *own* denials as foreign — two denied reads, zero rows.
Silently deleting real denials from a tamper-evident log is a far worse failure
than over-recording. The runtime shell-quotes its argv, so the prefix must too;
more importantly, that near miss is why the fix has a fail-safe.

## The fix

| condition | outcome |
|---|---|
| tag matches this session's prefix | `sandbox_denied` — same rule_id, same meaning, plus a guarantee it never carried |
| tag differs **and** this session has seen its own tag | counted as foreign, named in the closing row, **not recorded** |
| this session has **never** seen its own tag | `sandbox_denied_unattributed`, whose reason says it may be another sandbox's |

The third row is the fail-safe. A sandboxed process emits tagged benign denials
within moments of starting, so the prefix is normally proven before the first
interesting denial; if it is not, Aegis will not discard on an unproven match.

```
BEFORE  rows attributed to A: 1   sandbox_denied  id_rsa
AFTER   rows attributed to A: 0   closing: "1 denial(s) … came from a DIFFERENT
                                   sandbox session and were not recorded here"
```

and the counter-check that matters as much: a session that reads two denied
files still records both, attributed by tag.

**The constraints.** The chain verifies in every case tested. No existing row
silently changes meaning: `sandbox_denied` keeps its meaning and gains a
guarantee, unattributable rows get their own rule_id, and the
`sandbox_established` row now states which regime was in force — so a reader can
tell what a row in that session means without knowing which version wrote it.

## Suites

| | before | after |
|---|---|---|
| s9 | 187 / 0 | **210 / 0** |
| s9c | 115 / 0 | 115 / 0 |

`s7` 141, `s10` 86, `s5` 80 (1 NOT RUN, pre-existing) — 0 failed. The 23 new
checks include a live regression: a real `aegis run` that touches nothing, with
a real second sandbox denying a file while it is open.

**One s9c run reported 113/2 immediately after applying**, and did not reproduce
in six subsequent runs including the same batch order. The failing check names
were not captured. The operator's real audit log gained no rows during any run
today and verifies intact, so it was not the row-writing this sprint fixes.
Recorded as unexplained rather than dismissed — the same discipline S9e's
"transient flake" should have had, since that one turned out to be real.

## Still open

- **The tag encodes the command truncated to 100 characters.** Two concurrent
  sessions whose commands agree in their first 100 characters are still mutually
  attributable. Far narrower than "any two sessions", not zero. This belongs in
  any public writeup that cites the log.
- **The suffix is not checked, only the command prefix.** Two concurrent
  `aegis run` invocations of the *same* command attribute each other's denials.
  Both are honestly "an aegis run of this command denied this path"; neither is
  "this process tree".
- **Attribution depends on the runtime's tag format.** A runtime that stops
  tagging turns every row into the fail-safe's unattributed form — visible in
  the closing summary rather than silent, but a precision regression Aegis
  cannot prevent.
- **Attribution is not integrity.** `audit.db` is still writable from inside the
  sandbox (S2 gap 1, §The data directory is writable).
