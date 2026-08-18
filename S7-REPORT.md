# Aegis S7 — onboarding and packaging

**Sprint:** S7
**Date:** 2026-08-17
**Scope:** installation, setup and self-checking only. No new security control,
no change to the decision logic in `policy.py`.
**Goal:** a stranger installs Aegis in under five minutes without editing JSON
by hand.
**Status:** `aegis init` / `doctor` / `uninstall` **VERIFIED (harness, macOS)**;
`aegis doctor` additionally **VERIFIED (live, macOS)** against the real
installation and the real `@modelcontextprotocol/server-filesystem`, 2026-08-17.
Suite: **138 passed, 0 failed**, exit 0. Every prior suite unchanged.

---

## What was built

| File | Role |
|---|---|
| `pyproject.toml` | `aegis-mcp`, five console scripts, `keyring` as an optional extra, **zero runtime dependencies** |
| `aegis/__init__.py` | Makes `aegis/` a real package. Imports nothing; `import aegis` has no side effect |
| `aegis/cli.py` | `aegis init \| doctor \| uninstall \| proxy \| version` |
| `aegis/clients.py` | MCP client discovery, wrap/unwrap, diff-before-write, backup and restore |
| `aegis/onboard.py` | `aegis init` |
| `aegis/doctor.py` | `aegis doctor` — the command that proves rather than asserts |
| `aegis/policy.template.json` | Shipped defaults. Kept in agreement with `policy.example.json` by a test |
| `README.md` | Install → init → doctor, and §7 in short form |
| `tests/s7.py` | 138 checks against a fake `HOME` in a temp lab |
| `evidence/S7-suite.txt` | Suite output plus a regression run of every prior suite |
| `evidence/S7-cleanroom-install.txt` | Wheel built and installed into a fresh venv, on a machine with no Aegis state |
| `evidence/S7-doctor-unwired.txt` | The same install with the proxy removed from the pipe — doctor exits 1 |
| `evidence/S7-live-doctor.txt` | doctor on the real installation, real npx server, real audit chain |
| `evidence/S7-doctor-stale-client.txt` | correct config, real unwrapped server still running — doctor exits 1 |

Four existing files were touched. Three of them for import plumbing only, and
one message change:

| File | Change |
|---|---|
| `aegis/policy.py` | `import broker` → `from . import broker`, with a flat fallback. **No decision logic touched** — `git diff` is the import block and its comment |
| `aegis/proxy.py` | Same, for its five imports |
| `aegis/killswitch.py` | Same, for the function-level `audit` import |
| `aegis/broker.py` | New `keyring_available()`, and `aegis-secret` now says "keyring is not installed" instead of reporting every handle as `MISSING` |

---

## Packaging

```bash
pip install aegis-mcp            # aegis, aegis-secret, aegis-restore, aegis-stop, aegis-resume
pip install 'aegis-mcp[keyring]' # adds credential storage
```

**No runtime dependencies.** THREAT-MODEL.md B3 asks the trusted computing base
to stay small enough to audit by hand, and every dependency is code that runs
inside it. `keyring` is the one exception and it is opt-in.

`aegis-stop` and `aegis-resume` share one entry point, `aegis.killswitch:main`,
which dispatches on `argv[0]` — that was already how the `bin/` wrappers worked
in S5, so renaming either script changes its behaviour. The old `bin/` shell
wrappers still work and were left alone.

### The import change, and why it is not a rewrite

The modules imported each other flat (`import broker`), which works when
`aegis/` is on `sys.path` and fails as an installed package. Both forms now
work, via one try/except per import block:

```python
try:
    from . import broker, dlp, egress, killswitch
except ImportError:      # running aegis/proxy.py as a script
    import broker
    ...
```

The flat form has to keep working: **every `.mcp.json` written before S7 says
`python3 /path/aegis/proxy.py`**, including the one on this machine, and
breaking those would have made an upgrade silently disable the proxy. Both
paths are tested, and the live doctor run below goes through the old form.

### Keyring, absent

Verified in the clean-room venv, which genuinely has no keyring:

```
[ warn ] Credential storage (keyring)
           ModuleNotFoundError: No module named 'keyring'
           No credential handles are granted in policy, so nothing needs it today.
           Calls carrying a ${aegis:...} handle would be denied, not sent unprotected.
```

The import stays lazy and inside `broker.py`, so a missing library cannot break
proxy startup — checked by importing `aegis.policy` with `keyring` forced
missing. When policy *does* grant a handle, doctor makes it a **FAIL**, not a
warning: those calls will be denied and the operator should know before an
agent finds out for them.

One thing this fixed: `aegis-secret check <name>` used to print `MISSING` when
the library was absent, which sends the user hunting for a secret that was never
the problem. It now names the real cause and exits 1.

---

## `aegis init`

Two questions, then it writes. Non-interactive use is a first-class path
(`--yes --workspace ...`), because a setup command that only a human can drive
is a setup command nobody can test.

**It never overwrites without showing the change.** Every write goes through a
unified diff against the file's actual bytes — not against a re-parse of them,
so a whitespace-only reformat still shows up as a change, because it is one:

```
--- /private/tmp/.../proj/.mcp.json (now)
+++ /private/tmp/.../proj/.mcp.json (after aegis init)
@@ -1,8 +1,15 @@
     "mockfs": {
-      "command": "/tmp/.../venv/bin/python",
-      "args": ["/tmp/.../mock_fs_server.py", "/tmp/.../proj/workspace"]
+      "command": "/private/tmp/.../venv/bin/python",
+      "args": [
+        "-m",
+        "aegis.proxy",
+        "--",
+        "/tmp/.../venv/bin/python",
...
  backed up to /tmp/.../Aegis/backups/..._proj_.mcp.json.20260817-194310.bak
```

Detection covers `.mcp.json` in the project, `.cursor/mcp.json` (project and
user), `~/.claude.json` (top level and per-project), and Claude Desktop's
config. A file that exists but defines no servers is dropped rather than
offered — patching it would mean inviting the user to accept a server
definition Aegis invented. When nothing is found, init says which client
*settings* it did see, so "no MCP configuration" does not read as "no client
installed".

### The refusal

```
aegis init: REFUSING.
  the policy file would be /tmp/.../home/Library/Application Support/Aegis/policy.json
  which is inside the workspace root /tmp/.../home

  The agent can write everywhere inside a workspace root. A policy the agent
  can edit enforces nothing.
  Nothing has been written. Choose a workspace root that does not contain it,
  and run aegis init again.
```

`policy.py` already refuses to *start* in this state (S0 decision #2). Refusing
at write time turns "the proxy mysteriously will not start" into a sentence
explaining why, before anything lands on disk. The same refusal covers the trash
directory (an agent that can delete its own undo history has none) and the audit
database. Nothing overrides it — there is no `--force`.

Two more refusals, both because the alternative is silent: a workspace root
that does not exist is not created (a typo would otherwise grant access to a
directory nobody meant), and the assembled policy is passed through `Policy()`
before writing, so a policy that would not load is never written.

### How the proxy command is chosen

`-m aegis.proxy` pinned to `sys.executable` when that interpreter can import the
package **from a neutral cwd and with `PYTHONPATH` stripped**; otherwise the
absolute path to `proxy.py`. The strip matters: a shell exporting `PYTHONPATH`
would otherwise make init write a command that only starts inside that shell,
which is exactly the wiring bug doctor exists to catch — better not to write it.
The clean-room install produces the first form, the source checkout the second,
and doctor proved both.

---

## `aegis doctor` — the command that matters

Reading a config file and finding the word "aegis" in it proves that a config
file contains a string. So the last check runs the configured server command
exactly as the MCP client would, speaks real MCP to it, sends a real
`tools/call` for a path the policy forbids, and reopens the audit database:

```
[  ok  ] PROOF: a real tool call is denied and recorded
           server 'filesystem' from /Users/adarsh/code/aegis-testlab/.mcp.json
           ran: python3 /Users/adarsh/code/aegis/aegis/proxy.py -- npx -y @modelcontextprotocol/server-filesystem …
           asked it to open /Users/adarsh/.ssh/aegis-doctor-probe with the 'read_text_file'
             tool, which this policy otherwise allows
           it answered: AEGIS DENIED
           audit row 84 appeared (was 83): tool=read_text_file effect=deny rule=deny_paths
           the chain still verifies with that row in it
           The proxy is in the pipe. This is the only check here that shows that;
           every other one reads a file.
```

Four design points, each a place this could have been built to look good rather
than to be true:

**1. The probe tool is one the policy allows.** `read_text_file` is an *allow*
rule here, so the denial can only have come from the path check. An unknown tool
refused by default-deny would prove much less — a broken pipe can imitate that.
The tool and the expected `rule_id` are both derived by running the local policy
engine first, and the audit row must then cite the rule that was predicted. A
row that denies for a different reason is reported as a problem, not as a pass.

**2. The probe target is a file that does not exist.** `~/.ssh/aegis-doctor-probe`,
not `~/.ssh/id_rsa`. A check that reads a real secret to prove the secret cannot
be read is self-defeating.

**3. Doctor will not send the probe through an unwrapped server.** The structural
check gates the empirical one. A bare filesystem server would *execute* "read my
ssh directory", which is doctor performing the attack it is testing for. When
nothing is wired, the proof fails as "not attempted" and says why.

**4. It re-verifies the chain with the new row in it**, using `verify.py` as a
subprocess — the independent verifier from S2, not a third copy of the hash rule.

### A correct config is not a running proxy

An MCP client starts its servers **once, when it launches**. `aegis init` edits
the file those servers were launched from; it cannot reach into a process that
has already started. So a client left running across setup keeps talking to an
unwrapped server, and every check above — all of which read files — reports
green while nothing is mediated. That was gap 9 in the first draft of this
report, and it is now a check.

Doctor reads the process table and, for each configured server, looks for a
process matching its downstream command with **no Aegis proxy anywhere in its
ancestry**. Against the real installation, with the correct config untouched and
an unwrapped copy of the real filesystem server running
(`evidence/S7-doctor-stale-client.txt`):

```
[  ok  ] MCP configuration points at the proxy
           filesystem -> Aegis proxy   (/Users/adarsh/code/aegis-testlab/.mcp.json)
[ FAIL ] No client is still running the old wiring
           pid 3310 looks like the 'filesystem' server from …/.mcp.json,
             running with no Aegis proxy above it (launched by claude)
               npm exec @modelcontextprotocol/server-filesystem …/workspace
           pid 3330 …
               node …/node_modules/.bin/mcp-server-filesystem …/workspace
           QUIT AND REOPEN THAT APPLICATION. An MCP client starts its servers
           once, when it launches. … none of its tool calls are checked or
           recorded — however green everything above looks.
```

Every other check on that run is `ok`, including the wiring check, and doctor
exits 1.

Matching survives `npx` rewriting its own argv: the config says
`npx -y @modelcontextprotocol/server-filesystem <dir>` and the process that
actually runs is `node …/mcp-server-filesystem <dir>`. Fingerprinting drops
launchers (`npx`, `node`, `python3`, `sh`, `docker`, …) and reduces the rest to
last path segments, then requires two tokens to match where two exist — one
token alone matches the editor that has the folder open.

**It is a heuristic and says so.** `ps` can be restricted, a client can hold a
server whose command line resembles nothing in the config, and a server launched
in an unforeseen way will be missed. So a clean result is never reported as
proof, and **the restart instruction is printed on every run whatever the scan
found**:

```
+----------------------------------------------------------------------+
|  RESTART YOUR MCP CLIENT AFTER `aegis init`                           |
+----------------------------------------------------------------------+
A client starts its MCP servers once, when it launches. Changing the
configuration afterwards does not move a server that is already running.
Doctor checked the process table and saw nothing running outside a proxy,
but it cannot see inside an already-running client, and this check is a
heuristic. If you have not restarted the client since setup, do it now —
a green report and an unmediated agent look identical from here.
```

The banner switches to **RESTART REQUIRED** when something was detected. Both
forms are tested. False positives were checked against 566 real processes on
this machine: none, and doctor's own probe children are excluded by pid.

### Everything it checks

| Check | Fails when |
|---|---|
| Policy file exists and parses | `Policy.load` refuses it |
| Policy is outside every workspace root | (structural; `Policy.load` enforces it, doctor states it) |
| Audit database is writable | wrong mode, unopenable |
| Audit chain verifies | `verify.py` exits non-zero |
| Head anchor matches | anchor present and the chain fails; **warns** when absent |
| Credential storage (keyring) | policy grants handles and keyring is missing; **warns** otherwise |
| MCP configuration points at the proxy | no configured server is wrapped |
| **No client is still running the old wiring** | a process matching a configured server runs with no proxy above it; **warns** if `ps` cannot be read |
| **PROOF: a real tool call is denied and recorded** | no denial, no row, wrong row, or the chain breaks |

Exit is non-zero if any check FAILs. An empty audit log passes with a sentence
saying an empty chain is a valid chain — that is S2 gap 3, and it should not
read as a clean bill of health.

### What it prints that no other command does

`aegis doctor` ends with **WHAT THIS DOES NOT COVER** — Bash and every shell
command, the agent's native file tools, unwrapped MCP servers, whatever the
downstream server does on its own, root, and deleting the whole database. It
names the S1 live result directly: three of the model's four attempts on a
secret went through Bash and Aegis blocked none of them. THREAT-MODEL.md §7.6
has said this since S0, but §7 is a document a new user does not read and
`doctor` is a command they must run, so this is where it goes.

---

## `aegis uninstall`

Restores each MCP config from its backup, after showing the diff and verifying
the backup's SHA-256 against the digest recorded when it was taken — restoring a
corrupted backup over a working config would turn uninstall into the incident.

It leaves the audit database, the policy and the backups where they are, prints
all three paths, and says so:

> Aegis will not remove an audit trail on your behalf; that is the one action a
> compromised setup would most want to take.

Backups are tagged by kind, so uninstall restores MCP configuration only and can
never quietly revert a policy.

---

## Verification

**Tier: VERIFIED (harness, macOS)** per S1's definition — real hardware, real
subprocesses, real SQLite, raw output captured, driven by `tests/` rather than a
live model session — for `init`, `doctor` and `uninstall`.

**`aegis doctor`: VERIFIED (live, macOS), 2026-08-17.** Run against the real
installation: the real `policy.json` and `audit.db` in
`~/Library/Application Support/Aegis`, the real `aegis-testlab/.mcp.json` wired
since S1, and the real `@modelcontextprotocol/server-filesystem` launched by
`npx`. 83 rows before, 84 after, chain intact, exit 0
(`evidence/S7-live-doctor.txt`). This is one rung below S1/S2/S3's unqualified
VERIFIED, which needs a live *Claude Code* session with the client's own log
captured — doctor drives the chain itself rather than a model driving it.

| Suite | Result | Exit |
|---|---|---|
| `tests/s7.py` | **138 passed, 0 failed** | 0 |
| `tests/s5.py` | 80 passed, 0 failed, 1 NOT RUN | 1 |
| `tests/s4.py` | 65 passed, 0 failed, 2 NOT RUN | 1 |
| `tests/s3b.py` | 60/60 | 0 |
| `tests/s3a.py` | 99/99 | 0 |
| `tests/tamper.py` | 10/10 | 0 |

Every prior suite reports exactly its pre-S7 figure, which is the check that the
import change altered nothing.

### The four cases the brief named

| Case | Result |
|---|---|
| init on a machine with no prior config | policy written 0600 to the OS data dir, "MCP configuration found: none.", exit 0 |
| init where policy would land inside a workspace | **REFUSING**, exit non-zero, `policy.json` never created |
| doctor on a correct setup | exit 0, `AEGIS DENIED` returned, audit log grew by exactly one row, chain re-verified |
| **doctor with the proxy NOT wired in** | **exit 1.** Wiring check FAIL, proof FAIL "not attempted", **no audit row written**, and every file-reading check still PASSes — which is the point |
| doctor with a tampered chain | exit 1, "The record of what happened has been altered" |
| doctor with a correct config but a stale client | **exit 1**, names both matching pids and the app to restart, while every file check stays green |
| uninstall | config restored **byte for byte** (SHA-256 equality), audit db and policy still present with every row |

The unwired case is worth reading in `evidence/S7-doctor-unwired.txt`. Same
machine, same policy, same audit log as the passing run; the only change is that
`.mcp.json` no longer routes through Aegis. Policy, chain, anchor and keyring all
still report `ok`. **A doctor built out of file checks would have passed this
setup**, and the setup has no MCP-layer control at all.

The suite then proves the refusal was warranted: it sends the call doctor
declined to send directly to the unwrapped server, and the server executes it —
`EXECUTED-BY-BARE-SERVER` comes back, against a harmless file in the lab.

### The harness cannot reach the operator's state

Everything runs against a fake `HOME` inside a temp lab, so the default path
logic in `proxy.py` / `audit.py` / `clients.py` is exercised for real rather than
bypassed with `AEGIS_*` overrides — `aegis init` writes to the OS data directory,
and a test that redirected it with an environment variable would not be testing
what users run.

`_assert_real_state_untouched()` fingerprints the real `policy.json`, `audit.db`,
`KILLSWITCH`, `~/.mcp.json` and `~/.claude.json` before the first subprocess and
again at the end. This is the fourth sprint whose harness could have reached the
operator's real installation — S2's deleted audit row, S4's keychain, S5's kill
switch, and now a command whose entire job is writing to that directory.

### Not established by this sprint

- **A live Claude Code session driven through `aegis init`'s output.** doctor
  proves the pipe with doctor as the client. A model has not been pointed at a
  config `init` wrote.
- **Any client other than Claude Code.** Cursor and Claude Desktop config
  locations are *detected* and would be patched by the same code path, but
  nothing has been observed launching from them.
- **Linux and Windows.** `init` and `doctor` contain the XDG branches and
  nothing has run there. Note that on Linux the policy goes to
  `XDG_CONFIG_HOME/aegis` and the audit db to `XDG_DATA_HOME/aegis` — two
  different directories, inherited from S1/S2, untested together.
- **Publishing.** The wheel builds and installs from a local path. It has never
  been uploaded, and the name `aegis-mcp` is not claimed on PyPI.
- **Five minutes.** Not measured with a stranger. The clean-room transcript runs
  install → init → doctor in three commands, which is the shape of the claim,
  not evidence for it.

---

## Findings

### 1. `aegis-secret` reported the wrong cause when keyring was missing

`secret_exists()` returns False both when the library is absent and when the
handle is simply unset. That is the right answer for the substitution path —
neither can produce a secret — and the wrong thing to print at a person, who
would go looking for a handle that was never the problem. Fixed with
`keyring_available()` and a message that names the extra. The substitution path
is untouched.

### 2. A structural check can never be the proof, and it took writing doctor to see how far that goes

The first sketch of doctor checked eight things and ran nothing. Every one of
those checks passes on a machine where the proxy has been removed from the pipe
— demonstrated in `evidence/S7-doctor-unwired.txt`. The lesson generalises past
this command: **S6's approval bridge and S1's `policy.example.json` both failed
the same way**, by being correct on paper against something never executed.

### 3. `tests/s7.py` §3b is not mine

A section driving `aegis init` interactively over a real pty — typing answers,
reading prompts back, checking that a declined confirmation writes nothing —
appeared in `tests/s7.py` between two of my runs. It is not my work and I have
not claimed it. It passes, it is sandboxed the same way as the rest, and it
closes a real gap: every section I wrote uses `--yes`, which skips every
`input()` call in `onboard.py`, so the prompt code would have shipped never
having been typed at. Twelve of the 138 checks are that section.

---

## Known gaps (do not claim these are handled)

1. **`init` and `doctor` are not security controls and must not be described as
   any.** They configure and inspect controls that already existed. A passing
   `doctor` says the proxy is in one pipe; it says nothing about the other ways
   an agent reaches the disk.
2. **doctor's proof covers one server.** Where several are wired, only the first
   is probed; the rest are listed. A proxy correct for one and broken for another
   would pass.
3. **doctor writes to the real audit log.** One denied row per run, by design —
   it is a real decision honestly recorded — but a habit of running `doctor` in a
   loop pads the chain with rows nothing asked for.
4. **The wiring check trusts `is_wrapped()` to decide whether probing is safe.**
   A command crafted to look like an Aegis invocation but launch something else
   would get a probe sent through it. The probe is a read of a non-existent file,
   so the damage is bounded, but the gate is a string match.
5. **HTTP/SSE MCP servers cannot be wrapped at all.** `init` refuses them and
   says why. They stay outside the boundary, and doctor lists them as such.
6. **Reformatting.** Patching rewrites the whole config with `indent=2`. The diff
   shows it, and a backup precedes it, but comments in a JSONC-style config would
   not survive. Nothing warns about that specifically.
7. **`~/.claude.json` is rewritten wholesale if chosen.** It holds far more than
   MCP servers. The backup makes it recoverable; it is still a larger blast
   radius than `.mcp.json` and `init` does not say so more loudly than the diff.
8. **No `aegis upgrade`.** A `.mcp.json` written by an older Aegis keeps working
   (that is what the flat-import fallback is for), but nothing migrates it to the
   installed-package form.
9. **Stale-client detection is a process-table heuristic, not a guarantee.**
   Gap 9 in the first draft of this report — doctor reporting green while a
   client still ran the old wiring — is now a failing check with a live true
   positive behind it. What remains: `ps` may be restricted (reported as a
   warning, not a pass); a server launched in a way its configuration does not
   predict will be missed; a client that keeps an MCP server as an in-process
   thread rather than a child process is invisible to any process scan. The
   restart instruction is therefore printed on every run rather than only when
   something is found. Detection can also fire on a server a user is running by
   hand for their own reasons — a false alarm that costs a restart, chosen over
   a silence that costs the control.
10. **Still reviewed by nobody but its author.** THREAT-MODEL.md §10 is empty
    after eight sprints.

---

## Reproduce

```bash
python3 tests/s7.py
```

```bash
pip install -e . && aegis init --yes --workspace ~/code/some-project && aegis doctor
```

The one worth watching — break the wiring and confirm doctor notices:

```bash
python3 -c "import json,sys;p='.mcp.json';d=json.load(open(p));e=d['mcpServers']['filesystem'];a=e['args'];r=a[a.index('--')+1:];d['mcpServers']['filesystem']={'command':r[0],'args':r[1:]};open(p,'w').write(json.dumps(d,indent=2))" && aegis doctor; echo "exit $?"
```
