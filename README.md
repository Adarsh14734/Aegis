# Aegis

An MCP-layer policy proxy for AI coding agents. It sits between your agent and
one MCP server, decides every `tools/call` against a policy file the agent
cannot reach, and appends each decision to a hash-chained audit log.

**Read [THREAT-MODEL.md](THREAT-MODEL.md) before you rely on it**, especially
§7, which lists what Aegis does not protect against. The short version is at the
bottom of this file and `aegis doctor` prints it every time it runs.

Aegis has not been reviewed by anyone but its author, has no security audit and
no compliance certification. It is not suitable for regulated or enterprise
production use, and must not be described that way.

---

## Install

Aegis needs **Python 3.10 or newer**. On macOS, `/usr/bin/python3` is the
Command Line Tools shim and is 3.9 — new enough for many things and not for
this. Anything older is refused with a sentence saying so, never a traceback.

```bash
pip install aegis-mcp
```

The desktop app finds its own interpreter: it probes `python3`, `python3.10`
through `python3.14`, Homebrew, `/Library/Frameworks/Python.framework` and
pyenv, and uses the first that meets the minimum — because an app launched from
the Dock inherits `PATH=/usr/bin:/bin:/usr/sbin:/sbin` and would otherwise find
only the 3.9 shim. Set `AEGIS_PYTHON` to a full path to override the choice.

Credential storage is optional and off by default:

```bash
pip install 'aegis-mcp[keyring]'
```

Without it, everything works except `${aegis:...}` credential handles, which are
**denied** rather than passed through unprotected.

## Set up

Run this in the project directory your agent works in:

```bash
aegis init
```

It asks two questions — which folders the agent may work in, and which paths it
must never open — then writes a policy to your OS data directory at mode 0600
and offers to route the MCP servers it finds through the proxy. It shows a
unified diff of every file it is about to change and takes a backup first.

To script it:

```bash
aegis init --yes --workspace ~/code/myproject
```

## Prove it is actually working

```bash
aegis doctor
```

This is the command that matters. It does not read your config and tell you it
looks fine — it runs your configured server command exactly as your agent does,
speaks real MCP to it, asks it to open a file your policy forbids, and then
reopens the audit database to confirm a row appeared and the chain still
verifies. If the proxy is not in the pipe, `doctor` exits non-zero and says so.

**Restart your MCP client after `aegis init`.** A client starts its MCP servers
once, when it launches; editing the configuration afterwards does not move a
server that is already running. `aegis doctor` scans the process table for
servers running outside the proxy and fails if it finds one, but that is a
heuristic — it cannot see inside an already-running client. A green report and
an unmediated agent look identical from there.

## Confine the whole agent (optional, and the strongest part)

Everything above mediates one MCP pipe. `aegis run` puts the agent's **entire
process tree** inside an OS sandbox, so Bash, subprocesses, `npm install` and the
agent's own native file tools are constrained by the kernel:

```bash
npm install -g @anthropic-ai/sandbox-runtime   # the sandbox Aegis wraps
aegis run -- claude
```

Better, `aegis init` offers to route your client's own launch through it, so
typing `claude` starts it sandboxed and everything it spawns inherits that. It
asks — declining leaves the manual `aegis run` behaviour and `aegis doctor`
keeps warning. `aegis shell-init` prints a shell-only version.

Inside, `cat ~/.ssh/id_rsa` fails with `Operation not permitted`, a write outside
your workspace fails, and `curl` reaches only the domains your policy allows. The
profile is generated from `policy.json`, so there is one source of truth: a path
denied in policy is denied by the kernel.

If the sandbox cannot be established — wrong OS, runtime missing, profile
rejected — `aegis run` **refuses to launch**. It never falls back to running
unconfined.

Limits worth knowing before you rely on it. A wrapper is **advice, not
enforcement**: it is a PATH entry, so running the real binary's full path
bypasses it, a shell that never sourced the shim is unaffected, and a client
**already running** cannot be confined at all — that needs an Endpoint Security
entitlement Apple grants to registered organizations, which no `pip install` can
supply. A kernel escape defeats the whole thing
([THREAT-MODEL.md §7.6 and §7.7](THREAT-MODEL.md)). See [S9](S9-REPORT.md).

## Change what it may touch

```bash
aegis policy show
aegis policy set-folder ~/Robotics allow --confirm-grant
```

The desktop app has a Permissions screen for the same thing — folders reading
Allow / Ask / Deny, plus the never-open list, in sentences rather than JSON.

Granting access always asks first and names what is being granted; removing it
never does. Edits are refused outright if the audit chain does not verify, or if
the proxy would reject the result at startup. **Changes apply the next time your
agent starts** — a running proxy read the policy once, when it launched, and
`aegis doctor` tells you if one is still on the old copy.

## Undo it

```bash
aegis uninstall
```

Restores the MCP configuration from the backup. It deliberately leaves the audit
log and the policy where they are and tells you where that is — deleting an
audit trail on your behalf is the one thing a compromised setup would most want
to do.

---

## The other commands

| Command | What it does |
|---|---|
| `aegis proxy -- <server-cmd>` | Run the proxy. This is what `aegis init` writes into your config |
| `aegis run -- <agent-cmd>` | Launch an agent inside the OS sandbox (needs `srt`; refuses without it) |
| `aegis shell-init` | Print a shell snippet routing detected clients through the sandbox |
| `aegis policy show` / `set-folder` | Show or change what the agent may touch |
| `aegis-stop "reason"` | Kill switch: deny every tool call, starting with the next one |
| `aegis-resume` | Release it |
| `aegis-restore list` / `restore <id>` | Recover files copied aside before a destructive call |
| `aegis-secret set <name>` | Store a credential in the OS keychain (needs the `keyring` extra) |
| `python3 -m aegis.verify` | Verify the audit chain |

Verify the chain against a hash you wrote down somewhere else — the only check
that catches rows deleted off the end of the log:

```bash
python3 -m aegis.verify --expect-head <hash>
```

`verify.py` imports nothing from Aegis and carries its own independent copy of
the chain rule, so editing the code that writes the log cannot make forged rows
validate. The strongest way to run it is to copy that one file somewhere else
and run it directly — `python3 verify.py <path-to-audit.db>` — which is how you
check a log on a machine whose Aegis you no longer trust.

---

## What this does not cover

Aegis mediates tool calls that cross an MCP stdio pipe it was put in front of.
Outside that pipe it sees nothing:

- **Bash and every shell command**, and **native agent file tools**
  (Read/Write/Edit in Claude Code), *unless* you launch the agent with
  `aegis run` — that is what C11 is for. Without it, an agent running
  `cat ~/.ssh/id_rsa` never touches this proxy.
- **Agents started outside the wrapped path.** `aegis init` can route your
  client's launch through the sandbox, but the real binary's full path, an
  unsourced shell, and any process already running all escape it.
- **A kernel escape**, which defeats the sandbox and everything above it.
- **MCP servers not routed through the proxy**, and anything a downstream server
  does on its own. Aegis performs the requests for tools you mark `"egress"`,
  and controls those; it does not intercept requests it did not make.
- **Malware already on the machine, and anyone with root.** Both can edit the
  policy, the audit database and the head anchor.
- **Prompt injection as a phenomenon.** Aegis assumes injection succeeds and
  limits what the resulting instruction can reach.

[THREAT-MODEL.md §7](THREAT-MODEL.md) is the full list and it is longer than
this one.

## Sprint reports

Each control's verification tier, evidence and known gaps are in the sprint
reports: [S1](S1-REPORT.md) proxy · [S2](S2-REPORT.md) audit chain ·
[S3a](S3a-REPORT.md) / [S3b](S3b-REPORT.md) egress and DLP ·
[S4](S4-REPORT.md) credentials · [S5](S5-REPORT.md) approval, trash, kill
switch · [S6](S6-REPORT.md) desktop viewer · [S7](S7-REPORT.md) packaging and
onboarding · [S8](S8-REPORT.md) Aegis makes the request ·
[S9](S9-REPORT.md) the sandbox · [S10](S10-REPORT.md) the Permissions screen.
