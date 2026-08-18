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

```bash
pip install aegis-mcp
```

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

- **Bash and every shell command.** An agent that runs `cat ~/.ssh/id_rsa` never
  touches this proxy.
- **Native agent file tools** (Read/Write/Edit in Claude Code) — same absence.
- **MCP servers not routed through the proxy**, and anything a downstream server
  does on its own.
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
onboarding.
