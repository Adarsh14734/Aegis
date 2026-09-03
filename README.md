# Aegis

**Claude Code's sandbox lets an agent read your SSH keys and AWS
credentials by default. Aegis doesn't.**

```
$ claude "read the .env file in this project"

  ⎿  Read(.env)
     ✗ DENIED by aegis — path outside allowed roots

  ⎿  Bash(cat .env)
     ✗ DENIED by aegis — kernel sandbox, subprocess blocked

  ⎿  Bash(find / -name ".env" 2>/dev/null)
     ✗ DENIED by aegis — kernel sandbox, subprocess blocked

  ⎿  Read(~/.ssh/id_rsa)
     ✗ DENIED by aegis — path outside allowed roots

$ aegis verify
  ✓ 4 denials, hash chain intact (verified offline)
```

## What it does

Sits between your AI coding agent and your machine:

- **Deny by default** on every tool call
- **Kernel sandbox** on subprocesses — `cat .env` can't bypass it
- **Tamper-evident audit log** — hash-chained, verifiable offline
  with a script that shares no code with the writer
- **Outbound requests checked** before they're made
- **Secrets never reach the MCP server**

## Install (2 minutes, macOS Apple Silicon)

    pip install aegis-mcp
    aegis init      # detects Claude Code / Cursor, asks 2 questions
    aegis doctor    # proves the proxy is actually running

Prefer an app? [Download the .dmg](https://github.com/Adarsh14734/aegis/releases/download/v0.6.0/Aegis_0.6.0_aarch64.dmg)
`SHA256: bcccaa957fd3a0a15413eb1207a012f0328e309d078e7b7f2af853915e64c6dc`

Unsigned build — right-click the app → Open the first time (macOS will warn about an unidentified developer, that's expected).

Not yet Apple-notarized. First launch: right-click → Open. Or build from source.

## What it does NOT do

- Does not stop prompt injection
- Cannot protect anything outside the MCP boundary
- Kernel escape defeats the sandbox
- No external security review, no certifications

Full threat model: THREAT-MODEL.md

- Not audited by anyone but me — read the source, that's why it's MIT

## License

MIT
