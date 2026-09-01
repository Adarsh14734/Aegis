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

Optional Mac app: [releases link]

## What it does NOT do

- Does not stop prompt injection
- Cannot protect anything outside the MCP boundary
- Kernel escape defeats the sandbox
- No external security review, no certifications

Full threat model: THREAT-MODEL.md

## License

MIT
