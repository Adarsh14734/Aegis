# Aegis

**Claude Code's sandbox lets an agent read your SSH keys and AWS credentials by default. Aegis doesn't.**

Two layers, both verified on real hardware.

Kernel sandbox — the agent's own shell cannot reach a denied path:

    $ ! cat ~/.ssh/id_rsa
    cat: /Users/adarsh/.ssh/id_rsa: Operation not permitted

    $ ! cat ~/.aws/credentials
    cat: /Users/adarsh/.aws/credentials: Operation not permitted

    $ tail ~/Library/Application\ Support/Aegis/denials.log
    kernel denied file-read-data /Users/adarsh/.ssh/id_rsa to cat(pid 41560)
    kernel denied file-read-data /Users/adarsh/.aws/credentials to cat(pid 42180)

MCP proxy — same tool, same file, with and without Aegis in front:

    direct to the server:   allowed: TOKEN=proof-env-secret
    through aegis proxy:    AEGIS DENIED: read_text_file
                            Reason: path matches deny rule '.env'
                            Rule: deny_paths

## What it does

Sits between your AI coding agent and your machine:

- **Deny by default** on every tool call
- **Kernel sandbox** on subprocesses — `cat .env` can't bypass it
- **Tamper-evident audit log** — hash-chained, integrity checked by `aegis doctor`
- **Outbound requests checked** before they're made
- **Secrets never reach the MCP server**

## Install (macOS Apple Silicon)

    pip install aegis-mcp
    aegis init      # detects Claude Code / Cursor, asks a few questions
    aegis doctor    # proves the boundary is actually in place

Prefer an app? [Download the .dmg](https://github.com/Adarsh14734/Aegis/releases/download/v0.6.0/Aegis_0.6.0_aarch64.dmg)

`SHA256: bcccaa957fd3a0a15413eb1207a012f0328e309d078e7b7f2af853915e64c6dc`

Unsigned build — right-click the app → Open the first time (macOS will warn about an unidentified developer, that's expected). Or build from source.

## What it does NOT do

- Does not stop prompt injection
- Kernel escape defeats the sandbox
- The audit database is still writable from inside the sandbox
- No external security review, no certifications
- Not audited by anyone but me — read the source, that's why it's MIT

Full threat model: THREAT-MODEL.md

## License

MIT