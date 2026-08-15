# Manual check: a human approving on a live proxy's terminal (S5 / C7)

`tests/s5.py` covers the prompt, the timeout, the answer parsing and the
resolver identity against a **real pty** (§3), and covers the no-terminal
denial end to end through the proxy (§4). What it does not cover is the two
halves joined: a running proxy, with pipes on stdin and stdout, prompting a
human on its controlling terminal and forwarding the call when they say yes.

## Why it is not automated

The proxy needs stdin and stdout for JSON-RPC, so a test cannot simply hand it
a pty for those. Giving a subprocess a *controlling* terminal separately —
`os.setsid()` then `TIOCSCTTY` on a pty slave in `preexec_fn`, with pipes still
on fds 0 and 1 — hung with no output on macOS 26.5.1 / Python 3.14.3 across
several attempts. Rather than ship a flaky test or a fake terminal, this is a
by-hand procedure and §3+§4 carry the automated coverage.

If someone gets the controlling-tty trick working reliably, fold it into
`tests/s5.py` §3 and delete this file.

## Procedure

Takes about two minutes. Run it in a real terminal window — that is the point.

**1. Scratch policy and workspace.**

```bash
mkdir -p /tmp/s5-manual/workspace /tmp/s5-manual/data && printf 'speed = 40\n' > /tmp/s5-manual/workspace/config.txt && cat > /tmp/s5-manual/policy.json <<'EOF'
{"version":1,"workspace_roots":["/tmp/s5-manual/workspace"],
 "default_effect":"deny","ask_behavior":"prompt","ask_timeout_seconds":30,
 "tool_rules":{"move_file":{"effect":"ask","within":["<workspace>"]}}}
EOF
chmod 600 /tmp/s5-manual/policy.json
```

**2. Send one ASK call through the proxy.**

```bash
AEGIS_POLICY=/tmp/s5-manual/policy.json AEGIS_AUDIT_DB=/tmp/s5-manual/data/audit.db python3 -c 'import json,subprocess,sys; print(subprocess.run([sys.executable,"aegis/proxy.py","--",sys.executable,"tests/mock_fs_server.py"],input=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"move_file","arguments":{"source":"/tmp/s5-manual/workspace/config.txt","destination":"/tmp/s5-manual/workspace/moved.txt"}}})+"\n",capture_output=True,text=True).stdout)'
```

**What to look for.** The prompt should appear **in your terminal**, not in the
command's captured output:

```
==================================================================
  AEGIS — approval required
==================================================================
  Tool:  move_file
  Files: /tmp/s5-manual/workspace/config.txt
         /tmp/s5-manual/workspace/moved.txt
  Why:   policy marks this tool as requiring human approval
  Rule:  tool_rules.move_file

  Approving lets this call through to the server. Denying stops it.
  Denied automatically in 30s if nobody answers.
  Approve? [y/N]
```

Check all four:

- the prompt is on your terminal, and **not** in the printed JSON-RPC reply
- answering `y` prints `APPROVED`, the reply is not an error, and
  `/tmp/s5-manual/workspace/moved.txt` now exists
- rerun and answer `n`: the reply is `AEGIS DENIED`, rule `approval_denied`,
  and no file moves
- rerun and answer nothing for 30s: `TIMED OUT — denied`, rule
  `approval_timeout`, and no file moves

**3. Confirm the audit recorded who resolved it.**

```bash
sqlite3 /tmp/s5-manual/data/audit.db 'select rule_id, reason from audit'
```

Expect an `approval_prompt` row for each attempt, then `approval_granted` /
`approval_denied` / `approval_timeout`, with your `user@host via /dev/ttysNNN`
in the reason for the answered ones.

**4. Clean up.**

```bash
rm -rf /tmp/s5-manual
```

## Recording the result

If it passes, note the date in S5-REPORT.md and move the C7 end-to-end row from
UNVERIFIED to VERIFIED (manual, macOS) — a tier below VERIFIED (harness),
because it is not repeatable without a human. It stays UNVERIFIED until someone
actually does this.
