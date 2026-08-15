# Manual check: the real OS keychain write path (S4 / C6a, item 7c)

`tests/s4.py` cannot automate this. It writes to your **real login keychain**,
which the automated suite is forbidden to touch, so it is a by-hand procedure
that you opt into and then clean up.

## Why it cannot be automated

`keyring.backends.macOS.Keyring` accepts a keychain path — the `keychain`
attribute, settable through `KEYCHAIN_PATH` — and then ignores it. Read from
the installed library, version 25.7.0:

- `@warn_keychain` warns `"Specified keychain is ignored. See #623"`
- `api.set_generic_password(name, service, username, password)` takes the
  keychain `name` as its first parameter and never references it
- it calls `SecItemAdd(q, None)` with no `kSecUseKeychain` in the query, and
  `SecKeychainOpen` does not appear anywhere in the module

So every write goes to the default keychain. There is no isolated keychain to
point an automated test at. If a future keyring release honours the path,
fold this into `tests/s4.py` §7c and delete this file.

## Procedure

Takes about a minute. Uses an obviously-fake value.

**1. Store a fake secret.** You will be prompted twice, with no echo.

```bash
./bin/aegis-secret set s4_manual_probe
```

Paste exactly: `ghp_manualprobe0000000000000000000000AB`

**2. Confirm it is in the keychain and that Aegis reports it without printing it.**

```bash
./bin/aegis-secret check s4_manual_probe
```

Expect `s4_manual_probe: set`. It must not print the value.

**3. Grant it, in a scratch policy outside any workspace root.**

```bash
mkdir -p /tmp/s4-manual/workspace && cat > /tmp/s4-manual/policy.json <<'EOF'
{"version":1,"workspace_roots":["/tmp/s4-manual/workspace"],
 "allowed_domains":["api.github.com"],"default_effect":"deny","ask_behavior":"deny",
 "tool_rules":{"fetch":{"effect":"allow","egress":true}},
 "credentials":{"s4_manual_probe":{"tools":["fetch"],"hosts":["api.github.com"]}}}
EOF
chmod 600 /tmp/s4-manual/policy.json
```

**4. Run one call through the proxy against the echoing server.**

```bash
AEGIS_POLICY=/tmp/s4-manual/policy.json AEGIS_AUDIT_DB=/tmp/s4-manual/audit.db python3 -c 'import json,subprocess,sys; print(subprocess.run([sys.executable,"aegis/proxy.py","--",sys.executable,"tests/echo_server.py"],input=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://api.github.com/user","headers":["token ${aegis:s4_manual_probe}"],"echo_mode":"text"}}})+"\n",capture_output=True,text=True).stdout)'
```

**What to look for.** All four must hold:

- the reply contains `[AEGIS-REDACTED:s4_manual_probe]`
- the reply does **not** contain `ghp_manualprobe`
- `sqlite3 /tmp/s4-manual/audit.db 'select rule_id, reason from audit'` shows a
  row saying substitution occurred and a `credential_redacted` row, and neither
  contains the value
- `grep -c ghp_manualprobe /tmp/s4-manual/audit.db` returns 0

**5. Clean up. Do not skip this — it is a real keychain entry.**

```bash
./bin/aegis-secret delete s4_manual_probe && rm -rf /tmp/s4-manual
```

**6. Confirm nothing was left behind.**

```bash
security find-generic-password -s aegis 2>&1 | tail -1
```

Expect `The specified item could not be found in the keychain.`

## Recording the result

If it passes, note the date and keyring version in S4-REPORT.md under control
status and move 7c from UNVERIFIED to VERIFIED (manual, macOS) — a tier below
VERIFIED (harness), because it is not repeatable without a human. It stays
UNVERIFIED until someone actually does this.
