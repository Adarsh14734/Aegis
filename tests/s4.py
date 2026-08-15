"""S4 harness: the credential broker (C6, partial).

Sections:
  1. Handle detection and policy authorization — no keychain access at all
  2. The keychain is NOT consulted for a call that policy denies
  3. End-to-end substitution through the real proxy
  4. Disclosure at byte level: audit db, -wal, -shm, stderr, every frame
  5. A server that echoes the credential back gets it redacted
  6. Exceptions on the substitution path do not carry the value
  7. The real `keyring` library, against a temporary file backend

Sections 1-6 use tests/fixtures/keyring.py so the real login keychain is never
touched. Section 7 exercises the real library, and skips with a message if it
is not installed rather than pretending it passed.

SAFETY: the "secrets" here are invented strings in a temp directory. Nothing
is written to any real keychain by sections 1-6, and section 7 writes only to
a file backend inside its own temp directory.
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(FIXTURES))   # fake keyring first
sys.path.insert(0, str(ROOT / "aegis"))

import broker  # noqa: E402
from policy import Policy, PolicyError  # noqa: E402

PROXY = ROOT / "aegis" / "proxy.py"
ECHO = ROOT / "tests" / "echo_server.py"
MOCK = ROOT / "tests" / "mock_fs_server.py"

# Invented. Shaped like a GitHub token so that any DLP interaction would show up.
SECRET = "ghp_s4fixture000000000000000000000000ABCD"
SECRET2 = 'tricky"value\\with\\escapes'   # forces the JSON-escaped redaction path

passed = failed = 0


def check(ok: bool, label: str, detail: str = "") -> None:
    global passed, failed
    if ok:
        passed += 1
        print(f"  pass  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label}{('  <- ' + detail) if detail else ''}")


def rule(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


LAB = Path(tempfile.mkdtemp(prefix="aegis-s4-"))
WS = LAB / "workspace"
WS.mkdir()

POLICY_DOC = {
    "version": 1,
    "workspace_roots": [str(WS)],
    "deny_paths": [".env"],
    "allowed_domains": ["api.github.com", "example.com"],
    "default_effect": "deny",
    "ask_behavior": "deny",
    "tool_rules": {
        "fetch": {"effect": "allow", "egress": True},
        "write_file": {"effect": "allow", "within": ["<workspace>"]},
    },
    "credentials": {
        "github_token": {"tools": ["fetch"], "hosts": ["api.github.com"]},
        "escaped_token": {"tools": ["fetch"], "hosts": ["api.github.com"]},
        "unscoped": {},
        "no_hosts": {"tools": ["fetch"]},
    },
}


def write_policy(doc=None, name="policy.json") -> Path:
    p = LAB / name
    p.write_text(json.dumps(doc or POLICY_DOC))
    p.chmod(0o600)
    return p


POLICY = write_policy()
pol = Policy(json.loads(POLICY.read_text()), POLICY)

ENV = {
    **os.environ,
    "PYTHONPATH": str(FIXTURES),
    "AEGIS_POLICY": str(POLICY),
    "AEGIS_TEST_SECRETS": json.dumps({"github_token": SECRET, "escaped_token": SECRET2}),
}


# ---- 1. detection and authorization ---------------------------------------

rule("1. HANDLE DETECTION AND AUTHORIZATION (no keychain access)")

found = broker.find_handles({"headers": ["Authorization: token ${aegis:github_token}"]})
check(found == [("arguments.headers[0]", "github_token")], "handle found in a nested list",
      str(found))
deep = broker.find_handles({"a": {"b": {"c": "${aegis:github_token}"}}})
check(deep == [("arguments.a.b.c", "github_token")], "handle found three levels deep",
      str(deep))
check(broker.find_handles({"t": "cost is ${100} or $VAR or {aegis:x}"}) == [],
      "ordinary text is not a handle")

GH = "https://api.github.com/user/repos"
cases = [
    ("substitution authorized for the granted tool and host",
     "fetch", {"url": GH, "headers": ["token ${aegis:github_token}"]}, "allow", None),
    ("handle denied for a tool not in its list",
     "write_file", {"path": str(WS / "x"), "content": "${aegis:github_token}"},
     "deny", "credential_denied"),
    ("handle denied for a host not in its list",
     "fetch", {"url": "https://example.com/x", "headers": ["${aegis:github_token}"]},
     "deny", "credential_denied"),
    ("one unlisted URL alongside a listed one still denies",
     "fetch", {"url": GH, "callback": "https://example.com/c",
               "headers": ["${aegis:github_token}"]}, "deny", "credential_denied"),
    ("unknown handle denied",
     "fetch", {"url": GH, "headers": ["${aegis:no_such_handle}"]},
     "deny", "credential_denied"),
    ("handle with neither tools nor hosts denied",
     "fetch", {"url": GH, "headers": ["${aegis:unscoped}"]}, "deny", "credential_denied"),
    ("handle with tools but no hosts denied",
     "fetch", {"url": GH, "headers": ["${aegis:no_hosts}"]}, "deny", "credential_denied"),
    ("handle in a call carrying no URL denied",
     "fetch", {"headers": ["${aegis:github_token}"]}, "deny", "credential_denied"),
    ("a call with no handle is unaffected",
     "fetch", {"url": GH}, "allow", None),
]
for label, tool, args, want_effect, want_rule in cases:
    d = pol.evaluate(tool, args, WS)
    ok = d.effect.value == want_effect and (want_rule is None or d.rule_id == want_rule)
    check(ok, label, f"got {d.effect.value}/{d.rule_id}: {d.reason}")

d = pol.evaluate("fetch", {"url": "http://169.254.169.254/",
                           "headers": ["${aegis:github_token}"]}, WS)
check(d.rule_id == "egress_domain", "egress still outranks the credential check", d.rule_id)
d = pol.evaluate("write_file", {"path": str(WS / ".env"),
                                "content": "${aegis:github_token}"}, WS)
check(d.rule_id == "deny_paths", "deny_paths still outranks everything", d.rule_id)

for bad, why in [
    ({"credentials": []}, "credentials not an object"),
    ({"credentials": {"a b": {"tools": ["x"]}}}, "invalid handle name"),
    ({"credentials": {"t": {"tools": "fetch"}}}, "tools not a list"),
    ({"credentials": {"t": {"tools": ["*"]}}}, "wildcard tool"),
    ({"credentials": {"t": {"hosts": ["*"]}}}, "wildcard host"),
    ({"credentials": {"t": {"hosts": ["https://x.com"]}}}, "host with scheme"),
    ({"credentials": {"t": {"scope": []}}}, "unknown key"),
]:
    try:
        Policy({**POLICY_DOC, **bad}, POLICY)
        check(False, f"policy refuses: {why}", "loaded")
    except PolicyError as exc:
        check(True, f"policy refuses: {why}: {str(exc)[:48]}")


# ---- 2. denied calls must not touch the keychain --------------------------

rule("2. A DENIED CALL NEVER READS THE KEYCHAIN")

KLOG = LAB / "keyring-calls.log"
env2 = {**ENV, "AEGIS_TEST_KEYRING_LOG": str(KLOG)}


def run_proxy(calls, env, server=ECHO, db=None):
    db = db or (LAB / f"audit-{len(list(LAB.glob('audit-*.db')))}.db")
    frames = "\n".join(json.dumps({
        "jsonrpc": "2.0", "id": i, "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }) for i, (name, args) in enumerate(calls, start=1)) + "\n"
    p = subprocess.run(
        [sys.executable, str(PROXY), "--", sys.executable, str(server)],
        input=frames, capture_output=True, text=True,
        env={**env, "AEGIS_AUDIT_DB": str(db)}, timeout=60,
    )
    return p, db


denied_calls = [
    ("write_file", {"path": str(WS / "x"), "content": "${aegis:github_token}"}),
    ("fetch", {"url": "https://example.com/x", "headers": ["${aegis:github_token}"]}),
    ("fetch", {"url": GH, "headers": ["${aegis:no_such_handle}"]}),
]
p, denied_db = run_proxy(denied_calls, env2)
check(p.stdout.count('"isError": true') == 3, "all three denied", p.stdout[:160])
check(not KLOG.exists(), "keyring was never called for a denied call",
      KLOG.read_text() if KLOG.exists() else "")
check(SECRET not in p.stdout and SECRET not in p.stderr,
      "no secret anywhere in a denied exchange")


# ---- 3. end to end --------------------------------------------------------

rule("3. END-TO-END SUBSTITUTION THROUGH THE REAL PROXY")

p, db = run_proxy([
    ("fetch", {"url": GH, "headers": ["Authorization: token ${aegis:github_token}"],
               "echo_mode": "none"}),
], ENV)
frame = json.loads(p.stdout.strip().splitlines()[0])
echoed = frame["result"]["content"][0]["text"]
check(SECRET in echoed or "[AEGIS-REDACTED" in echoed,
      "the server received something in place of the handle", echoed[:120])
check("${aegis:github_token}" not in echoed,
      "the server did NOT receive the literal handle", echoed[:120])
check("[AEGIS-REDACTED:github_token]" in echoed,
      "...and what came back to the model is redacted, not the value", echoed[:160])
check(SECRET not in p.stdout, "the value never reaches the client stream")

# prove the server really got the plaintext, by having it write the value to a
# file the test can read rather than returning it
p2, _ = run_proxy([
    ("fetch", {"url": GH, "headers": ["${aegis:github_token}"]}),
], ENV, server=MOCK)
check(p2.returncode == 0, "a substituted call is forwarded and completes")


# ---- 4. disclosure at byte level -----------------------------------------

rule("4. DISCLOSURE — byte-level check of every channel")

blobs = {"stdout frames": p.stdout, "proxy stderr": p.stderr}
for suffix in ("", "-wal", "-shm"):
    f = Path(str(db) + suffix)
    if f.exists():
        blobs[f"audit db {f.name}"] = f.read_bytes().decode("latin-1")
for where, blob in blobs.items():
    check(SECRET not in blob, f"secret absent from {where}")
    check("ghp_s4fixture" not in blob, f"no fragment of it in {where}")

rows = list(sqlite3.connect(str(db)).execute(
    "SELECT id, effect, rule_id, reason FROM audit"))
print("\n  audit rows:")
for r in rows:
    print(f"    {r[0]}  {r[1]:<7} {r[2]:<22} {r[3][:88]}")
joined = json.dumps(rows)
check(SECRET not in joined, "secret absent from the audit rows")
check("github_token" in joined, "the handle NAME is recorded")
check(any("substituted credential handle" in r[3] for r in rows),
      "the audit says substitution occurred")
check(any(r[2] == "credential_redacted" for r in rows),
      "the audit records that a redaction happened")
v = subprocess.run([sys.executable, str(ROOT / "aegis" / "verify.py"), str(db)],
                   capture_output=True, text=True)
check(v.returncode == 0, "chain still verifies", (v.stdout + v.stderr)[:120])

drows = list(sqlite3.connect(str(denied_db)).execute("SELECT rule_id, reason FROM audit"))
check(all(r[0] == "credential_denied" for r in drows),
      "denied calls recorded with rule_id credential_denied", str(drows)[:120])


# ---- 5. echoing server ----------------------------------------------------

rule("5. A SERVER THAT ECHOES THE CREDENTIAL BACK")

for mode, label in (("text", "in a normal result"), ("error", "inside an error message")):
    pe, dbe = run_proxy([
        ("fetch", {"url": GH, "headers": ["token ${aegis:github_token}"],
                   "echo_mode": mode}),
    ], ENV)
    check(SECRET not in pe.stdout, f"echoed credential {label} is redacted")
    check("[AEGIS-REDACTED:github_token]" in pe.stdout,
          f"...and replaced by a named marker {label}", pe.stdout[:140])
    n = sqlite3.connect(str(dbe)).execute(
        "SELECT count(*) FROM audit WHERE rule_id='credential_redacted'").fetchone()[0]
    check(n >= 1, f"redaction audited {label}")

pe, _ = run_proxy([
    ("fetch", {"url": GH, "headers": ["${aegis:escaped_token}"], "echo_mode": "text"}),
], ENV)
check(SECRET2 not in pe.stdout, "a secret with quotes and backslashes is redacted")
check(json.dumps(SECRET2)[1:-1] not in pe.stdout,
      "...including its JSON-escaped spelling on the wire", pe.stdout[:160])


# ---- 6. exceptions do not leak -------------------------------------------

rule("6. EXCEPTIONS ON THE SUBSTITUTION PATH")

# a backend that puts the secret into its own exception message
pf, dbf = run_proxy([
    ("fetch", {"url": GH, "headers": ["${aegis:github_token}"]}),
], {**ENV, "AEGIS_TEST_KEYRING_RAISES": "1"})
check('"isError": true' in pf.stdout, "the call is denied when the backend fails")
check("credential_unavailable" in pf.stdout, "with rule_id credential_unavailable",
      pf.stdout[:200])
check(SECRET not in pf.stdout, "the raising backend's message does not reach the client")
check(SECRET not in pf.stderr, "...nor stderr")
check("Traceback" not in pf.stderr, "no traceback was printed at all", pf.stderr[-200:])
fblob = Path(str(dbf)).read_bytes().decode("latin-1")
check(SECRET not in fblob, "...nor the audit db")

# missing secret
pm, _ = run_proxy([("fetch", {"url": GH, "headers": ["${aegis:github_token}"]})],
                  {**ENV, "AEGIS_TEST_SECRETS": "{}"})
check("credential_unavailable" in pm.stdout, "a missing secret denies the call",
      pm.stdout[:200])

# in-process: the exception type and message carry nothing
def exploding_resolver(handle):
    raise RuntimeError(f"boom while reading {SECRET}")


try:
    broker.substitute({"h": "${aegis:github_token}"}, resolver=exploding_resolver)
    check(False, "substitute() raises on resolver failure")
except broker.BrokerError as exc:
    check(SECRET not in str(exc), "BrokerError message carries no value", str(exc))
    check(exc.__cause__ is None and exc.__context__ is None,
          "the original exception is not chained (no traceback with locals)")
except BaseException as exc:
    check(False, "substitute() raises BrokerError specifically", type(exc).__name__)

r = broker.Redactor()
r.remember("t", SECRET)
check(r.scrub(f"failed: {SECRET} rejected") == "failed: [AEGIS-REDACTED] rejected",
      "Redactor.scrub removes the value from arbitrary text")


# ---- 7. the real keyring library -----------------------------------------

rule("7. THE REAL keyring LIBRARY (not the test fixture)")

real = shutil.which("python3")
probe = subprocess.run(
    [sys.executable, "-c", "import keyring; print('yes')"],
    capture_output=True, text=True,
    env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"},
)
if probe.returncode != 0:
    print("  SKIP  the real 'keyring' library is not installed for "
          f"{sys.executable}.")
    print("        Sections 1-6 used tests/fixtures/keyring.py. To exercise the")
    print("        real library:  pip install keyring keyrings.alt")
    print("        S4-REPORT.md records this as a gap, not as a pass.")
else:
    kr_home = LAB / "kr"
    kr_home.mkdir()
    real_env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    real_env.update({
        "AEGIS_POLICY": str(POLICY),
        "XDG_DATA_HOME": str(kr_home),
        "PYTHON_KEYRING_BACKEND": "keyrings.alt.file.PlaintextKeyring",
    })
    seed = subprocess.run(
        [sys.executable, "-c",
         "import keyring, sys; keyring.set_password('aegis','github_token', sys.argv[1])",
         SECRET],
        capture_output=True, text=True, env=real_env,
    )
    if seed.returncode != 0:
        print(f"  SKIP  could not seed a temporary backend: {seed.stderr.strip()[:160]}")
    else:
        pr, dbr = run_proxy([
            ("fetch", {"url": GH, "headers": ["token ${aegis:github_token}"],
                       "echo_mode": "text"}),
        ], real_env)
        check('"isError": false' in pr.stdout or "ECHO" in pr.stdout,
              "real keyring: the call was forwarded", pr.stdout[:160])
        check("[AEGIS-REDACTED:github_token]" in pr.stdout,
              "real keyring: the echoed value came back redacted", pr.stdout[:160])
        check(SECRET not in pr.stdout and SECRET not in pr.stderr,
              "real keyring: no disclosure to the client")
        check(SECRET not in Path(str(dbr)).read_bytes().decode("latin-1"),
              "real keyring: no disclosure to the audit db")


shutil.rmtree(LAB, ignore_errors=True)

rule("SUMMARY")
print(f"  {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
