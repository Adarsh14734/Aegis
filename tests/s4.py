"""S4 harness: the credential broker (C6, partial).

Sections:
  1. Handle detection and policy authorization — no keychain access at all
  2. The keychain is NOT consulted for a call that policy denies
  3. End-to-end substitution through the real proxy
  4. Disclosure at byte level: audit db, -wal, -shm, stderr, every frame
  5. A server that echoes the credential back gets it redacted
  6. Exceptions on the substitution path do not carry the value
  7. The real `keyring` library, against a temporary file backend

REVISED IN S8. Sections 3, 5 and 6 drove credentials through the *substitution*
path: Aegis put the plaintext into the tool arguments and forwarded them to the
MCP server. S8 deleted that path — a credential now goes onto a request Aegis
makes itself (aegis/fetch.py), and a handle on a tool that cannot reach it is
denied. Those sections therefore now assert the S8 truth, against a real HTTP
origin on 127.0.0.1 rather than against the echo MCP server, which is no longer
in the path at all. What each one used to assert is recorded in S8-REPORT.md.
Sections 1, 2, 4 and 7 are unchanged in substance.

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

sys.path.insert(0, str(ROOT / "tests"))
import http_target  # noqa: E402

PROXY = ROOT / "aegis" / "proxy.py"
ECHO = ROOT / "tests" / "echo_server.py"
MOCK = ROOT / "tests" / "mock_fs_server.py"

# Invented. Shaped like a GitHub token so that any DLP interaction would show up.
SECRET = "ghp_s4fixture000000000000000000000000ABCD"
SECRET2 = 'tricky"value\\with\\escapes'   # forces the JSON-escaped redaction path

passed = failed = 0
unverified: list[str] = []


def check(ok: bool, label: str, detail: str = "") -> None:
    global passed, failed
    if ok:
        passed += 1
        print(f"  pass  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label}{('  <- ' + detail) if detail else ''}")


def mark_unverified(what: str, why: str, remedy: str = "") -> None:
    """Record a claim this run did NOT establish.

    A skipped test that reads as green is worse than a failing one: it puts a
    tick next to something nobody checked. Anything recorded here is printed
    in the summary and makes the suite exit non-zero, so an unverified path
    cannot be mistaken for a verified one by looking at the exit code.
    """
    unverified.append(what)
    print(f"  NOT RUN  {what}")
    print(f"           why: {why}")
    if remedy:
        print(f"           to run it: {remedy}")


def run_child(argv, env, label: str):
    """Run a child process and, on failure, print everything needed to debug it.

    The previous version of this harness truncated the child's stderr to 160
    characters, which cut it off *above* the exception line — so the one thing
    a reader needed was the one thing removed. Print the command, the exit
    code, and both streams in full.
    """
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=120)
    if proc.returncode != 0:
        print(f"  child failed: {label}")
        print(f"    command : {' '.join(str(a) for a in argv)}")
        print(f"    exit    : {proc.returncode}")
        for stream, name in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
            if stream.strip():
                print(f"    {name}  :")
                for ln in stream.strip().splitlines():
                    print(f"      | {ln}")
    return proc


def rule(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


# --- labguard: pins every Aegis path into a temp lab and verifies it, in this
# --- process AND in a child, before anything runs. Five suites have written to
# --- the operator's real installation because env pinning failed silently; this
# --- aborts instead. See tests/labguard.py.
sys.path.insert(0, str(ROOT / "tests"))
import labguard  # noqa: E402

LAB = labguard.pin("aegis-s4-")
WS = LAB / "workspace"
WS.mkdir()

# S8: the far side of a credentialed request is now an HTTP origin, not the MCP
# server. 127.0.0.1 is addressed literally and listed in allowed_domains — the
# documented operator opt-in — so the proxy subprocess resolves it through the
# production socket path with nothing injected.
TARGET_LOG = LAB / "origin-requests.jsonl"
TARGET, PORT = http_target.serve(str(TARGET_LOG))
LOCAL = f"http://127.0.0.1:{PORT}"

POLICY_DOC = {
    "version": 1,
    "workspace_roots": [str(WS)],
    "deny_paths": [".env"],
    "allowed_domains": ["api.github.com", "example.com", "127.0.0.1"],
    "default_effect": "deny",
    "ask_behavior": "deny",
    "tool_rules": {
        "fetch": {"effect": "allow", "egress": True},
        "write_file": {"effect": "allow", "within": ["<workspace>"]},
    },
    "credentials": {
        "github_token": {"tools": ["fetch"], "hosts": ["api.github.com", "127.0.0.1"]},
        "escaped_token": {"tools": ["fetch"], "hosts": ["api.github.com", "127.0.0.1"]},
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

rule("3. END-TO-END CREDENTIAL USE THROUGH THE REAL PROXY (S8 path)")

# S8: Aegis makes the request. The MCP server is bypassed, so the far side is
# the HTTP origin and the question "did the plaintext reach the wire" is
# answered from that origin's own request log rather than from a tool result.
p, db = run_proxy([
    ("fetch", {"url": f"{LOCAL}/echo",
               "headers": {"Authorization": "token ${aegis:github_token}"}}),
], ENV)
frame = json.loads(p.stdout.strip().splitlines()[0])
body = frame["result"]["content"][0]["text"]

arrived = [json.loads(l) for l in TARGET_LOG.read_text().splitlines() if l.strip()]
check(bool(arrived), "the request reached the origin", str(arrived)[:120])
check(SECRET in (arrived[-1]["headers"].get("authorization") or ""),
      "the origin received the real credential on the wire",
      str(arrived[-1]["headers"].get("authorization"))[:60])
check("${aegis:github_token}" not in json.dumps(arrived[-1]),
      "the origin did NOT receive the literal handle", json.dumps(arrived[-1])[:160])
check("[AEGIS-REDACTED:github_token]" in body,
      "...and what came back to the model is redacted, not the value", body[:160])
check(SECRET not in p.stdout, "the value never reaches the client stream")

# The MCP server is not merely uninvolved by convention: nothing was forwarded.
p2, _ = run_proxy([
    ("fetch", {"url": f"{LOCAL}/ok", "headers": {"Authorization": "${aegis:github_token}"}}),
], ENV, server=MOCK)
check(p2.returncode == 0, "a credentialed call completes without the server")
check("MOCK SERVER" not in p2.stdout,
      "...and the MCP server produced no part of the answer", p2.stdout[:160])


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
check(any("used credential handle" in r[3] for r in rows),
      "the audit says which handle was spent", str(rows)[:200])
check(any("request performed by Aegis" in r[3] for r in rows),
      "the audit says Aegis made the request itself", str(rows)[:200])
check(any("echoed the credential back" in r[3] for r in rows),
      "the audit records that the far side echoed it and it was redacted",
      str(rows)[:300])
check(any(r[2].startswith("tool_rules.fetch") for r in rows),
      "the egress row cites the tool rule", str(rows)[:200])
v = subprocess.run([sys.executable, str(ROOT / "aegis" / "verify.py"), str(db)],
                   capture_output=True, text=True)
check(v.returncode == 0, "chain still verifies", (v.stdout + v.stderr)[:120])

drows = list(sqlite3.connect(str(denied_db)).execute("SELECT rule_id, reason FROM audit"))
check(all(r[0] == "credential_denied" for r in drows),
      "denied calls recorded with rule_id credential_denied", str(drows)[:120])


# ---- 5. echoing server ----------------------------------------------------

rule("5. A SERVER THAT ECHOES THE CREDENTIAL BACK")

# S8: the echo comes from the origin now — /echo reflects the request headers,
# so the credential really is in the response body before Aegis strips it.
for route, label in (("/echo", "in a normal result"), ("/status/500", "with an error status")):
    pe, dbe = run_proxy([
        ("fetch", {"url": f"{LOCAL}{route}",
                   "headers": {"Authorization": "token ${aegis:github_token}"}}),
    ], ENV)
    check(SECRET not in pe.stdout, f"an echoed credential {label} is redacted",
          pe.stdout[:160])
    if route == "/echo":
        check("[AEGIS-REDACTED:github_token]" in pe.stdout,
              f"...and replaced by a named marker {label}", pe.stdout[:200])
        n = sqlite3.connect(str(dbe)).execute(
            "SELECT count(*) FROM audit WHERE reason LIKE '%echoed the credential%'"
        ).fetchone()[0]
        check(n >= 1, f"the redaction is audited {label}")

pe, _ = run_proxy([
    ("fetch", {"url": f"{LOCAL}/echo",
               "headers": {"Authorization": "${aegis:escaped_token}"}}),
], ENV)
check(SECRET2 not in pe.stdout, "a secret with quotes and backslashes is redacted")
check(json.dumps(SECRET2)[1:-1] not in pe.stdout,
      "...including its JSON-escaped spelling on the wire", pe.stdout[:160])


# ---- 6. exceptions do not leak -------------------------------------------

rule("6. EXCEPTIONS ON THE SUBSTITUTION PATH")

# a backend that puts the secret into its own exception message
pf, dbf = run_proxy([
    ("fetch", {"url": f"{LOCAL}/ok", "headers": {"Authorization": "${aegis:github_token}"}}),
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
pm, _ = run_proxy([("fetch", {"url": f"{LOCAL}/ok",
                              "headers": {"Authorization": "${aegis:github_token}"}})],
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


# ---- 7. the real keyring library and the real OS keychain -----------------

rule("7. THE REAL keyring LIBRARY AND THE REAL OS KEYCHAIN")

# Sections 1-6 ran against tests/fixtures/keyring.py. Everything below is about
# how much of the *production* path that leaves unproven. Three distinct
# claims, verified separately, because conflating them is how a report ends up
# overstating its evidence:
#
#   7a  the real library loads and broker's read path works through it
#   7b  the real library end to end, against an isolated file backend
#   7c  the real OS keychain write path
#
# Only 7a and 7b are automatable here. 7c is not, for a specific and checkable
# reason recorded below.

NO_FIXTURE_ENV = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
probe = run_child(
    [sys.executable, "-c",
     "import keyring, keyring.backends.macOS as m;"
     "kr = keyring.get_keyring();"
     "print(type(kr).__module__, isinstance(kr, m.Keyring))"],
    NO_FIXTURE_ENV, "import the real keyring library",
)
has_keyring = probe.returncode == 0
backend_line = probe.stdout.strip()
is_macos_backend = backend_line.endswith("True")
print(f"  real keyring available: {has_keyring}   default backend: {backend_line or 'n/a'}")

# --- 7a: broker's read path, through the real library, writing nothing -----
if not has_keyring:
    mark_unverified(
        "7a: broker read path against the real keyring library",
        "the 'keyring' library is not importable for this interpreter",
        f"pip install keyring, then rerun with {sys.executable}",
    )
else:
    reader = run_child(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, sys.argv[1]);"
         "import broker;"
         "print('exists:', broker.secret_exists('aegis_s4_absent_probe'));"
         "\ntry:\n"
         "    broker.get_secret('aegis_s4_absent_probe')\n"
         "except broker.BrokerError as e:\n"
         "    print('raised:', type(e).__name__);"
         "    print('chained:', e.__cause__ is not None or e.__context__ is not None);"
         "    print('msg:', e)\n",
         str(ROOT / "aegis")],
        NO_FIXTURE_ENV, "broker read path via real keyring",
    )
    out = reader.stdout
    check(reader.returncode == 0, "7a real library: broker imports and runs", out[:200])
    check("exists: False" in out, "7a real library: a missing handle reports absent", out[:200])
    check("raised: BrokerError" in out,
          "7a real library: a missing secret raises BrokerError", out[:200])
    check("chained: False" in out,
          "7a real library: no exception is chained onto it", out[:200])
    check("no secret is stored" in out,
          "7a real library: the message names the handle, not a value", out[:200])
    if is_macos_backend:
        check(True, "7a real library: the backend in use is the macOS Keychain")

# --- 7b: end to end against an isolated file backend ----------------------
alt = run_child([sys.executable, "-c", "import keyrings.alt.file"],
                NO_FIXTURE_ENV, "import keyrings.alt")
if not has_keyring or alt.returncode != 0:
    mark_unverified(
        "7b: end-to-end substitution against the real keyring library",
        "keyrings.alt is not installed, and it is the only way to give the real "
        "library a writable backend that is not your login keychain",
        f"{sys.executable} -m pip install keyrings.alt",
    )
else:
    kr_home = LAB / "kr"
    kr_home.mkdir()
    real_env = {
        **NO_FIXTURE_ENV,
        "AEGIS_POLICY": str(POLICY),
        "XDG_DATA_HOME": str(kr_home),
        "PYTHON_KEYRING_BACKEND": "keyrings.alt.file.PlaintextKeyring",
    }
    seed = run_child(
        [sys.executable, "-c",
         "import keyring, sys; keyring.set_password('aegis','github_token', sys.argv[1])",
         SECRET],
        real_env, "seed the isolated file backend",
    )
    if seed.returncode != 0:
        mark_unverified(
            "7b: end-to-end substitution against the real keyring library",
            "seeding the isolated backend failed; the child's output is above",
            "fix the cause shown above and rerun",
        )
    else:
        pr, dbr = run_proxy([
            ("fetch", {"url": GH, "headers": ["token ${aegis:github_token}"],
                       "echo_mode": "text"}),
        ], real_env)
        check("ECHO" in pr.stdout, "7b real library: the call was forwarded",
              pr.stdout[:160])
        check("[AEGIS-REDACTED:github_token]" in pr.stdout,
              "7b real library: the echoed value came back redacted", pr.stdout[:160])
        check(SECRET not in pr.stdout and SECRET not in pr.stderr,
              "7b real library: no disclosure to the client")
        check(SECRET not in Path(str(dbr)).read_bytes().decode("latin-1"),
              "7b real library: no disclosure to the audit db")
        print("  note: this used keyrings.alt.file.PlaintextKeyring — a plaintext")
        print("        FILE, not the OS keychain. It proves the library wiring,")
        print("        not the keychain integration. See 7c.")

# --- 7c: the real OS keychain write path ----------------------------------
# Not automatable without violating the standing constraint that this suite
# must never write to the real login keychain. The reason is specific and was
# read out of the installed library rather than assumed:
#
#   keyring.backends.macOS.Keyring accepts a keychain path (attribute
#   `keychain`, settable via KEYCHAIN_PATH) but ignores it. Its own
#   @warn_keychain decorator says so: "Specified keychain is ignored. See
#   #623". api.set_generic_password() takes the keychain name as its first
#   argument, never references it, and calls SecItemAdd() with no
#   kSecUseKeychain — SecKeychainOpen does not appear in the module at all.
#   Every write therefore lands in the user's default (login) keychain.
#
# So on macOS with keyring 25.7.0 there is no isolated keychain to write to.
# The write path is left UNVERIFIED rather than tested against the developer's
# real credential store.
mark_unverified(
    "7c: the real OS keychain WRITE path (aegis-secret set -> substitution)",
    "keyring 25.7.0 ignores KEYCHAIN_PATH (upstream #623) and SecItemAdd targets "
    "the default keychain, so an automated write would land in your login "
    "keychain, which this suite must never touch",
    "run tests/manual/keychain-check.md by hand, or wait for a keyring release "
    "that honours the keychain path",
)


shutil.rmtree(LAB, ignore_errors=True)

rule("SUMMARY")
print(f"  {passed} passed, {failed} failed, {len(unverified)} NOT RUN")
if unverified:
    print("\n  These claims were NOT established by this run:")
    for item in unverified:
        print(f"    - {item}")
    print("\n  The suite exits non-zero because of them. A skipped check that")
    print("  reads as green puts a tick next to something nobody verified.")
sys.exit(1 if (failed or unverified) else 0)
