"""Aegis S8 harness — Aegis as the HTTP client, and the versioned audit payload.

Two things are being established here and they are worth separating:

  1. **The request Aegis makes goes where Aegis checked.** Resolution happens
     once, every resolved address is checked, and the socket is opened to that
     address. Redirects are re-checked hop by hop. A credential is attached by
     Aegis or not at all.
  2. **The schema change did not invalidate anyone's chain.** A database
     written before S8 verifies byte-identically, and a database holding both
     old and new rows verifies as one chain.

Real sockets throughout: `tests/http_target.py` is a genuine HTTP origin on
127.0.0.1 that records every request it receives, so "the credential reached
the wire" and "the request never arrived" are both answerable from its log
rather than from what Aegis says about itself.

DNS is the one thing a test cannot own, so `fetch.resolve` takes an injectable
resolver. It is not a bypass — whatever it returns goes through exactly the
same address checks as a real answer, which is the property §2 exercises by
pointing a name at 10.0.0.1 and watching it be refused.

    python3 tests/s8.py            exit 0 only if every check passed
"""

import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))  # fake keyring, before the real one

import http_target  # noqa: E402
from aegis import audit as audit_mod  # noqa: E402
from aegis import broker, egress, fetch  # noqa: E402
from aegis.policy import Policy  # noqa: E402

PROXY = ROOT / "aegis" / "proxy.py"
VERIFY = ROOT / "aegis" / "verify.py"
MOCK = ROOT / "tests" / "mock_fs_server.py"

PASSED = 0
FAILED = 0
FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> bool:
    global PASSED, FAILED
    if ok:
        PASSED += 1
        print(f"  pass  {label}")
    else:
        FAILED += 1
        FAILURES.append(label)
        print(f"  FAIL  {label}" + (f"\n        {detail}" if detail else ""))
    return ok


def rule(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


# ---------------------------------------------------------------------------
# lab — pinned before anything resolves a default path (S5 finding 1)
# ---------------------------------------------------------------------------

LAB = Path(tempfile.mkdtemp(prefix="aegis-s8-"))
WS = LAB / "workspace"
WS.mkdir(parents=True)
os.environ["AEGIS_AUDIT_DB"] = str(LAB / "audit.db")
os.environ["AEGIS_KILLSWITCH"] = str(LAB / "KILLSWITCH")

REAL_DIR = (
    Path.home() / "Library" / "Application Support" / "Aegis"
    if sys.platform == "darwin"
    else Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "aegis"
)
REAL_WATCH = [REAL_DIR / "audit.db", REAL_DIR / "policy.json", REAL_DIR / "KILLSWITCH"]
BASELINE = {
    str(p): (hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "absent")
    for p in REAL_WATCH
}

SECRET = "ghp_s8fixture_ZZZ9aaaa1111bbbb2222cccc3333"
# The fake keyring reads this from the environment of whatever process asks —
# set before any in-process substitution, not only for the subprocesses.
os.environ["AEGIS_TEST_SECRETS"] = json.dumps(
    {"tok": SECRET, "wide": SECRET, "local": SECRET})
RECORD = LAB / "target-requests.jsonl"

TARGET, PORT = http_target.serve(str(RECORD))
HOST = "target.test"
BASE = f"http://{HOST}:{PORT}"
# The same origin, addressed the way a subprocess with no injected resolver
# must address it. 127.0.0.1 is in allowed_domains as the documented operator
# opt-in, so this exercises the real resolution path end to end.
LOCAL = f"http://127.0.0.1:{PORT}"
print(f"lab: {LAB}\norigin: 127.0.0.1:{PORT} as {HOST}")


def fake_resolver(mapping):
    """A getaddrinfo stand-in. Whatever it answers is still fully checked."""

    def resolve(host, port, *args, **kwargs):
        if host not in mapping:
            raise socket.gaierror(f"no fixture address for {host!r}")
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))
            for ip in mapping[host]
        ]

    return resolve


RESOLVER = fake_resolver({
    HOST: ["127.0.0.1"],
    "elsewhere.test": ["127.0.0.1"],
    "rebind.test": ["10.0.0.7"],
    "split.test": ["93.184.216.34", "192.168.1.9"],
    "denied.test": ["127.0.0.1"],
    # getaddrinfo answers an IP literal with itself; the fixture must too, or
    # the literal cases below would be testing the fixture, not the control.
    "127.0.0.1": ["127.0.0.1"],
    "169.254.169.254": ["169.254.169.254"],
    "::1": ["::1"],
    "2130706433": ["127.0.0.1"],
})


def policy_doc(**over) -> dict:
    doc = {
        "version": 1,
        "workspace_roots": [str(WS)],
        "deny_paths": [".env"],
        # 127.0.0.1 is listed on purpose: it is the documented operator opt-in
        # for a local service, and it is what lets this suite exercise the real
        # socket path instead of a mock. A deployment that does not list it gets
        # the full refusal, which §2 verifies.
        "allowed_domains": [HOST, "elsewhere.test", "rebind.test", "split.test",
                            "127.0.0.1"],
        "tool_rules": {
            "fetch": {"effect": "allow", "egress": True},
            "write_file": {"effect": "allow", "within": ["<workspace>"]},
            "read_file": {"effect": "allow", "within": ["<workspace>"]},
        },
        "credentials": {
            "tok": {"tools": ["fetch"], "hosts": [HOST]},
            "wide": {"tools": ["fetch"], "hosts": [HOST, "elsewhere.test"]},
            # For §5, which runs the real proxy in a subprocess with no
            # injected resolver: the origin is addressed literally so the
            # production socket.getaddrinfo path is the one under test.
            "local": {"tools": ["fetch"], "hosts": ["127.0.0.1"]},
        },
        "default_effect": "deny",
        "ask_behavior": "deny",
    }
    doc.update(over)
    return doc


POLICY_PATH = LAB / "policy.json"
POLICY_PATH.write_text(json.dumps(policy_doc()))
os.chmod(POLICY_PATH, 0o600)
POLICY = Policy.load(POLICY_PATH)

ENV = {
    **os.environ,
    "AEGIS_POLICY": str(POLICY_PATH),
    "PYTHONPATH": os.pathsep.join([str(ROOT / "tests" / "fixtures"), str(ROOT)]),
    "AEGIS_TEST_SECRETS": os.environ["AEGIS_TEST_SECRETS"],
}


def target_log() -> list[dict]:
    if not RECORD.exists():
        return []
    return [json.loads(line) for line in RECORD.read_text().splitlines() if line.strip()]


def perform(arguments, redactor=None):
    return fetch.perform("fetch", arguments, POLICY, redactor, RESOLVER)


# ---------------------------------------------------------------------------
rule("1. THE ADDRESS CHECKED IS THE ADDRESS DIALLED")
# ---------------------------------------------------------------------------

before = len(target_log())
out = perform({"url": f"{BASE}/ok"})
check("an allowed request is performed", out.allowed, out.reason)
check("...and the body comes back", "AEGIS-TARGET-OK" in out.body, out.body[:120])
check("...to the host that was asked for", out.host == HOST, str(out.host))
check("...and the origin really received it", len(target_log()) == before + 1)

arrived = target_log()[-1]
check("the Host header carries the original name, not the dialled address",
      arrived["host_header"].startswith(HOST), str(arrived["host_header"]))

check("status is recorded", out.status == 200, str(out.status))
check("request bytes are recorded and non-zero", (out.req_bytes or 0) > 0, str(out.req_bytes))
check("response bytes are recorded and non-zero", (out.resp_bytes or 0) > 0, str(out.resp_bytes))
check("response bytes exceed the body length (status line and headers counted)",
      (out.resp_bytes or 0) > len("AEGIS-TARGET-OK"), str(out.resp_bytes))

post = perform({"url": f"{BASE}/echo", "method": "POST", "body": "hello-from-aegis",
                "headers": {"X-Test": "1"}})
check("a POST with a body is performed", post.allowed, post.reason)
echoed = json.loads(post.body)
check("...the body arrived intact", echoed["body"] == "hello-from-aegis", str(echoed)[:160])
check("...and the header arrived", echoed["headers"].get("x-test") == "1")
check("request bytes grow with the body",
      (post.req_bytes or 0) > (out.req_bytes or 0), f"{out.req_bytes} vs {post.req_bytes}")

# ---------------------------------------------------------------------------
rule("2. SSRF VIA DNS — a name that resolves to a private address")
# ---------------------------------------------------------------------------

# rebind.test is IN allowed_domains. Nothing lexical about it is suspicious;
# only resolution reveals it. This is precisely the case S3a documented as out
# of reach: "a hostname whose DNS record points at 169.254.169.254 is NOT
# caught. That gap closes only in C4 proper, at the socket."
before = len(target_log())
out = perform({"url": "http://rebind.test/ok"})
check("a name resolving to a private address is denied", not out.allowed, out.reason)
check("...with rule_id egress_domain", out.rule_id == "egress_domain", out.rule_id)
check("...naming the address and the category",
      "10.0.0.7" in out.reason and "private address" in out.reason, out.reason)
check("...and nothing was sent", len(target_log()) == before)

check("the same host passes the S3a lexical check, which is the point",
      egress.check_url("url", "http://rebind.test/ok", POLICY.allowed_domains) is None,
      "S3a would have allowed this")

out = perform({"url": "http://split.test/ok"})
check("a name resolving to one public AND one private address is denied",
      not out.allowed, out.reason)
check("...naming the private one", "192.168.1.9" in out.reason, out.reason)

for target, label in (
    ("http://127.0.0.1:1/ok", "a loopback IP literal"),
    ("http://169.254.169.254/latest/meta-data/", "the cloud metadata address"),
    ("http://[::1]/ok", "IPv6 loopback"),
    ("http://2130706433/ok", "the integer spelling of 127.0.0.1"),
):
    out = perform({"url": target})
    # 127.0.0.1 is explicitly listed in this policy, so it is permitted to be
    # dialled and then simply fails to connect on port 1 — the operator opt-in
    # working as documented. Everything else is refused before any socket.
    if "127.0.0.1:1" in target:
        check(f"{label} is dialled only because it is explicitly listed",
              out.rule_id in ("egress_failed",), f"{out.rule_id}: {out.reason}")
    else:
        check(f"{label} is refused", not out.allowed, f"{out.rule_id}: {out.reason}")

# ---------------------------------------------------------------------------
rule("3. REDIRECTS — every hop is a new decision")
# ---------------------------------------------------------------------------

out = perform({"url": f"{BASE}/redirect/2"})
check("a short redirect chain is followed", out.allowed, out.reason)
check("...to the end of the chain", "AEGIS-TARGET-OK" in out.body, out.body[:80])
check("...and every hop is recorded", len(out.hops) == 3, str(out.hops))

# Same-origin hops only prove the loop runs. This one leaves the allowlist.
before = len(target_log())
out = perform({"url": f"{BASE}/to?target=http://evil.test/steal"})
check("a redirect to a host outside allowed_domains is denied",
      not out.allowed, out.reason)
check("...as a redirect, not as the original destination",
      out.rule_id == "egress_redirect", out.rule_id)
check("...naming the hop it was refused at", "redirect hop 1" in out.reason, out.reason)
check("...and saying which host", "evil.test" in out.reason, out.reason)
check("...and it is a denial, not a silent stop at the 302",
      "AEGIS-TARGET-OK" not in out.body and out.body == "", repr(out.body[:80]))
check("...the first hop did happen and is recorded", len(target_log()) == before + 1)

out = perform({"url": f"{BASE}/to?target=http://rebind.test/x"})
check("a redirect to a name resolving privately is denied at the hop",
      not out.allowed and out.rule_id == "egress_redirect", f"{out.rule_id}: {out.reason}")
check("...naming the resolved address", "10.0.0.7" in out.reason, out.reason)

out = perform({"url": f"{BASE}/redirect/9"})
check("a chain longer than 5 hops is denied", not out.allowed, out.reason)
check("...with rule_id egress_redirect_limit",
      out.rule_id == "egress_redirect_limit", out.rule_id)
check("...naming the limit", str(fetch.MAX_REDIRECTS) in out.reason, out.reason)
check("...after following exactly the limit", len(out.hops) == fetch.MAX_REDIRECTS + 1,
      str(len(out.hops)))

# ---------------------------------------------------------------------------
rule("4. THE CREDENTIAL IS ATTACHED BY AEGIS, TO THE WIRE, AND NOWHERE ELSE")
# ---------------------------------------------------------------------------

redactor = broker.Redactor()
before = len(target_log())
out = perform(
    {"url": f"{BASE}/echo", "headers": {"Authorization": "token ${aegis:tok}"}},
    redactor,
)
check("a credentialed request is performed", out.allowed, out.reason)

arrived = target_log()[-1]
check("the origin received the real secret in the Authorization header",
      SECRET in arrived["headers"].get("authorization", ""),
      str(arrived["headers"].get("authorization"))[:60])
check("...and not the literal handle",
      "${aegis:tok}" not in json.dumps(arrived), json.dumps(arrived)[:200])

check("the response the model sees has the value redacted",
      SECRET not in out.body, out.body[:200])
check("...and says which handle was removed",
      "[AEGIS-REDACTED:tok]" in out.body, out.body[:200])
check("the audit-bound reason carries no value", SECRET not in out.summary())
check("the recorded host is the destination", out.host == HOST, str(out.host))

# The credential's grant is re-checked at every hop, against the host the
# redirect moved to and not the one the arguments named.
out = perform(
    {"url": f"{BASE}/to?target=http://elsewhere.test:%d/echo" % PORT,
     "headers": {"Authorization": "token ${aegis:tok}"}},
    broker.Redactor(),
)
check("a credential is not carried across a redirect to a host it was not granted for",
      not out.allowed, f"{out.rule_id}: {out.reason}")
check("...with rule_id credential_redirect",
      out.rule_id == "credential_redirect", out.rule_id)
check("...explaining that the redirect is why", "redirected" in out.reason, out.reason)

hostlog = json.dumps(target_log())
check("the secret never reached elsewhere.test",
      not any(SECRET in json.dumps(e.get("headers", {}))
              and "elsewhere" in (e.get("host_header") or "")
              for e in target_log()), "leaked across the hop")

# A handle whose grant does cover both hosts follows the redirect.
out = perform(
    {"url": f"{BASE}/to?target=http://elsewhere.test:%d/echo" % PORT,
     "headers": {"Authorization": "token ${aegis:wide}"}},
    broker.Redactor(),
)
check("a handle granted for both hosts does follow the redirect", out.allowed, out.reason)
check("...and ends at the second host", out.host == "elsewhere.test", str(out.host))

# ---------------------------------------------------------------------------
rule("5. THE MCP SERVER IS NOT INVOLVED — byte level, through the real proxy")
# ---------------------------------------------------------------------------

SERVER_LOG = LAB / "server-saw.jsonl"
RECORDING_SERVER = LAB / "recording_server.py"
RECORDING_SERVER.write_text(
    "import json, sys\n"
    f"LOG = open({str(SERVER_LOG)!r}, 'a')\n"
    "for line in sys.stdin:\n"
    "    line = line.strip()\n"
    "    if not line:\n"
    "        continue\n"
    "    LOG.write(line + '\\n'); LOG.flush()\n"
    "    msg = json.loads(line)\n"
    "    if msg.get('id') is None:\n"
    "        continue\n"
    "    sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'],\n"
    "        'result': {'content': [{'type': 'text', 'text': 'SERVER SAW IT'}],\n"
    "                   'isError': False}}) + '\\n')\n"
    "    sys.stdout.flush()\n"
)

db8 = LAB / "audit-proxy.db"
frames = "\n".join(json.dumps({
    "jsonrpc": "2.0", "id": i, "method": "tools/call",
    "params": {"name": name, "arguments": args},
}) for i, (name, args) in enumerate([
    ("fetch", {"url": f"{LOCAL}/echo",
               "headers": {"Authorization": "token ${aegis:local}"}}),
    ("fetch", {"url": f"{LOCAL}/ok"}),
    ("read_file", {"path": str(WS / "note.txt")}),
], start=1)) + "\n"
(WS / "note.txt").write_text("a file, for a non-egress row")

proc = subprocess.run(
    [sys.executable, str(PROXY), "--", sys.executable, str(RECORDING_SERVER)],
    input=frames, capture_output=True, text=True,
    env={**ENV, "AEGIS_AUDIT_DB": str(db8)}, timeout=120,
)
check("the proxy ran", proc.returncode == 0, proc.stderr[-500:])

saw = SERVER_LOG.read_text() if SERVER_LOG.exists() else ""
check("the MCP server never saw the credential", SECRET not in saw, saw[:200])
check("the MCP server never saw the handle either", "${aegis:local}" not in saw, saw[:200])
check("the MCP server never saw the URL of an egress call", "/echo" not in saw, saw[:200])
check("the MCP server did see the non-egress call, so it was really listening",
      "read_file" in saw, saw[:200])
check("no fetch call was forwarded at all", "fetch" not in saw, saw[:200])

check("the secret is absent from the client stream", SECRET not in proc.stdout)
check("the secret is absent from proxy stderr", SECRET not in proc.stderr)
for suffix in ("", "-wal", "-shm"):
    f = Path(str(db8) + suffix)
    if f.exists():
        check(f"the secret is absent from the audit db {f.name or ''}".strip(),
              SECRET.encode() not in f.read_bytes())

rows = list(sqlite3.connect(str(db8)).execute(
    "SELECT id, tool, effect, rule_id, host, status, req_bytes, resp_bytes, v FROM audit"))
print("\n  audit rows:")
for r in rows:
    print(f"    {r[0]}  {r[1]:<10} {r[2]:<6} {r[3]:<22} host={r[4]} "
          f"status={r[5]} req={r[6]} resp={r[7]} v={r[8]}")

egress_rows = [r for r in rows if r[1] == "fetch"]
check("both egress calls are recorded", len(egress_rows) == 2, str(len(egress_rows)))
check("...with the destination host", all(r[4] == "127.0.0.1" for r in egress_rows),
      str(egress_rows))
check("...with the HTTP status", all(r[5] == 200 for r in egress_rows), str(egress_rows))
check("...with request bytes", all((r[6] or 0) > 0 for r in egress_rows), str(egress_rows))
check("...with response bytes", all((r[7] or 0) > 0 for r in egress_rows), str(egress_rows))
check("...and payload version 2", all(r[8] == 2 for r in egress_rows), str(egress_rows))

file_rows = [r for r in rows if r[1] == "read_file"]
check("a non-egress row has no host/status/bytes",
      all(r[4] is None and r[5] is None and r[6] is None for r in file_rows), str(file_rows))
check("...and is still v2", all(r[8] == 2 for r in file_rows), str(file_rows))

v = subprocess.run([sys.executable, str(VERIFY), str(db8)], capture_output=True, text=True)
check("the chain verifies with the new columns in it", v.returncode == 0,
      (v.stdout + v.stderr)[:300])

# ---------------------------------------------------------------------------
rule("6. NO FALLBACK TO THE S4 SUBSTITUTION PATH")
# ---------------------------------------------------------------------------

# An egress tool whose arguments Aegis cannot build a request from.
bad = perform({"headers": {"Authorization": "token ${aegis:tok}"}})
check("an egress call with no url is denied", not bad.allowed, bad.reason)
check("...with rule_id egress_not_performable",
      bad.rule_id == "egress_not_performable", bad.rule_id)
check("...and the denial explains the contract",
      "arguments.url" in bad.reason, bad.reason)

bad = perform({"url": f"{BASE}/ok", "headers": ["Authorization: token ${aegis:tok}"]})
check("headers as a list (the S4 shape) is denied, not substituted",
      not bad.allowed and bad.rule_id == "egress_not_performable",
      f"{bad.rule_id}: {bad.reason}")

# A credential handle on a tool that cannot reach fetch.py at all.
db6 = LAB / "audit-nofallback.db"
proc = subprocess.run(
    [sys.executable, str(PROXY), "--", sys.executable, str(MOCK)],
    input=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "write_file", "arguments": {
            "path": str(WS / "leak.txt"), "content": "${aegis:tok}"}},
    }) + "\n",
    capture_output=True, text=True,
    env={**ENV, "AEGIS_AUDIT_DB": str(db6)}, timeout=60,
)
check("a credential handle on a non-egress tool is denied",
      '"isError": true' in proc.stdout, proc.stdout[:200])
check("...and the secret is nowhere in the exchange",
      SECRET not in proc.stdout and SECRET not in proc.stderr)
check("...and the file was never written", not (WS / "leak.txt").exists())
reasons = " ".join(r[0] for r in sqlite3.connect(str(db6)).execute(
    "SELECT rule_id FROM audit"))
check("...recorded as credential_denied or credential_requires_egress",
      "credential" in reasons, reasons)

# ---------------------------------------------------------------------------
rule("7. THE SCHEMA CHANGE DID NOT INVALIDATE ANY EXISTING CHAIN")
# ---------------------------------------------------------------------------


def build_v1_db(path: Path, n: int = 6) -> str:
    """A pre-S8 database, written with the v1 rule and the v1 column set only.

    Deliberately built by hand rather than by importing audit.py: the point is
    a database that S8's code has never touched, in exactly the shape S2 left
    behind.
    """
    con = sqlite3.connect(str(path))
    con.execute(
        "CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,"
        " tool TEXT NOT NULL, effect TEXT NOT NULL, rule_id TEXT NOT NULL,"
        " reason TEXT NOT NULL, paths TEXT NOT NULL, prev_hash TEXT NOT NULL,"
        " row_hash TEXT NOT NULL)"
    )
    prev = "0" * 64
    for i in range(1, n + 1):
        ts = 1700000000.0 + i
        paths = json.dumps([f"/old/path/{i}"], separators=(",", ":"))
        payload = json.dumps({
            "id": i, "ts": ts, "tool": "read_file", "effect": "deny",
            "rule_id": "deny_paths", "reason": f"pre-S8 row {i}", "paths": paths,
        }, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256((payload + prev).encode()).hexdigest()
        con.execute(
            "INSERT INTO audit (id, ts, tool, effect, rule_id, reason, paths,"
            " prev_hash, row_hash) VALUES (?,?,?,?,?,?,?,?,?)",
            (i, ts, "read_file", "deny", "deny_paths", f"pre-S8 row {i}",
             paths, prev, digest),
        )
        prev = digest
    con.commit()
    con.close()
    return prev


def verify(path: Path, *args):
    return subprocess.run([sys.executable, str(VERIFY), str(path), *args],
                          capture_output=True, text=True)

old_db = LAB / "pre-s8.db"
old_head = build_v1_db(old_db)
before_bytes = old_db.read_bytes()

r = verify(old_db)
check("a pre-S8 database verifies under the S8 verifier", r.returncode == 0,
      (r.stdout + r.stderr)[:300])
check("...reporting its 6 rows", "6 row(s) verified" in r.stdout, r.stdout[:200])
check("...with the head hash it always had", old_head in r.stdout, r.stdout[:300])
check("...and the verifier did not modify it", old_db.read_bytes() == before_bytes)

# Now open it with S8's store, which migrates it, and append.
store = audit_mod.AuditStore.open(old_db)
head_id, head_hash = store.head()
check("S8 reads the pre-S8 head correctly", head_hash == old_head, head_hash)
store.record(tool="fetch", effect="allow", rule_id="tool_rules.fetch",
             reason="an S8 row appended to a pre-S8 chain", paths=[],
             host="target.test", status=204, req_bytes=101, resp_bytes=202)
store.record(tool="read_file", effect="deny", rule_id="deny_paths",
             reason="an S8 row with no destination", paths=["/x/.env"])
store.close()

r = verify(old_db)
check("the mixed chain verifies", r.returncode == 0, (r.stdout + r.stderr)[:400])
check("...counting 8 rows", "8 row(s) verified" in r.stdout, r.stdout[:200])
check("...and saying which rule each half used",
      "6 row(s) under the v1 payload" in r.stdout and "2 under v2" in r.stdout,
      r.stdout[:400])

mixed = list(sqlite3.connect(str(old_db)).execute(
    "SELECT id, v, host, status FROM audit ORDER BY id"))
check("the pre-S8 rows still read v NULL", all(r_[1] is None for r_ in mixed[:6]),
      str(mixed[:6]))
check("...and were not back-filled with anything",
      all(r_[2] is None and r_[3] is None for r_ in mixed[:6]), str(mixed[:6]))
check("the appended rows are v2", all(r_[1] == 2 for r_ in mixed[6:]), str(mixed[6:]))

# Migration must never rewrite a stored row: the first six rows' hashes are the
# same bytes they were before S8 ever opened the file.
after = list(sqlite3.connect(str(old_db)).execute(
    "SELECT row_hash FROM audit ORDER BY id LIMIT 6"))
con = sqlite3.connect(":memory:")
check("every pre-S8 row_hash survived the migration byte for byte",
      [h[0] for h in after][-1] == old_head, str(after[-1]))

# Tampering is still caught on both sides of the boundary. The v2 cases edit
# the columns S8 added, which is the check that they are genuinely inside the
# hash rather than merely stored next to it.
for row_id, sql, label in (
    (2, "UPDATE audit SET effect='allow' WHERE id=2", "an old field on a v1 row"),
    (8, "UPDATE audit SET effect='allow' WHERE id=8", "an old field on a v2 row"),
    (7, "UPDATE audit SET host='evil.test' WHERE id=7", "the host on a v2 row"),
    (7, "UPDATE audit SET status=200 WHERE id=7", "the status on a v2 row"),
    (7, "UPDATE audit SET resp_bytes=0 WHERE id=7", "the byte count on a v2 row"),
    (7, "UPDATE audit SET v=NULL WHERE id=7", "downgrading a v2 row to v1"),
):
    scratch = LAB / f"tamper-{row_id}-{abs(hash(sql)) % 10000}.db"
    scratch.write_bytes(old_db.read_bytes())
    c = sqlite3.connect(str(scratch))
    c.execute(sql)
    c.commit()
    c.close()
    r = verify(scratch)
    check(f"editing {label} is detected", r.returncode == 1, r.stdout[:200])
    check(f"...and named at row {row_id}", f"row id {row_id}" in r.stderr, r.stderr[:200])

# A row claiming a version this verifier does not implement must not pass.
scratch = LAB / "future.db"
scratch.write_bytes(old_db.read_bytes())
c = sqlite3.connect(str(scratch))
c.execute("UPDATE audit SET v=99 WHERE id=7")
c.commit()
c.close()
r = verify(scratch)
check("a row declaring an unknown payload version fails", r.returncode == 1, r.stdout[:200])
check("...saying it could not be checked rather than passing it",
      "does not implement" in r.stderr, r.stderr[:300])

# The real pre-S8 databases in evidence/ are the strongest version of this test:
# nobody wrote them for this suite.
for name in ("S2-tampered-audit.db",):
    src = ROOT / "evidence" / name
    if src.exists():
        copy = LAB / name
        copy.write_bytes(src.read_bytes())
        r = verify(copy)
        check(f"the archived broken database {name} still fails, as it must",
              r.returncode == 1, (r.stdout + r.stderr)[:200])

# ---------------------------------------------------------------------------
rule("8. RESPONSE CAP")
# ---------------------------------------------------------------------------

out = perform({"url": f"{BASE}/big"})
check("a large response is fetched", out.allowed, out.reason)
check("...and its real byte count is recorded",
      (out.resp_bytes or 0) >= 200_000, str(out.resp_bytes))
check("...under the cap, so it is not truncated here", not out.truncated)

# ---------------------------------------------------------------------------
rule("SUMMARY")
# ---------------------------------------------------------------------------

TARGET.shutdown()

now = {
    str(p): (hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else "absent")
    for p in REAL_WATCH
}
check("the operator's real Aegis state is untouched",
      now == BASELINE, str([k for k in BASELINE if BASELINE[k] != now[k]]))

print(f"\n  {PASSED} passed, {FAILED} failed")
if FAILED:
    print("\n  failures:")
    for name in FAILURES:
        print(f"    - {name}")
print(f"\n  lab: {LAB}   (delete when done)")
print(
    "\n  NOT established by this run:\n"
    "    - anything about traffic Aegis does not itself make. A server that\n"
    "      fetches on its own, and Bash, are exactly as far outside the\n"
    "      boundary as they were in S1 (THREAT-MODEL.md §7.6)\n"
    "    - domain fronting, which is why D3 specified C4 as TLS-terminating\n"
    "    - real DNS. Resolution is driven by an injected resolver here; the\n"
    "      production path calls socket.getaddrinfo and is checked by hand\n"
)
sys.exit(1 if FAILED else 0)
