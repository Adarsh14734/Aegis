"""S3b harness: the three scoped fixes from S3a findings.

  1. Egress checks apply only to tools declaring "egress": true, and a policy
     whose tool *names* suggest fetching without declaring the flag is refused.
  2. AuditStore.open() survives concurrent boot — 16 real proxies, one database.
  3. The head anchor is written on clean shutdown and picked up by verify.py.

Section 2 launches 16 proxy processes at once. It is the slowest part of the
suite and the reason this file exists separately from tests/s3a.py.

SAFETY: everything runs in a temp directory. Fake credentials only.
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "aegis"))

from policy import Policy, PolicyError  # noqa: E402

PROXY = ROOT / "aegis" / "proxy.py"
VERIFY = ROOT / "aegis" / "verify.py"
MOCK = ROOT / "tests" / "mock_fs_server.py"

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


# --- labguard: pins every Aegis path into a temp lab and verifies it, in this
# --- process AND in a child, before anything runs. Five suites have written to
# --- the operator's real installation because env pinning failed silently; this
# --- aborts instead. See tests/labguard.py.
sys.path.insert(0, str(ROOT / "tests"))
import labguard  # noqa: E402

LAB = labguard.pin("aegis-s3b-")
WS = LAB / "workspace"
WS.mkdir()
(WS / "config.txt").write_text("conveyor_speed = 40\n")

BASE_RULES = {
    "read_file": {"effect": "allow", "within": ["<workspace>"]},
    "write_file": {"effect": "allow", "within": ["<workspace>"]},
    "fetch": {"effect": "allow", "egress": True},
}


def make_policy(rules=None, domains=("example.com",), name="policy.json") -> Path:
    p = LAB / name
    p.write_text(json.dumps({
        "version": 1,
        "workspace_roots": [str(WS)],
        "deny_paths": [".env"],
        "allowed_domains": list(domains),
        "default_effect": "deny",
        "ask_behavior": "deny",
        "tool_rules": BASE_RULES if rules is None else rules,
    }))
    p.chmod(0o600)
    return p


def load_rules(rules):
    return Policy({
        "version": 1,
        "workspace_roots": [str(WS)],
        "default_effect": "deny",
        "tool_rules": rules,
    }, LAB / "policy.json")


# ---- FIX 1 -----------------------------------------------------------------

rule("FIX 1 — egress applies only to tools declaring \"egress\": true")

pol = Policy(json.loads(make_policy().read_text()), LAB / "policy.json")
URL_DOC = "See https://docs.python.org/3/library/json.html\n"

cases = [
    ("write_file with a URL in content is ALLOWED (the S3a false positive)",
     "write_file", {"path": str(WS / "README.md"), "content": URL_DOC}, "allow", None),
    ("write_file with an SSRF-looking URL is still ALLOWED (not a destination)",
     "write_file", {"path": str(WS / "n.md"), "content": "http://169.254.169.254/"},
     "allow", None),
    ("fetch to an unlisted host is DENIED",
     "fetch", {"url": "https://docs.python.org/x"}, "deny", "egress_domain"),
    ("fetch to an allowed host is ALLOWED",
     "fetch", {"url": "https://example.com/x"}, "allow", None),
    ("fetch to cloud metadata is DENIED",
     "fetch", {"url": "http://169.254.169.254/latest/meta-data/"}, "deny", "egress_domain"),
    ("DLP still fires on a non-egress tool",
     "write_file", {"path": str(WS / "d.sh"), "content": "AKIAIOSFODNN7EXAMPLE"},
     "deny", "dlp"),
    ("DLP still fires on an egress tool",
     "fetch", {"url": "https://example.com/x", "body": "ghp_"
               "0123456789abcdefghijklmnopqrstuvwxyz"}, "deny", "dlp"),
    ("deny_paths still outranks everything",
     "write_file", {"path": str(WS / ".env"), "content": URL_DOC}, "deny", "deny_paths"),
]
for label, tool, args, want_effect, want_rule in cases:
    d = pol.evaluate(tool, args, WS)
    ok = d.effect.value == want_effect and (want_rule is None or d.rule_id == want_rule)
    check(ok, label, f"got {d.effect.value}/{d.rule_id}: {d.reason}")

# an unknown tool carrying a URL is still default-denied, not egress-denied
d = pol.evaluate("exec_shell", {"url": "https://evil.xyz"}, WS)
check(d.effect.value == "deny" and d.rule_id == "default_effect",
      "unknown tool with a URL falls to default-deny", f"{d.effect.value}/{d.rule_id}")

# explicit egress:false behaves as absent
d = load_rules({"summarize": {"effect": "allow", "egress": False}}).evaluate(
    "summarize", {"text": "https://evil.xyz"}, WS)
check(d.effect.value == "allow", 'explicit "egress": false skips the check', d.reason)

print()
NAMEY = ["fetch_url", "http_get", "web_search", "my_api_call", "downloader",
         "curl_wrapper", "browse_page", "url_open", "send_request", "WebFetch",
         "mcp__browser__open"]
for name in NAMEY:
    try:
        load_rules({name: {"effect": "allow"}})
        check(False, f"refuses to load: {name!r} without an egress flag", "loaded")
    except PolicyError as exc:
        check(name in str(exc), f"refuses to load: {name!r} without an egress flag",
              str(exc)[:70])

print()
for name in NAMEY[:4]:
    for flag in (True, False):
        try:
            load_rules({name: {"effect": "allow", "egress": flag}})
            check(True, f"loads: {name!r} declaring egress={flag}")
        except PolicyError as exc:
            check(False, f"loads: {name!r} declaring egress={flag}", str(exc)[:70])

print()
QUIET = ["read_file", "write_file", "read_text_file", "list_directory",
         "directory_tree", "search_files", "get_file_info", "move_file",
         "edit_file", "create_directory", "delete_file", "read_media_file",
         "list_allowed_directories", "read_multiple_files",
         "list_directory_with_sizes"]
try:
    load_rules({n: {"effect": "allow"} for n in QUIET})
    check(True, f"{len(QUIET)} ordinary filesystem tool names need no flag")
except PolicyError as exc:
    check(False, "ordinary filesystem tool names need no flag", str(exc)[:90])

for bad in ("yes", 1, None, "true"):
    try:
        load_rules({"summarize": {"effect": "allow", "egress": bad}})
        check(False, f"rejects non-boolean egress {bad!r}", "loaded")
    except PolicyError as exc:
        check(True, f"rejects non-boolean egress {bad!r}: {str(exc)[:45]}")


# ---- FIX 2 -----------------------------------------------------------------

rule("FIX 2 — 16 concurrent proxies against one audit database")

CONC = LAB / "conc"
CONC.mkdir()
CDB = CONC / "audit.db"
CPOLICY = make_policy(name="conc-policy.json")
N_PROXIES, N_CALLS = 16, 12

frames = "\n".join(json.dumps({
    "jsonrpc": "2.0", "id": i, "method": "tools/call",
    "params": {"name": "read_file", "arguments": {"path": str(WS / "config.txt")}},
}) for i in range(1, N_CALLS + 1)) + "\n"

env = {**os.environ, "AEGIS_POLICY": str(CPOLICY), "AEGIS_AUDIT_DB": str(CDB)}
started = time.time()
procs = [
    subprocess.Popen(
        [sys.executable, str(PROXY), "--", sys.executable, str(MOCK)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, text=True,
    )
    for _ in range(N_PROXIES)
]
outs = []
for p in procs:
    outs.append(p.communicate(input=frames, timeout=120))
elapsed = time.time() - started

codes = [p.returncode for p in procs]
refused = [err for _, err in outs if "refusing to start" in err]
locked = [err for _, err in outs if "database is locked" in err]
print(f"  {N_PROXIES} proxies x {N_CALLS} calls in {elapsed:.1f}s")
check(all(c == 0 for c in codes), "every proxy exited 0", f"codes={codes}")
check(not refused, f"zero boot failures", f"{len(refused)} refused to start")
check(not locked, "no 'database is locked' reached stderr", f"{len(locked)} saw it")

ids = [r[0] for r in sqlite3.connect(str(CDB)).execute("SELECT id FROM audit ORDER BY id")]
check(len(ids) == N_PROXIES * N_CALLS,
      f"all {N_PROXIES * N_CALLS} rows written", f"got {len(ids)}")
check(ids == list(range(1, len(ids) + 1)), "id sequence is contiguous",
      f"gaps at {sorted(set(range(1, max(ids)+1)) - set(ids))[:5]}")

v = subprocess.run([sys.executable, str(VERIFY), str(CDB)], capture_output=True, text=True)
check(v.returncode == 0, "chain verifies after concurrent writes",
      (v.stdout + v.stderr).strip()[:160])
check("journal_mode=wal" not in v.stdout,
      "verify did not need to alter the database")
mode = sqlite3.connect(str(CDB)).execute("PRAGMA journal_mode").fetchone()[0]
check(mode.lower() == "wal", "database is still in WAL mode", mode)


# ---- FIX 3 -----------------------------------------------------------------

rule("FIX 3 — head anchor written on shutdown, read back by verify.py")

ANCHOR = CONC / "aegis-head.txt"
check(ANCHOR.exists(), "aegis-head.txt written next to the db")
check(oct(ANCHOR.stat().st_mode & 0o777) == "0o600",
      "anchor is mode 0600", oct(ANCHOR.stat().st_mode & 0o777))
body = ANCHOR.read_text()
print("\n" + "\n".join(f"    {ln}" for ln in body.strip().splitlines()) + "\n")
fields = dict(l.split("=", 1) for l in body.splitlines() if "=" in l and not l.startswith("#"))
check(fields.get("db") == "audit.db", "anchor names the database it describes")
check(len(fields.get("head_hash", "")) == 64, "anchor carries a full 64-char hash")
check("NOT tamper-proof" in body, "anchor states its own limitation in the file")

out = subprocess.run([sys.executable, str(VERIFY), str(CDB)],
                     capture_output=True, text=True).stdout
check("aegis-head.txt" in out, "verify reports the anchor source it used", out[:120])
check("not tamper-proof" in out, "verify states the anchor is not tamper-proof")

# no anchor -> says so rather than implying it checked one
solo = LAB / "solo"
solo.mkdir()
shutil.copy(CDB, solo / "audit.db")
out = subprocess.run([sys.executable, str(VERIFY), str(solo / "audit.db")],
                     capture_output=True, text=True).stdout
check("anchor: none" in out, "no anchor file -> 'anchor: none'", out[:120])
check("would not be visible" in out, "and says truncation would be invisible")

out = subprocess.run([sys.executable, str(VERIFY), str(CDB), "--no-anchor"],
                     capture_output=True, text=True).stdout
check("anchor: none" in out, "--no-anchor ignores the file")


def fresh(name: str) -> Path:
    d = LAB / name
    d.mkdir()
    shutil.copy(CDB, d / "audit.db")
    shutil.copy(ANCHOR, d / "aegis-head.txt")
    return d / "audit.db"


print()
# truncation: the whole point of the anchor
t = fresh("trunc")
con = sqlite3.connect(str(t))
con.execute(f"DELETE FROM audit WHERE id > {len(ids) - 5}")
con.commit()
con.close()
r = subprocess.run([sys.executable, str(VERIFY), str(t)], capture_output=True, text=True)
check(r.returncode == 1, "truncated tail is caught by the anchor", r.stdout[:120])
check("shorter than its own anchor" in r.stderr, "and the message says what happened",
      r.stderr[:120])
r2 = subprocess.run([sys.executable, str(VERIFY), str(t), "--no-anchor"],
                    capture_output=True, text=True)
check(r2.returncode == 0, "the same truncation is invisible without the anchor "
                          "(this is the limitation, not a pass)")

# full rewrite: anchored row no longer matches
w = fresh("rewrite")
con = sqlite3.connect(str(w))
# Must be an actual change: every row in this database is already
# effect='allow', so flipping it to 'allow' would rebuild an identical chain
# and prove nothing. Flip it to deny and rewrite the reason.
con.execute("UPDATE audit SET effect='deny', reason='tampered' WHERE id=1")
import hashlib  # noqa: E402 - attacker simulation, kept local

def rewrite_chain(con, hashlib, json):
    """Recompute every row_hash, the way an attacker with write access would.

    S8: rows carry a payload version, so a forger has to use the rule each row
    declares. Updating this simulation is not a fix — it is what keeps the
    demonstration honest. If it kept computing the v1 rule, the verifier would
    catch the forgery for the wrong reason (a stale attacker) and the report
    would claim a defence that does not exist. THREAT-MODEL.md §7.2 still
    stands: nothing local stops this.
    """
    has_v = "v" in {r[1] for r in con.execute("PRAGMA table_info(audit)")}
    cols = ("id", "ts", "tool", "effect", "rule_id", "reason", "paths")
    extra = ("v", "host", "status", "req_bytes", "resp_bytes")
    select = ", ".join(cols + (extra if has_v else ()))
    prev = "0" * 64
    for row in con.execute(f"SELECT {select} FROM audit ORDER BY id").fetchall():
        vals = dict(zip(cols + (extra if has_v else ()), row))
        if has_v and vals.get("v") == 2:
            payload = {k: vals[k] for k in ("v",) + cols + extra[1:]}
        else:
            payload = {k: vals[k] for k in cols}
        h = hashlib.sha256(
            (json.dumps(payload, sort_keys=True, separators=(",", ":")) + prev).encode()
        ).hexdigest()
        con.execute("UPDATE audit SET prev_hash=?, row_hash=? WHERE id=?",
                    (prev, h, vals["id"]))
        prev = h
    return prev


rewrite_chain(con, hashlib, json)
con.commit()
con.close()
r = subprocess.run([sys.executable, str(VERIFY), str(w)], capture_output=True, text=True)
check(r.returncode == 1, "wholesale chain rewrite is caught by the anchor", r.stdout[:120])

# growth past the anchor is normal, not an alarm
g = fresh("growth")
sys.path.insert(0, str(ROOT / "aegis"))
from audit import AuditStore  # noqa: E402

s = AuditStore.open(g)
for _ in range(7):
    s.record(tool="read_file", effect="allow", rule_id="tool_rules.read_file",
             reason="matched allow rule", paths=[])
s.conn.close()  # no clean shutdown, so the anchor stays behind the log
r = subprocess.run([sys.executable, str(VERIFY), str(g)], capture_output=True, text=True)
check(r.returncode == 0, "rows appended past a stale anchor still verify",
      (r.stdout + r.stderr)[:160])
check("appended since" in r.stdout, "and the growth is reported", r.stdout[:160])

# a corrupted anchor is suspicious, not absent
c = fresh("corrupt")
(c.parent / "aegis-head.txt").write_text("head_hash=garbage\n")
r = subprocess.run([sys.executable, str(VERIFY), str(c)], capture_output=True, text=True)
check(r.returncode == 1, "an unparseable anchor fails rather than being ignored",
      r.stderr[:120])

# an anchor for a different db must not be applied to this one
o = fresh("othername")
renamed = o.parent / "audit.db.pre-reset-20260815"
o.rename(renamed)
r = subprocess.run([sys.executable, str(VERIFY), str(renamed)],
                   capture_output=True, text=True)
check(r.returncode == 0 and "anchor: none" in r.stdout,
      "an anchor naming another db is ignored, not misapplied",
      (r.stdout + r.stderr)[:160])

shutil.rmtree(LAB, ignore_errors=True)

rule("SUMMARY")
print(f"  {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
