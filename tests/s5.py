"""S5 harness: approval (C7), bulk threshold (C8), soft delete (C9), kill switch (C10).

Sections:
  1. C10 kill switch — beats deny_paths, survives restart, cheap enough
  2. C8  bulk threshold — escalates, and an allow rule cannot skip it
  3. C7  approval — approve, deny, timeout, EOF, garbage, against a REAL pty
  4. C7  no TTY — the fail-closed path, end to end through the proxy
  5. C9  soft delete — copies before forwarding, failed copy denies, restore works
  6.     audit coverage — every path lands with the right rule_id

Section 3 drives a real pty (`pty.openpty`) rather than a mock terminal, so the
prompt, `select` timeout and answer parsing are exercised against a real
character device. What it does NOT cover is a human answering a prompt on a
proxy's *controlling* terminal end to end; that needs a controlling tty in a
subprocess whose stdin and stdout are pipes, which did not work reliably here.
It is written up in tests/manual/approval-check.md and is recorded as
UNVERIFIED rather than skipped quietly — the S4 lesson.

SAFETY: everything runs in a temp directory. The kill switch and trash are
redirected there via AEGIS_AUDIT_DB, so this never touches your real data dir.
"""

import json
import os
import pty
import select
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "aegis"))

import approval  # noqa: E402
import killswitch  # noqa: E402
import trash  # noqa: E402
from policy import Effect, Policy, PolicyError  # noqa: E402

PROXY = ROOT / "aegis" / "proxy.py"
MOCK = ROOT / "tests" / "mock_fs_server.py"

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
    unverified.append(what)
    print(f"  NOT RUN  {what}")
    print(f"           why: {why}")
    if remedy:
        print(f"           to run it: {remedy}")


def rule(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


LAB = Path(tempfile.mkdtemp(prefix="aegis-s5-"))
WS = LAB / "workspace"
DATA = LAB / "data"
TRASH = LAB / "trash"
WS.mkdir()
DATA.mkdir()
DB = DATA / "audit.db"

# Point THIS process at the temp data directory before anything resolves a
# path from it. The kill switch lives beside audit.db, so without this the
# in-process checks below would engage the switch in the operator's real data
# directory — stopping their real agent, and leaving it stopped if this suite
# crashed between engage() and release(). Subprocesses inherit it via ENV.
os.environ["AEGIS_AUDIT_DB"] = str(DB)

_ks = killswitch.killswitch_path()
if LAB not in _ks.parents:
    sys.exit(
        f"refusing to run: the kill switch would resolve to {_ks}, outside the "
        f"temp lab {LAB}. This suite engages it, and it must never touch a real "
        f"data directory."
    )

POLICY_DOC = {
    "version": 1,
    "workspace_roots": [str(WS)],
    "deny_paths": [".env"],
    "default_effect": "deny",
    "ask_behavior": "prompt",
    "bulk_threshold": 10,
    "ask_timeout_seconds": 2,
    "trash_dir": str(TRASH),
    "tool_rules": {
        "read_file": {"effect": "allow", "within": ["<workspace>"]},
        "write_file": {"effect": "allow", "within": ["<workspace>"]},
        "read_many": {"effect": "allow", "within": ["<workspace>"]},
        "move_file": {"effect": "ask", "within": ["<workspace>"]},
        "delete_file": {"effect": "allow", "within": ["<workspace>"],
                        "destructive": True},
        "purge": {"effect": "deny", "destructive": True},
    },
}


def write_policy(doc=None, name="policy.json") -> Path:
    p = LAB / name
    p.write_text(json.dumps(doc or POLICY_DOC))
    p.chmod(0o600)
    return p


POLICY = write_policy()
ENV = {**os.environ, "AEGIS_POLICY": str(POLICY), "AEGIS_AUDIT_DB": str(DB)}


def load(**over):
    return Policy({**POLICY_DOC, **over}, POLICY)


def run_proxy(calls, env=None, timeout=60):
    """Run the proxy in a NEW SESSION, so it has no controlling terminal.

    Without os.setsid() this suite tests different things depending on how it
    was launched. From a terminal the proxy inherits that terminal, so an ASK
    prompts the person running the tests — who is not answering — and denies on
    timeout as approval_timeout. From a non-interactive shell there is no
    terminal, so the same call denies as ask_no_tty. The suite passed in the
    second environment and failed five checks in the first.

    A new session has no controlling tty until one is explicitly acquired, so
    this pins the headless path in both. It also stops the suite from writing
    approval prompts into the tester's terminal, which it should never have
    been doing. §3 covers the terminal-present paths against a real pty.
    """
    frames = "\n".join(json.dumps({
        "jsonrpc": "2.0", "id": i, "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }) for i, (name, args) in enumerate(calls, start=1)) + "\n"
    return subprocess.run(
        [sys.executable, str(PROXY), "--", sys.executable, str(MOCK)],
        input=frames, capture_output=True, text=True,
        env=env or ENV, timeout=timeout, preexec_fn=os.setsid,
    )


def audit_rows(db=DB):
    return list(sqlite3.connect(str(db)).execute(
        "SELECT id, effect, tool, rule_id, reason FROM audit ORDER BY id"))


def fixture(name="config.txt", body="conveyor_speed = 40\n") -> Path:
    p = WS / name
    p.write_text(body)
    return p


# ---- 1. C10 kill switch ---------------------------------------------------

rule("1. C10 KILL SWITCH")

fixture()
pol = load()
check(pol.killswitch_path == DATA / "KILLSWITCH",
      "kill switch lives in the data dir beside audit.db", str(pol.killswitch_path))

d = pol.evaluate("read_file", {"path": str(WS / "config.txt")}, WS)
check(d.effect is Effect.ALLOW, "before: an ordinary call is allowed", d.rule_id)

killswitch.engage("s5 test")
try:
    d = pol.evaluate("read_file", {"path": str(WS / "config.txt")}, WS)
    check(d.effect is Effect.DENY and d.rule_id == "killswitch",
          "engaged: an ordinary call is denied", f"{d.effect.value}/{d.rule_id}")

    # the ordering claim: it must beat deny_paths, which was previously first
    d = pol.evaluate("read_file", {"path": str(WS / ".env")}, WS)
    check(d.rule_id == "killswitch",
          "engaged: beats deny_paths (checked before every other rule)", d.rule_id)
    d = pol.evaluate("nonexistent_tool", {}, WS)
    check(d.rule_id == "killswitch", "engaged: beats default-deny too", d.rule_id)
    check("aegis-resume" in d.reason, "the denial tells you how to undo it", d.reason)

    # end to end, and it must apply to a proxy started AFTER it was thrown
    p = run_proxy([("read_file", {"path": str(WS / "config.txt")})])
    check(p.stdout.count('"isError": true') == 1, "engaged: proxy denies the call")
    check("killswitch" in p.stdout, "engaged: the frame names the rule", p.stdout[:160])
    rows = audit_rows()
    check(rows and rows[-1][3] == "killswitch", "engaged: audited with rule_id killswitch",
          str(rows[-1] if rows else None))

    # survives a restart: a second, fresh proxy is still stopped
    p2 = run_proxy([("read_file", {"path": str(WS / "config.txt")})])
    check("killswitch" in p2.stdout,
          "survives proxy restart (it is a file, not process state)")
finally:
    killswitch.release()

d = pol.evaluate("read_file", {"path": str(WS / "config.txt")}, WS)
check(d.effect is Effect.ALLOW, "released: calls flow again without a restart", d.rule_id)

# cheap enough to run per call
N = 20000
start = time.perf_counter()
for _ in range(N):
    killswitch.is_engaged(pol.killswitch_path)
per_call_us = (time.perf_counter() - start) / N * 1e6
check(per_call_us < 50, f"cost is {per_call_us:.1f}us per call (one stat)",
      f"{per_call_us:.1f}us")

check(killswitch.is_engaged(Path("/nonexistent-dir-xyz/KILLSWITCH")) is False,
      "a missing switch in a missing dir is 'not engaged', not an error")


# ---- 2. C8 bulk threshold -------------------------------------------------

rule("2. C8 BULK THRESHOLD")

many = [str(WS / f"f{i}.txt") for i in range(11)]
few = [str(WS / f"f{i}.txt") for i in range(10)]

d = pol.evaluate("read_many", {"paths": few}, WS)
check(d.effect is Effect.ALLOW, "10 paths at threshold 10 is allowed", d.rule_id)
d = pol.evaluate("read_many", {"paths": many}, WS)
check(d.effect is Effect.ASK and d.rule_id == "bulk_operation",
      "11 paths escalates to ASK", f"{d.effect.value}/{d.rule_id}")
check("11 paths" in d.reason and "10" in d.reason,
      "the reason states the count and the threshold", d.reason)

# the load-bearing claim: an allow rule must not skip it
check(POLICY_DOC["tool_rules"]["read_many"]["effect"] == "allow",
      "...and read_many is explicitly an allow rule")

d = load(bulk_threshold=1).evaluate("read_many", {"paths": few}, WS)
check(d.rule_id == "bulk_operation", "a lower threshold escalates sooner", d.rule_id)
d = load(bulk_threshold=500).evaluate("read_many", {"paths": many}, WS)
check(d.effect is Effect.ALLOW, "a higher threshold lets it through", d.rule_id)

# deny still wins over bulk: a denied call should not spend a human's attention
d = pol.evaluate("purge", {"paths": many}, WS)
check(d.effect is Effect.DENY and d.rule_id == "tool_rules.purge",
      "a denied tool with 11 paths is denied, not escalated", d.rule_id)
d = pol.evaluate("read_many", {"paths": many + [str(LAB / "outside.txt")]}, WS)
check(d.effect is Effect.DENY and "within" in d.rule_id,
      "an out-of-workspace path denies rather than prompting", d.rule_id)

for bad in (0, -1, "10", 1.5, True):
    try:
        load(bulk_threshold=bad)
        check(False, f"rejects bulk_threshold={bad!r}", "loaded")
    except PolicyError:
        check(True, f"rejects bulk_threshold={bad!r}")

no_key = Policy({k: v for k, v in POLICY_DOC.items() if k != "bulk_threshold"}, POLICY)
check(no_key.bulk_threshold == 10, "default threshold is 10 when the key is absent",
      str(no_key.bulk_threshold))


# ---- 3. C7 approval against a real pty ------------------------------------

rule("3. C7 APPROVAL — real pty, real select, real timeout")


def ask_on_pty(answer: bytes | None, timeout=2.0, delay=0.05):
    """Drive approval.prompt_on() over a real pty. Returns (resolution, seen)."""
    master, slave = pty.openpty()
    stream = os.fdopen(slave, "r+b", buffering=0)
    seen = bytearray()
    stop = threading.Event()

    def responder():
        """Keep draining the master end until told to stop — the prompt writes
        again *after* the answer (APPROVED / DENIED / TIMED OUT), and a
        responder that stops at 'Approve?' would never see it."""
        sent = False
        while not stop.is_set():
            r, _, _ = select.select([master], [], [], 0.05)
            if r:
                seen.extend(os.read(master, 4096))
            if answer is not None and not sent and b"Approve?" in seen:
                time.sleep(delay)
                os.write(master, answer)
                sent = True

    t = threading.Thread(target=responder, daemon=True)
    t.start()
    result = approval.prompt_on(
        stream, "move_file", "tool_rules.move_file",
        "policy marks this tool as requiring human approval",
        [str(WS / "config.txt"), str(WS / "notes.txt")], timeout=timeout,
    )
    time.sleep(0.15)  # let the closing line reach the master end
    stop.set()
    t.join(timeout + 3)
    while select.select([master], [], [], 0.05)[0]:
        seen.extend(os.read(master, 4096))
    try:
        stream.close()
        os.close(master)
    except OSError:
        pass
    return result, bytes(seen)


res, seen = ask_on_pty(b"y\n")
check(res.approved and res.rule_id == "approval_granted", "'y' approves",
      f"{res.rule_id}: {res.detail}")
check(b"AEGIS" in seen and b"move_file" in seen, "the prompt names the tool", seen[:120])
check(b"config.txt" in seen, "the prompt lists the paths")
check(b"tool_rules.move_file" in seen, "the prompt names the rule that triggered it")
check(b"Denied automatically in 2s" in seen, "the prompt states the timeout consequence",
      seen[-200:])
check("@" in res.resolver and "/dev/" in res.resolver,
      "the resolver is recorded as user@host via tty", res.resolver)

res, _ = ask_on_pty(b"yes\n")
check(res.approved, "'yes' approves")
res, _ = ask_on_pty(b"n\n")
check(not res.approved and res.rule_id == "approval_denied", "'n' denies", res.rule_id)
res, _ = ask_on_pty(b"\n")
check(not res.approved and res.rule_id == "approval_denied", "an empty line denies",
      res.rule_id)
res, _ = ask_on_pty(b"maybe later\n")
check(not res.approved and res.rule_id == "approval_denied",
      "anything not affirmative denies", res.rule_id)
res, _ = ask_on_pty(b"Y\n")
check(res.approved, "'Y' approves (case-insensitive)")

start = time.time()
res, seen = ask_on_pty(None, timeout=1.0)
elapsed = time.time() - start
check(not res.approved and res.rule_id == "approval_timeout",
      "no answer times out to DENY", res.rule_id)
check(0.9 < elapsed < 3.0, f"timeout fired at {elapsed:.1f}s (asked for 1.0s)",
      f"{elapsed:.2f}s")
check(b"TIMED OUT" in seen, "the terminal is told it timed out")


# ---- 4. C7 no TTY, end to end --------------------------------------------

rule("4. C7 NO CONTROLLING TERMINAL — end to end through the proxy")

available, why = approval.controlling_tty_available()
print(f"  this process: controlling tty available = {available}"
      f"{'' if available else f' ({why})'}")
print("  the proxy below is run with os.setsid(), so it has none either way\n")

check(approval.controlling_tty_available("/dev/null")[0] is False,
      "a non-terminal device is not mistaken for a terminal",
      str(approval.controlling_tty_available("/dev/null")))

os.remove(DB)
started = time.time()
p = run_proxy([("move_file", {"source": str(WS / "config.txt"),
                              "destination": str(WS / "moved.txt")})])
elapsed = time.time() - started
check('"isError": true' in p.stdout, "an ASK with no tty is denied")
check("ask_no_tty" in p.stdout, "...with rule_id ask_no_tty", p.stdout[:200])
# The point of detecting absence up front: no stall, and an audit record that
# says nobody was there rather than that somebody declined to answer.
check(elapsed < POLICY_DOC["ask_timeout_seconds"],
      f"...denied immediately, not after the {POLICY_DOC['ask_timeout_seconds']}s "
      f"timeout (took {elapsed:.2f}s)", f"{elapsed:.2f}s")
check("approval_timeout" not in p.stdout,
      "...and NOT recorded as a timeout — nobody present is a different event",
      p.stdout[:200])
check("not attempted" in p.stdout.lower() or "was not forwarded" in p.stdout,
      "the model is told the call did not run", p.stdout[:220])
check(not (WS / "moved.txt").exists(), "the server never performed the move")
rows = audit_rows()
check(any(r[3] == "approval_prompt" for r in rows),
      "the prompt attempt is audited", str(rows))
check(any(r[3] == "ask_no_tty" for r in rows), "the resolution is audited", str(rows))
check(any("no human could be asked" in r[4] for r in rows),
      "the audit says why it was denied", str(rows))
check(not any(r[3] == "approval_timeout" for r in rows),
      "no approval_timeout row: the audit distinguishes absent from unanswered",
      str([r[3] for r in rows]))

p = run_proxy([("read_many", {"paths": many})])
check("bulk_operation" in p.stdout or "ask_no_tty" in p.stdout,
      "a bulk escalation with no tty also denies", p.stdout[:200])
check(not any(Path(m).exists() for m in many), "no bulk work was performed")

d = load(ask_behavior="deny").evaluate(
    "move_file", {"source": str(WS / "config.txt"), "destination": str(WS / "m.txt")}, WS)
check(d.effect is Effect.DENY, "ask_behavior=deny still collapses ASK for headless use",
      d.rule_id)
try:
    load(ask_behavior="allow")
    check(False, "ask_behavior=allow is refused", "loaded")
except PolicyError:
    check(True, "ask_behavior=allow is refused at load")


# ---- 5. C9 soft delete ----------------------------------------------------

rule("5. C9 SOFT DELETE")

os.remove(DB)
target = fixture("doomed.txt", "important data\n")
(WS / "sub").mkdir(exist_ok=True)
(WS / "sub" / "nested.txt").write_text("nested\n")

p = run_proxy([("delete_file", {"path": str(target)})])
check('"isError": false' in p.stdout or "MOCK SERVER" in p.stdout,
      "a destructive call is forwarded once staged", p.stdout[:160])
snaps = trash.snapshots(TRASH)
check(len(snaps) == 1, f"one snapshot written ({len(snaps)})")
saved = snaps[0]["saved"] if snaps else []
check(len(saved) == 1, "the target was copied")
check(Path(saved[0]["stored"]).read_text() == "important data\n" if saved else False,
      "the copy has the original contents")
check(str(target) in saved[0]["original"] if saved else False,
      "the manifest records where it came from")
check(snaps[0]["tool"] == "delete_file", "the manifest records the tool")
rows = audit_rows()
check(any("copied to trash" in r[4] for r in rows),
      "the audit records that a copy was made", str(rows[-1]))

# the copy must happen BEFORE forwarding: prove ordering by deleting the
# original afterwards and restoring from trash
target.unlink()
restored, skipped = trash.restore(TRASH, snaps[0]["snapshot_id"])
check(restored == 1 and target.exists(), "aegis-restore puts it back",
      f"restored={restored} skipped={skipped}")
check(target.read_text() == "important data\n", "restored contents are identical")
restored2, skipped2 = trash.restore(TRASH, snaps[0]["snapshot_id"])
check(restored2 == 0 and skipped2, "restore refuses to overwrite without --force",
      str(skipped2))
restored3, _ = trash.restore(TRASH, snaps[0]["snapshot_id"], force=True)
check(restored3 == 1, "--force overwrites")

# a failed copy must deny
os.remove(DB)
readonly_trash = LAB / "ro-trash"
readonly_trash.mkdir()
readonly_trash.chmod(0o500)
ro_policy = write_policy({**POLICY_DOC, "trash_dir": str(readonly_trash)},
                         "ro-policy.json")
survivor = fixture("survivor.txt", "must not be deleted\n")
p = run_proxy([("delete_file", {"path": str(survivor)})],
              env={**ENV, "AEGIS_POLICY": str(ro_policy)})
check('"isError": true' in p.stdout, "a failed copy denies the call", p.stdout[:200])
check("trash_failed" in p.stdout, "...with rule_id trash_failed", p.stdout[:220])
check(survivor.exists(), "the file was not touched")
readonly_trash.chmod(0o700)
rows = audit_rows()
check(any(r[3] == "trash_failed" for r in rows), "the failure is audited", str(rows))

# a missing target is not a failure
os.remove(DB)
p = run_proxy([("delete_file", {"path": str(WS / "never-existed.txt")})])
check('"isError": false' in p.stdout or "MOCK" in p.stdout,
      "deleting a nonexistent file is not blocked by C9", p.stdout[:160])
check(any(m["missing"] for m in trash.snapshots(TRASH)),
      "...and is recorded as 'missing' in the manifest")

# a policy that declares destructive tools without a trash dir must not load
try:
    Policy({**POLICY_DOC, "trash_dir": None}, POLICY)
    check(False, "destructive without trash_dir is refused", "loaded")
except PolicyError as exc:
    check(True, f"destructive without trash_dir is refused: {str(exc)[:44]}")
try:
    Policy({**POLICY_DOC, "trash_dir": str(WS / "trash")}, POLICY)
    check(False, "trash_dir inside the workspace is refused", "loaded")
except PolicyError as exc:
    check(True, f"trash_dir inside the workspace is refused: {str(exc)[:40]}")


# ---- 6. audit coverage ----------------------------------------------------

rule("6. AUDIT COVERAGE AND CHAIN INTEGRITY")

v = subprocess.run([sys.executable, str(ROOT / "aegis" / "verify.py"), str(DB)],
                   capture_output=True, text=True)
check(v.returncode == 0, "the chain still verifies over S5 rows",
      (v.stdout + v.stderr)[:160])

os.remove(DB)
killswitch.engage("audit coverage")
run_proxy([("read_file", {"path": str(WS / "config.txt")})])
killswitch.release()
run_proxy([("move_file", {"source": str(WS / "config.txt"),
                          "destination": str(WS / "m2.txt")})])
run_proxy([("read_many", {"paths": many})])
seen_rules = {r[3] for r in audit_rows()}
for expected in ("killswitch", "approval_prompt", "ask_no_tty"):
    check(expected in seen_rules, f"rule_id {expected!r} appears in the audit",
          str(sorted(seen_rules)))
check("bulk_operation" in str(audit_rows()),
      "the bulk escalation is traceable in the audit", str(sorted(seen_rules)))

mark_unverified(
    "C7 end to end: a human answering on a live proxy's controlling terminal",
    "giving a subprocess a controlling tty while its stdin and stdout are pipes "
    "did not work reliably here; §3 covers the prompt, timeout and parsing "
    "against a real pty, and §4 covers the no-tty denial end to end",
    "run tests/manual/approval-check.md by hand",
)

shutil.rmtree(LAB, ignore_errors=True)

rule("SUMMARY")
print(f"  {passed} passed, {failed} failed, {len(unverified)} NOT RUN")
if unverified:
    print("\n  Not established by this run:")
    for item in unverified:
        print(f"    - {item}")
    print("\n  The suite exits non-zero because of it.")
sys.exit(1 if (failed or unverified) else 0)
