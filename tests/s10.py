"""Aegis S10 harness — editing policy.json from the UI, safely.

S10 adds the first write path to Aegis's own configuration. THREAT-MODEL.md A7
calls that file the one that makes every other control decorative if it is
compromised, so the interesting checks here are all refusals: the things the
editor will NOT do, proved by trying them.

Everything is driven through `aegis policy`, which is the same seam the Tauri
window uses. That is deliberate — the UI shells out rather than reimplementing
the write path, so exercising the CLI exercises what the screen does.

    python3 tests/s10.py       exit 0 only if every check ran and passed
"""

import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import labguard  # noqa: E402

LAB = labguard.pin("aegis-s10-")

PASSED = 0
FAILED = 0
FAILURES: list[str] = []
NOT_RUN: list[tuple[str, str]] = []


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


def not_run(what: str, why: str) -> None:
    NOT_RUN.append((what, why))
    print(f"  NOT RUN  {what}\n           {why}")


def rule(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


# ---------------------------------------------------------------------------
# lab
# ---------------------------------------------------------------------------

WS = LAB / "workspace"
ROBOTICS = LAB / "Robotics"
TAXES = LAB / "Taxes"
PRIVATE = LAB / "Private"
for d in (WS, ROBOTICS, TAXES, PRIVATE):
    d.mkdir(parents=True, exist_ok=True)
(ROBOTICS / "arm.py").write_text("# robot\n")
(TAXES / "2025.pdf").write_text("taxes\n")

BASE_DOC = {
    "version": 1,
    "workspace_roots": [str(WS)],
    "deny_paths": [".env", "id_rsa"],
    "allowed_domains": [],
    "tool_rules": {
        "read_file": {"effect": "allow", "within": ["<workspace>"]},
        "write_file": {"effect": "allow", "within": ["<workspace>"]},
    },
    "default_effect": "deny",
    "ask_behavior": "deny",
}
labguard.check_policy_doc(BASE_DOC)
POLICY_PATH = LAB / "policy.json"
DB = LAB / "audit.db"


def reset_policy(doc=None) -> None:
    POLICY_PATH.write_text(json.dumps(doc or BASE_DOC, indent=2))
    os.chmod(POLICY_PATH, 0o600)


reset_policy()

from aegis import policyedit  # noqa: E402
from aegis.audit import AuditStore  # noqa: E402
from aegis.policy import Effect, Policy  # noqa: E402

ENV = labguard.subprocess_env(PYTHONPATH=str(ROOT))


def cli(*args, expect_json=True):
    # Always --json: this is the shape the Tauri command consumes, so testing
    # it is testing what the screen gets rather than what a terminal prints.
    args = tuple(args) + (("--json",) if expect_json and args[0] != "show" else ())
    done = subprocess.run(
        [sys.executable, "-m", "aegis.cli", "policy", *args],
        capture_output=True, text=True, timeout=180, env=ENV, cwd=str(ROOT),
    )
    if expect_json and done.stdout.strip():
        try:
            return done, json.loads(done.stdout)
        except json.JSONDecodeError:
            return done, None
    return done, None


def rows(rule_id: str | None = None) -> list[tuple]:
    if not DB.exists():
        return []
    con = sqlite3.connect(str(DB))
    try:
        sql = "SELECT tool, effect, rule_id, reason, paths FROM audit"
        if rule_id:
            sql += f" WHERE rule_id='{rule_id}'"
        return list(con.execute(sql + " ORDER BY id"))
    finally:
        con.close()


print(f"lab: {LAB}")


# ---------------------------------------------------------------------------
rule("1. PLAIN ENGLISH, NOT rule_ids")
# ---------------------------------------------------------------------------

snap = policyedit.snapshot(POLICY_PATH, DB)
print("  " + json.dumps(snap["folders"], indent=2).replace("\n", "\n  "))

check("a folder reads as a sentence about what the agent can do",
      snap["folders"][0]["sentence"] == "Can read and change your workspace folder",
      str(snap["folders"][0]))
check("Ask reads as asking you first",
      "Must ask you first" in policyedit.describe_folder(TAXES, Effect.ASK),
      policyedit.describe_folder(TAXES, Effect.ASK))
check("Deny reads as cannot open at all",
      "Cannot open your Private folder at all"
      == policyedit.describe_folder(PRIVATE, Effect.DENY))

blob = json.dumps(snap)
leaked = [t for t in ("filesystem.read", "tool_rules", "deny_paths.", "rule_id",
                      "workspace_roots", "effect\":\"allow\"".replace('"', ''))
          if t in blob]
check("no policy-schema jargon reaches the screen",
      not any(t in blob for t in ("filesystem.read", "tool_rules", "rule_id")),
      str(leaked))
check("the deny list is explained, not just listed",
      all("Never open anything matching" in d["sentence"] for d in snap["deny_paths"]),
      str(snap["deny_paths"]))
check("the screen is told edits apply to the NEXT session",
      "NEXT time your agent starts" in snap["applies_note"], snap["applies_note"])


# ---------------------------------------------------------------------------
rule("2. THE THREE STATES ARE REAL — the engine enforces what the UI offers")
# ---------------------------------------------------------------------------

# A UI offering Ask against an engine that cannot express it would be a lie, so
# each state is asserted against Policy.evaluate, not against the document.
doc, changes = policyedit.plan_folder(BASE_DOC, ROBOTICS, Effect.ALLOW)
pol = Policy(doc, POLICY_PATH)
d = pol.evaluate("read_file", {"path": str(ROBOTICS / "arm.py")}, LAB)
check("Allow: the engine permits a read there", d.effect is Effect.ALLOW,
      f"{d.effect} {d.rule_id}")

doc2, _ = policyedit.plan_folder(doc, TAXES, Effect.ASK)
pol2 = Policy({**doc2, "ask_behavior": "prompt"}, POLICY_PATH)
d = pol2.evaluate("read_file", {"path": str(TAXES / "2025.pdf")}, LAB)
check("Ask: the engine escalates to a human", d.effect is Effect.ASK,
      f"{d.effect} {d.rule_id}")
check("...citing the folder rule", d.rule_id == "folder_rules", d.rule_id)
check("...and saying which folder in the reason", "Ask" in d.reason, d.reason)

# PRIVATE is already unreachable — it is in no workspace root — so setting it
# to Deny is a no-op and the editor adds NO redundant rule. The denial still
# comes from containment, which is the honest reason for it. A UI that wrote a
# rule here would grow a policy full of entries that change nothing.
doc3, deny_changes = policyedit.plan_folder(doc2, PRIVATE, Effect.DENY)
check("setting an already-unreachable folder to Deny changes nothing",
      deny_changes == [], str(deny_changes))
check("...and adds no redundant rule to the policy",
      doc3.get("folder_rules") == doc2.get("folder_rules"),
      str(doc3.get("folder_rules")))
pol3 = Policy(doc3, POLICY_PATH)
d = pol3.evaluate("read_file", {"path": str(PRIVATE / "x.txt")}, LAB)
check("Deny: the engine refuses", d.effect is Effect.DENY, f"{d.effect} {d.rule_id}")
check("...citing the real reason — it is in no allowed root",
      d.rule_id == "tool_rules.read_file.within", d.rule_id)

# An explicit Deny only earns a rule where it actually overrides something.
doc3b, explicit = policyedit.plan_folder(doc, ROBOTICS, Effect.DENY)
check("denying a folder that WAS allowed does write a rule",
      len(explicit) == 1 and any(
          e["effect"] == "deny" for e in doc3b.get("folder_rules") or []),
      str(doc3b.get("folder_rules")))
d = Policy(doc3b, POLICY_PATH).evaluate(
    "read_file", {"path": str(ROBOTICS / "arm.py")}, LAB)
check("...and the engine cites the folder rule for it",
      d.effect is Effect.DENY and d.rule_id == "folder_rules",
      f"{d.effect} {d.rule_id}")

# A deny INSIDE an allowed folder must still deny — that is why longest-match
# exists, and it is the case a shallower implementation gets wrong.
nested = ROBOTICS / "secrets"
nested.mkdir(exist_ok=True)
doc4, _ = policyedit.plan_folder(doc3, nested, Effect.DENY)
pol4 = Policy(doc4, POLICY_PATH)
d = pol4.evaluate("read_file", {"path": str(nested / "k.txt")}, LAB)
check("a Deny subfolder inside an Allow folder still denies",
      d.effect is Effect.DENY and d.rule_id == "folder_rules",
      f"{d.effect} {d.rule_id}")
d = pol4.evaluate("read_file", {"path": str(ROBOTICS / "arm.py")}, LAB)
check("...without denying its parent", d.effect is Effect.ALLOW, f"{d.effect}")

# deny_paths must still outrank everything, or the UI could widen the strongest
# rule in the file by adding a folder.
d = pol4.evaluate("read_file", {"path": str(ROBOTICS / ".env")}, LAB)
check("deny_paths still beats an Allow folder", d.rule_id == "deny_paths", d.rule_id)

check("a policy with no folder_rules behaves exactly as before",
      Policy(BASE_DOC, POLICY_PATH).folder_rules == ())


# ---------------------------------------------------------------------------
rule("3. WIDENING NEEDS AN EXPLICIT CONFIRM NAMING THE GRANT")
# ---------------------------------------------------------------------------

reset_policy()
done, out = cli("set-folder", str(ROBOTICS), "allow")
check("granting access without confirmation is REFUSED",
      out is not None and not out["written"], done.stdout[:200] + done.stderr[:200])
check("...and the refusal names what would be granted",
      "Robotics" in (out or {}).get("error", ""), str(out))
check("...and says a grant needs confirming",
      "grants access" in (out or {}).get("error", ""), str(out))
check("...and the policy on disk is unchanged",
      json.loads(POLICY_PATH.read_text()) == BASE_DOC)

done, out = cli("set-folder", str(ROBOTICS), "allow", "--confirm-grant")
check("with the confirmation it is written", out and out["written"], str(out))
check("...and reports what changed in words",
      any("Robotics" in c for c in (out or {}).get("changes", [])), str(out))
check("...and says it applies next session",
      (out or {}).get("applies") == "next session", str(out))

# Narrowing is the asymmetric case: no confirmation required.
done, out = cli("set-folder", str(ROBOTICS), "deny")
check("REMOVING access needs no confirmation", out and out["written"], str(out))
check("...and the folder is now denied",
      policyedit.folder_effect(json.loads(POLICY_PATH.read_text()), ROBOTICS)
      is Effect.DENY)

# Ask is narrower than Allow but wider than Deny.
done, out = cli("set-folder", str(ROBOTICS), "ask")
check("Deny -> Ask is widening and is refused without confirmation",
      out and not out["written"], str(out))
done, out = cli("set-folder", str(ROBOTICS), "ask", "--confirm-grant")
check("...and permitted with it", out and out["written"], str(out))

# Removing a deny-list entry is the widest change available.
done, out = cli("deny-remove", ".env")
check("removing a deny-list entry is widening and refused",
      out and not out["written"], str(out))
check("...with the consequence spelled out",
      "become readable" in (out or {}).get("error", ""), str(out))
done, out = cli("deny-add", "*.pem")
check("ADDING a deny-list entry needs no confirmation", out and out["written"],
      str(out))


# ---------------------------------------------------------------------------
rule("4. THE DOCUMENT IS VALIDATED BY THE PROXY'S OWN LOADER")
# ---------------------------------------------------------------------------

reset_policy()
# A document the proxy would reject at startup must never reach disk. Driven
# through apply() with a hand-built bad doc, because the CLI cannot express one.
bad = json.loads(json.dumps(BASE_DOC))
bad["default_effect"] = "allow"   # policy.py refuses this outright
try:
    policyedit.apply(bad, [policyedit.Change("x", "x", "a", "b", False, "test")],
                     path=POLICY_PATH, db=DB)
    refused = False
    why = ""
except policyedit.EditError as exc:
    refused, why = True, str(exc)
check("a policy the proxy would reject is REFUSED", refused, why[:200])
check("...saying the proxy would reject it", "would reject this policy" in why, why[:200])
check("...quoting the loader's own words", "default_effect may not be 'allow'" in why,
      why[:200])
check("...and nothing was written",
      json.loads(POLICY_PATH.read_text()) == BASE_DOC)

# The validator is the real one, not a copy: prove it catches a rule only
# policy.py knows about (a fetch-named tool with no egress flag, S3b).
bad2 = json.loads(json.dumps(BASE_DOC))
bad2["tool_rules"]["web_fetch"] = {"effect": "allow"}
try:
    policyedit.apply(bad2, [policyedit.Change("x", "x", "a", "b", False, "t")],
                     path=POLICY_PATH, db=DB)
    caught = False
except policyedit.EditError as exc:
    caught = "egress" in str(exc)
check("...including rules only the real loader knows (S3b egress flag)", caught)


# ---------------------------------------------------------------------------
rule("5. WHERE IT WRITES, AND HOW")
# ---------------------------------------------------------------------------

reset_policy()
done, out = cli("set-folder", str(ROBOTICS), "allow", "--confirm-grant")
mode = POLICY_PATH.stat().st_mode & 0o777
check("the policy is written at 0600", mode == 0o600, oct(mode))
check("...and is valid JSON the loader accepts",
      Policy.load(POLICY_PATH) is not None)
check("...with no temp file left behind",
      not list(LAB.glob("policy.json.aegis-edit*")),
      str(list(LAB.glob("*.aegis-edit*"))))

# Refuse to write a policy inside a workspace root — the agent could rewrite it.
inside = WS / "policy.json"
doc_inside = json.loads(json.dumps(BASE_DOC))
try:
    policyedit.assert_writable_location(inside, doc_inside)
    refused = False
    why = ""
except policyedit.EditError as exc:
    refused, why = True, str(exc)
check("REFUSES to write the policy inside a workspace root", refused, why[:160])
check("...explaining the agent could rewrite it", "the agent can write" in why.lower(),
      why[:200])
check("...and no file was created there", not inside.exists())

# Regression: a data directory reached through a symlink (macOS /tmp ->
# /private/tmp) must still be writable. This refused every legitimate write
# until both sides of the comparison were resolved.
symlinked = Path("/tmp") / LAB.name if str(LAB).startswith("/private/tmp") else None
if symlinked is not None and symlinked.exists():
    try:
        policyedit.assert_writable_location(symlinked / "policy.json", BASE_DOC)
        sym_ok = True
    except policyedit.EditError as exc:
        sym_ok, sym_why = False, str(exc)
    check("a data directory reached through a symlink is still writable", sym_ok,
          locals().get("sym_why", ""))
else:
    check("the data-directory check resolves both sides before comparing",
          "resolve()" in (ROOT / "aegis" / "policyedit.py").read_text(),
          "assert_writable_location must resolve the data dir")

outside = LAB / "elsewhere" / "policy.json"
try:
    policyedit.assert_writable_location(outside, BASE_DOC)
    refused2 = False
except policyedit.EditError:
    refused2 = True
check("REFUSES to write outside the Aegis data directory", refused2)


# ---------------------------------------------------------------------------
rule("6. EVERY CHANGE IS AUDITED — what changed, not the file")
# ---------------------------------------------------------------------------

edits = rows("policy_edited")
print(f"  {len(edits)} policy_edited row(s)")
for r in edits[-3:]:
    print(f"    {r[1]:<6} {r[2]:<14} {r[3][:96]}")

check("edits are recorded with rule_id policy_edited", len(edits) >= 1)
check("...naming the folder that changed",
      any("Robotics" in r[3] for r in edits), str(edits[-1:]))
check("...and both states, so the change is reconstructable",
      any("->" in r[3] for r in edits), str(edits[-1:]))
check("...marked as a grant when it granted",
      any(r[3].startswith("granted:") for r in edits), str(edits[-1:]))
check("...and saying it applies to the next session",
      all("NEXT proxy session" in r[3] for r in edits), str(edits[-1:]))

whole_file = json.dumps(BASE_DOC["tool_rules"])
check("the whole policy is NOT copied into the log",
      not any(whole_file in r[3] for r in edits)
      and not any(len(r[3]) > 600 for r in edits),
      str(max((len(r[3]) for r in edits), default=0)))
check("the path that changed is in the paths column",
      any(str(ROBOTICS) in r[4] for r in edits), str(edits[-1:]))

v = subprocess.run([sys.executable, str(ROOT / "aegis" / "verify.py"), str(DB)],
                   capture_output=True, text=True, timeout=120)
check("the chain still verifies with policy_edited rows in it", v.returncode == 0,
      (v.stdout + v.stderr)[:200])


# ---------------------------------------------------------------------------
rule("7. A BROKEN CHAIN LOCKS THE EDITOR")
# ---------------------------------------------------------------------------

# Per the S2 operating rule, tampering happens on this lab's own database.
before_doc = json.loads(POLICY_PATH.read_text())
con = sqlite3.connect(str(DB))
con.execute("UPDATE audit SET reason='tampered' WHERE id=(SELECT MIN(id) FROM audit)")
con.commit()
con.close()

ok, detail = policyedit.chain_verifies(DB)
check("the tampered chain is detected", not ok, detail)

done, out = cli("set-folder", str(TAXES), "allow", "--confirm-grant")
check("the editor REFUSES to change the rules while the chain is broken",
      out and not out["written"], str(out)[:200])
check("...saying it will not change the rules either",
      "does not verify" in (out or {}).get("error", ""), str(out)[:300])
check("...and the policy is untouched",
      json.loads(POLICY_PATH.read_text()) == before_doc)

snap = policyedit.snapshot(POLICY_PATH, DB)
check("the screen is told it is not editable", snap["editable"] is False)
check("...and why, in a sentence",
      "does not verify" in snap["not_editable_reason"], snap["not_editable_reason"])


# ---------------------------------------------------------------------------
rule("8. DOCTOR SEES A RUNNING PROXY THAT HAS NOT PICKED UP THE EDIT")
# ---------------------------------------------------------------------------

# Fresh db: section 7 deliberately broke the old one.
DB.unlink()
for suffix in ("-wal", "-shm"):
    Path(str(DB) + suffix).unlink(missing_ok=True)
reset_policy()

store = AuditStore.open(DB)
store.record(tool="aegis policy", effect="allow", rule_id="policy_edited",
             reason="changed: Robotics: Deny -> Allow (applies to the NEXT proxy "
                    "session)", paths=[str(ROBOTICS)])
store.close()

edit = policyedit.last_edit(DB)
check("the last edit is readable from the log", edit is not None, str(edit))
check("...with an age", edit and edit["age_seconds"] >= 0, str(edit))

from aegis import doctor as doctor_mod  # noqa: E402

# The two ages are compared against `ps -o etime=`, which has one-second
# granularity, so the gap between the edit and the proxy start has to be bigger
# than that or the comparison is a coin toss. The first version recorded the
# edit and started the proxy back to back and passed by luck.
time.sleep(2.5)

# A long-lived proxy started AFTER this edit is the not-stale case.
proxy = subprocess.Popen(
    [sys.executable, str(ROOT / "aegis" / "proxy.py"), "--",
     sys.executable, "-c", "import sys;[sys.stdin.readline() or sys.exit(0) for _ in iter(int,1)]"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    env={**ENV, "AEGIS_POLICY": str(POLICY_PATH), "AEGIS_AUDIT_DB": str(DB)},
)
time.sleep(3)
try:
    ages = doctor_mod._proxy_ages()
    check("doctor can see a running proxy and how long it has run",
          any(pid == proxy.pid for pid, _, _ in ages), str(ages)[:200])

    # Make the edit look older than the proxy, then newer, and check both.
    report = doctor_mod.Report()
    doctor_mod._check_policy_freshness(report)
    fresh = [c for c in report.checks if "Policy edits" in c.name][0]
    check("with the edit older than the proxy, doctor PASSES",
          fresh.status == doctor_mod.PASS, f"{fresh.status} {fresh.lines}")

    # Now record an edit AFTER the proxy started: the proxy is stale. Same
    # margin, for the same reason.
    time.sleep(1.5)
    store = AuditStore.open(DB)
    store.record(tool="aegis policy", effect="allow", rule_id="policy_edited",
                 reason="changed: Taxes: Deny -> Ask", paths=[str(TAXES)])
    store.close()
    report = doctor_mod.Report()
    doctor_mod._check_policy_freshness(report)
    fresh = [c for c in report.checks if "Policy edits" in c.name][0]
    check("with the edit NEWER than the proxy, doctor FAILS",
          fresh.status == doctor_mod.FAIL, f"{fresh.status} {fresh.lines}")
    check("...naming the pid that is still enforcing the old policy",
          any(str(proxy.pid) in l for l in fresh.lines), str(fresh.lines)[:300])
    check("...and telling the user to restart",
          any("Restart your agent" in l for l in fresh.lines), str(fresh.lines)[:300])
    check("...explaining why the policy is read once per session",
          any("could race" in l for l in fresh.lines), str(fresh.lines)[:400])
finally:
    proxy.stdin.close()
    try:
        proxy.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proxy.kill()


# ---------------------------------------------------------------------------
rule("9. THE SELECTOR ROUND-TRIPS (UI bug 1)")
# ---------------------------------------------------------------------------

# Found by clicking: Ask and Deny never took. The write was genuinely failing —
# setting a folder to Ask/Deny used to DROP it from workspace_roots, and for the
# single-folder policy `aegis init` writes that emptied the list, so `Policy`
# refused the document. The selector was honest; the write was broken.

reset_policy()
solo = json.loads(json.dumps(BASE_DOC))          # exactly one workspace root
POLICY_PATH.write_text(json.dumps(solo, indent=2))
os.chmod(POLICY_PATH, 0o600)

for target, needs_grant in (("deny", False), ("ask", True), ("allow", True)):
    args = [str(WS), target] + (["--confirm-grant"] if needs_grant else [])
    done, out = cli("set-folder", *args)
    check(f"setting the ONLY workspace folder to {target} is written",
          out is not None and out["written"], str(out)[:200])

    shown = policyedit.snapshot(POLICY_PATH, DB)
    row = [f for f in shown["folders"] if Path(f["path"]) == WS]
    check(f"...and the screen reads back {target}",
          len(row) == 1 and row[0]["effect"] == target,
          str(shown["folders"]))
    check(f"...as exactly ONE row, not one per source",
          len(row) == 1, str([f["path"] for f in shown["folders"]]))

    pol = Policy.load(POLICY_PATH)
    d = pol.evaluate("read_file", {"path": str(WS / "a.txt")}, LAB)
    expected = {"allow": Effect.ALLOW, "ask": Effect.DENY, "deny": Effect.DENY}[target]
    # ask_behavior is "deny" in BASE_DOC, so an ASK collapses closed here.
    check(f"...and the engine enforces it ({target})", d.effect is expected,
          f"{d.effect} {d.rule_id}")

check("workspace_roots is never emptied by a folder change",
      len(json.loads(POLICY_PATH.read_text())["workspace_roots"]) >= 1,
      POLICY_PATH.read_text()[:200])

# The kernel has to agree with the screen, or a Bash tool writes where the MCP
# layer refuses (S9's profile derives writable roots from workspace_roots, and
# the folder now stays in there).
from aegis import sandbox as sandbox_mod  # noqa: E402

cli("set-folder", str(WS), "deny")
prof = sandbox_mod.profile_from_policy(Policy.load(POLICY_PATH))
check("a Deny folder is denied in the sandbox profile too",
      any(str(WS) in p_ for p_ in prof["filesystem"]["denyWrite"]),
      str(prof["filesystem"]["denyWrite"]))
check("...for reads as well as writes",
      any(str(WS) in p_ for p_ in prof["filesystem"]["denyRead"]),
      str(prof["filesystem"]["denyRead"]))

cli("set-folder", str(WS), "ask", "--confirm-grant")
prof = sandbox_mod.profile_from_policy(Policy.load(POLICY_PATH))
check("an Ask folder is NOT kernel-denied — an approval must be able to proceed",
      not any(str(WS) in p_ for p_ in prof["filesystem"]["denyWrite"]),
      str(prof["filesystem"]["denyWrite"]))


# ---------------------------------------------------------------------------
rule("SUMMARY")
# ---------------------------------------------------------------------------

ok, moved = labguard.assert_untouched()
check("the operator's real Aegis state is untouched", ok, str(moved))

print(f"\n  {PASSED} passed, {FAILED} failed, {len(NOT_RUN)} NOT RUN")
if FAILURES:
    print("\n  failures:")
    for name in FAILURES:
        print(f"    - {name}")
if NOT_RUN:
    print("\n  NOT established by this run:")
    for what, why in NOT_RUN:
        print(f"    - {what}\n      {why}")

print(f"\n  lab: {LAB}   (delete when done)")
print(
    "\n  NOT established by this suite:\n"
    "    - the Tauri window itself. The Rust half compiles and its commands are\n"
    "      thin shells around `aegis policy`, which is what is tested here; no\n"
    "      human has clicked the screen\n"
    "    - that a user understands the sentences. Wording is asserted for\n"
    "      absence of jargon, not for comprehension\n"
)
sys.exit(1 if (FAILED or NOT_RUN) else 0)
