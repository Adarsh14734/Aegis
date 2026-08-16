"""Measure the approval rate the default policy produces — D4.

THREAT-MODEL.md D4 makes the approval budget a security property: "Target:
fewer than 5 approval prompts per hour of agent work. Above that, T5 (approval
fatigue) defeats C7."

So the rate has to be measured, not asserted. This replays tests/drive.py's
case list through the policy engine and counts how many calls would block on a
human, then reports the per-tool picture — because drive.py's mix is
adversarial and is NOT what a working session looks like.

Reads policy.example.json. Evaluates only; nothing is forwarded anywhere.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "aegis"))

LAB = Path(tempfile.mkdtemp(prefix="aegis-budget-"))
os.environ["AEGIS_AUDIT_DB"] = str(LAB / "audit.db")

from policy import Effect, Policy  # noqa: E402

WS = Path.home() / "code" / "aegis-testlab" / "workspace"
doc = json.loads((ROOT / "policy.example.json").read_text())
doc["workspace_roots"] = [str(WS)]
doc["trash_dir"] = str(LAB / "trash")
pol = Policy(doc, LAB / "policy.json")

# ---- 1. the adversarial suite --------------------------------------------

lines = (ROOT / "tests" / "drive.py").read_text().splitlines()
start = next(i for i, l in enumerate(lines) if l.startswith("CASES = ["))
end = next(i for i in range(start, len(lines)) if lines[i] == "]")
ns = {
    "WS": WS,
    "POLICY": LAB / "policy.json",
    "LAB": Path.home() / "code" / "aegis-testlab",
    "FAKE_SECRETS": Path.home() / "code" / "aegis-testlab" / "fake-secrets" / ".aws" / "credentials",
}
exec("\n".join(lines[start:end + 1]), ns)  # noqa: S102 - reading our own test data
cases = ns["CASES"]

counts, asks = {}, []
for label, tool, args in cases:
    d = pol.evaluate(tool, args if isinstance(args, dict) else {}, WS)
    counts[d.effect.value] = counts.get(d.effect.value, 0) + 1
    if d.effect is Effect.ASK:
        asks.append((d.rule_id, label.strip()))

print("=" * 74)
print("APPROVAL BUDGET — default policy (policy.example.json), D4 target <5/hour")
print("=" * 74)
print(f"\n1. tests/drive.py replayed: {len(cases)} calls -> {counts}")
print(f"   prompts: {len(asks)}")
for rid, label in asks:
    print(f"     - {rid:<22} {label}")
per100 = len(asks) / len(cases) * 100
print(f"\n   {per100:.1f} prompts per 100 tool calls")
for rate in (20, 60, 120, 300):
    n = per100 / 100 * rate
    flag = "  OVER D4 BUDGET" if n > 5 else ""
    print(f"     {rate:>3} calls/hour -> {n:5.1f} prompts/hour{flag}")

# ---- 2. per-tool, which is what actually drives the rate ------------------

print("\n2. which tools prompt, per call:")
tools = ["read_text_file", "read_multiple_files", "list_directory", "directory_tree",
         "search_files", "get_file_info", "write_file", "create_directory",
         "edit_file", "move_file", "delete_file"]
prompting = []
for tool in tools:
    d = pol.evaluate(tool, {"path": str(WS / "f.txt")}, WS)
    if d.effect is Effect.ASK:
        prompting.append(tool)
    print(f"     {tool:<22} {d.effect.value:<5} ({d.rule_id})")
d = pol.evaluate("read_text_file", {"paths": [str(WS / f"f{i}") for i in range(11)]}, WS)
print(f"     {'(11 paths, any tool)':<22} {d.effect.value:<5} ({d.rule_id})")

print(f"\n   prompting tools: {', '.join(prompting) or 'none'}"
      f"  (+ any call over the bulk threshold of {pol.bulk_threshold} paths)")

print("\n3. what that means for a working session:")
print("   drive.py is an adversarial suite — 19 of its 27 calls are denials — so")
print("   its ratio is not a session rate. The rate is driven by how often the")
print("   prompting tools above actually get used. Derived, not assumed:")
print(f"\n     prompts/hour = (share of calls that are {' or '.join(prompting) or 'prompting'}")
print(f"                     or exceed {pol.bulk_threshold} paths) x calls per hour\n")
print(f"     {'share':>7} | {'60 calls/hr':>12} | {'120 calls/hr':>13}")
print(f"     {'-'*7}-+-{'-'*12}-+-{'-'*13}")
for share in (1, 2, 5, 10, 25):
    row = f"     {share:>6}% |"
    for rate in (60, 120):
        n = share / 100 * rate
        row += f" {n:>7.1f}{'  OVER' if n > 5 else '      '} |" if rate == 60 else \
               f" {n:>8.1f}{'  OVER' if n > 5 else '      '}"
    print(row)
print("\n   Renames and >10-path calls are occasional, not routine: single-digit")
print("   percentages are the realistic band, which keeps this inside D4's")
print("   budget of 5/hour. It leaves the budget if a session is dominated by")
print("   bulk operations, and nothing here caps that — see S5-REPORT.md.")

import shutil  # noqa: E402

shutil.rmtree(LAB, ignore_errors=True)
