"""Aegis — tests against the BUILT .app, not the development tree.

Every existing suite runs from the repository, where `aegis/` sits above the
executable. That is not the shape any user gets. Inside
`/Applications/Aegis.app` there is no repository above the binary, and S6's
locator walked upwards looking for one — so the shipped app could not verify
the chain and the Permissions screen refused every edit. Twelve sprints of
green suites never saw it, because none of them ran the artifact.

This file does. It copies the built bundle OUT of the repository first, so a
walk upwards finds nothing, and then asks the real binary where it would look.

    python3 tests/bundle.py

Requires a build:  cd ui && npx tauri build --bundles app
Without one the suite reports NOT RUN and exits non-zero, rather than passing
on a bundle that does not exist.
"""

import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
import labguard  # noqa: E402

LAB = labguard.pin("aegis-bundle-")

APP = ROOT / "ui/src-tauri/target/release/bundle/macos/Aegis.app"
CONF = json.loads((ROOT / "ui/src-tauri/tauri.conf.json").read_text())

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


def clean_env(**over) -> dict:
    """The environment an installed app actually starts with.

    AEGIS_HOME and PYTHONPATH are stripped: both would let the binary find the
    repository and hide the very bug this file exists for.
    """
    env = labguard.subprocess_env(**over)
    # Only strip what the caller did not deliberately set: §4 needs PYTHONPATH
    # to simulate an installed package, and stripping it there would test
    # nothing.
    for leak in ("AEGIS_HOME", "PYTHONPATH", "AEGIS_PYTHON", "AEGIS_PYTHON_DIRS"):
        if leak not in over:
            env.pop(leak, None)
    return env


# The PATH a double-clicked .app inherits. Not the shell's — this is the whole
# reason §8 exists: on this PATH `python3` is /usr/bin/python3, the Command
# Line Tools shim, which is Python 3.9. Aegis needs 3.10.
FINDER_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


def looks_like_a_traceback(text: str) -> bool:
    """A traceback is not a message. If one of these reaches a screen, the user
    has been handed the internals of a program instead of a sentence."""
    return ("Traceback (most recent call last)" in text
            or "TypeError:" in text
            or "  File \"" in text)


def ask(app_dir: Path, flag: str, **over) -> dict:
    """Put a question to the SHIPPED binary and read its answer as JSON.

    Three flags, all read-only, all answering one decision that broke in a
    shape no test could see from the development tree:

      --locate  where it would find the Python side
      --python  which interpreter it would run, and whether it is new enough
      --chain   what it would tell the user about the audit chain right now
    """
    done = subprocess.run(
        [str(app_dir / "Contents/MacOS/aegis-ui"), flag],
        capture_output=True, text=True, timeout=180,
        cwd=os.path.sep,  # neutral: nothing above / holds the repo
        env=clean_env(**over),
    )
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError:
        return {"found": False, "raw": done.stdout, "stderr": done.stderr[-300:]}


def locate(app_dir: Path, **over) -> dict:
    """Ask the shipped binary where it would find the Python side."""
    return ask(app_dir, "--locate", **over)


print(f"lab: {LAB}")
print(f"app: {APP}")

if not APP.exists():
    not_run("every check in this file",
            f"no built bundle at {APP}. Run: cd ui && npx tauri build --bundles app")
    print(f"\n  {PASSED} passed, {FAILED} failed, {len(NOT_RUN)} NOT RUN")
    sys.exit(1)


# ---------------------------------------------------------------------------
rule("1. THE BUNDLE CARRIES THE PYTHON SIDE")
# ---------------------------------------------------------------------------

res = APP / "Contents/Resources"
check("the app ships an aegis/ directory", (res / "aegis").is_dir(),
      str(sorted(p.name for p in res.iterdir())))
for needed in ("verify.py", "cli.py", "policyedit.py", "policy.py", "audit.py"):
    check(f"...including {needed}", (res / "aegis" / needed).is_file())
check("no __pycache__ was shipped",
      not list(APP.rglob("__pycache__")), str(list(APP.rglob("__pycache__"))[:2]))
check("tauri.conf.json declares the resource, so this is not a one-off copy",
      "aegis" in json.dumps(CONF["bundle"].get("resources", {})),
      json.dumps(CONF["bundle"].get("resources")))


# ---------------------------------------------------------------------------
rule("2. INSTALLED SHAPE — the app moved OUT of the repository")
# ---------------------------------------------------------------------------

# The decisive move. Inside the repo a walk upwards still finds `aegis/`, so a
# broken locator would pass. Copied here there is nothing above the app but the
# lab, which is what /Applications looks like.
INSTALLED = LAB / "Applications" / "Aegis.app"
INSTALLED.parent.mkdir(parents=True, exist_ok=True)
shutil.copytree(APP, INSTALLED, symlinks=True)
check("the app is copied outside the repository", not str(INSTALLED).startswith(str(ROOT)),
      str(INSTALLED))
check("...with no aegis/ in any parent directory",
      not any((p / "aegis" / "verify.py").is_file() for p in INSTALLED.parents),
      str([str(p) for p in INSTALLED.parents][:4]))

found = locate(INSTALLED)
print(f"  --locate says: {json.dumps(found)[:200]}")
check("the shipped binary FINDS its Python side", found.get("found") is True,
      json.dumps(found)[:300])
check("...from its own bundle, not a repository",
      found.get("source") == "bundled with the app", str(found.get("source")))
check("...resolving inside the installed app",
      str(found.get("dir", "")).startswith(str(INSTALLED)), str(found.get("dir")))
check("...and the verifier it names actually exists",
      Path(found.get("verifier", "/nonexistent")).is_file(), str(found.get("verifier")))


# ---------------------------------------------------------------------------
rule("3. WITHOUT THE PYTHON SIDE IT SAYS SO — it never assumes")
# ---------------------------------------------------------------------------

# The requirement that matters as much as the fix: a UI that cannot verify the
# chain must keep saying it cannot. "Assume intact" would turn a broken install
# into a green screen, which is worse than the bug being fixed.
STRIPPED = LAB / "Stripped" / "Aegis.app"
STRIPPED.parent.mkdir(parents=True, exist_ok=True)
shutil.copytree(APP, STRIPPED, symlinks=True)
shutil.rmtree(STRIPPED / "Contents/Resources/aegis")

# `import aegis` must also be impossible, or the installed-package fallback
# legitimately rescues it — which is a real path, tested in §4. Starving PATH
# is no longer enough on its own: the interpreter search deliberately looks in
# absolute locations a Finder-launched app cannot reach through PATH (that is
# the whole of §8), so the search directories are emptied too.
blind = locate(STRIPPED, PATH="/nonexistent-for-this-check", AEGIS_PYTHON_DIRS="")
print(f"  --locate says: {json.dumps(blind)[:200]}")
check("a bundle with no Python side reports NOT FOUND", blind.get("found") is False,
      json.dumps(blind)[:300])
check("...and the message names every place it looked",
      all(t in blind.get("message", "") for t in ("AEGIS_HOME", "bundled", "aegis-mcp")),
      blind.get("message", "")[:300])
check("...and tells the user how to fix it",
      "pip install aegis-mcp" in blind.get("message", "")
      or "Reinstall" in blind.get("message", ""), blind.get("message", "")[:300])


# ---------------------------------------------------------------------------
rule("4. THE INSTALLED-PACKAGE FALLBACK")
# ---------------------------------------------------------------------------

# Someone who `pip install`ed aegis-mcp and also runs the app: the bundle is the
# first answer, an importable package is the second. Simulated by stripping the
# bundle and putting the repo on PYTHONPATH, which is what an install looks like
# to `import aegis`.
viapkg = locate(STRIPPED, PYTHONPATH=str(ROOT))
print(f"  --locate says: {json.dumps(viapkg)[:200]}")
check("an importable aegis-mcp is found when the bundle has none",
      viapkg.get("found") is True, json.dumps(viapkg)[:300])
check("...and is reported as the installed package, not as bundled",
      viapkg.get("source") == "installed aegis-mcp package", str(viapkg.get("source")))

# Precedence: with BOTH available the bundle wins, so an app always runs the
# Python it shipped with rather than whatever happens to be installed.
both = locate(INSTALLED, PYTHONPATH=str(ROOT))
check("the bundled copy takes precedence over an installed package",
      both.get("source") == "bundled with the app", str(both.get("source")))
check("...which keeps the app running the Python it was built against",
      str(both.get("dir", "")).startswith(str(INSTALLED)), str(both.get("dir")))


# ---------------------------------------------------------------------------
rule("5. THE BUNDLED PYTHON ACTUALLY WORKS")
# ---------------------------------------------------------------------------

# Finding a file is not running it. Both things the app does with the Python
# side are exercised here, from the installed copy.
WS = LAB / "workspace"
WS.mkdir(exist_ok=True)
POLICY = LAB / "policy.json"
DB = LAB / "audit.db"
doc = {
    "version": 1, "workspace_roots": [str(WS)], "deny_paths": [".env"],
    "allowed_domains": [],
    "tool_rules": {"read_file": {"effect": "allow", "within": ["<workspace>"]}},
    "default_effect": "deny", "ask_behavior": "deny",
}
labguard.check_policy_doc(doc)
POLICY.write_text(json.dumps(doc, indent=2))
os.chmod(POLICY, 0o600)

sys.path.insert(0, str(ROOT))
from aegis.audit import AuditStore  # noqa: E402

store = AuditStore.open(DB)
store.record(tool="read_file", effect="deny", rule_id="deny_paths",
             reason="a real row for the bundled verifier to check", paths=[])
store.close()

bundled_verifier = INSTALLED / "Contents/Resources/aegis/verify.py"
done = subprocess.run(["python3", str(bundled_verifier), str(DB)],
                      capture_output=True, text=True, timeout=180,
                      cwd=os.path.sep, env=clean_env())
check("the BUNDLED verifier verifies a real chain", done.returncode == 0,
      (done.stdout + done.stderr)[:200])
check("...and says so in its own words", "row(s) verified" in done.stdout,
      done.stdout[:200])

done = subprocess.run(
    ["python3", "-m", "aegis.cli", "policy", "show"],
    capture_output=True, text=True, timeout=180,
    cwd=str(INSTALLED / "Contents/Resources"),
    env=clean_env(PYTHONPATH=str(INSTALLED / "Contents/Resources"),
                  AEGIS_POLICY=str(POLICY), AEGIS_AUDIT_DB=str(DB)),
)
check("the BUNDLED package can run the policy editor", done.returncode == 0,
      (done.stdout + done.stderr)[:300])
shown = json.loads(done.stdout) if done.returncode == 0 else {}
check("...and returns the permissions the screen renders",
      bool(shown.get("folders")) and shown.get("editable") is True,
      json.dumps(shown)[:200])

# A broken chain must still lock the editor when run from the bundle.
import sqlite3  # noqa: E402

con = sqlite3.connect(str(DB))
con.execute("UPDATE audit SET reason='tampered' WHERE id=1")
con.commit()
con.close()
done = subprocess.run(
    ["python3", "-m", "aegis.cli", "policy", "show"],
    capture_output=True, text=True, timeout=180,
    cwd=str(INSTALLED / "Contents/Resources"),
    env=clean_env(PYTHONPATH=str(INSTALLED / "Contents/Resources"),
                  AEGIS_POLICY=str(POLICY), AEGIS_AUDIT_DB=str(DB)),
)
locked = json.loads(done.stdout) if done.stdout.strip() else {}
check("a tampered chain still locks the editor when run from the bundle",
      locked.get("editable") is False, json.dumps(locked)[:200])


# ---------------------------------------------------------------------------
rule("6. THE APP LOOKS LIKE AN APP")
# ---------------------------------------------------------------------------

icns = APP / "Contents/Resources/icon.icns"
data = icns.read_bytes()
off, kinds = 8, []
while off < len(data) - 8:
    kind = data[off:off + 4].decode("ascii", "replace")
    length = struct.unpack(">I", data[off + 4:off + 8])[0]
    if length <= 0:
        break
    kinds.append(kind)
    off += length
print(f"  icns entries: {', '.join(kinds)}")

# The Dock needs the large representations. An icon with only `is32` (16x16)
# is why there was no Dock icon the first time.
check("the icon has the large sizes the Dock needs",
      any(k in kinds for k in ("ic07", "ic08", "ic09", "ic10")), str(kinds))
check("...and is more than the 16x16 the broken one carried",
      len(kinds) > 3 and len(data) > 30_000, f"{len(kinds)} entries, {len(data)} bytes")

# ---- and it is a PICTURE ---------------------------------------------------
#
# Every check above passed on an icon.icns whose every pixel, at every size,
# was the single colour #1a2a3a. It was a well-formed ten-entry icns of a flat
# tile — invisible on a dark Dock, a blank square on a light one — and the
# checks only ever asked about the container. So the next four ask about the
# image. A placeholder cannot pass them.

def icns_images(blob: bytes):
    """Every PNG inside an .icns, decoded to (size, RGBA bytes)."""
    out, off = [], 8
    while off < len(blob) - 8:
        length = struct.unpack(">I", blob[off + 4:off + 8])[0]
        if length <= 0:
            break
        body = blob[off + 8:off + length]
        if body[:8] == b"\x89PNG\r\n\x1a\x0a"[:8] or body[:4] == b"\x89PNG":
            out.append(decode_png(body))
        off += length
    return out


def decode_png(blob: bytes):
    """Minimal 8-bit RGBA PNG decoder — stdlib only, like everything else here."""
    off, idat, ihdr = 8, b"", None
    while off < len(blob):
        length = struct.unpack(">I", blob[off:off + 4])[0]
        kind = blob[off + 4:off + 8]
        if kind == b"IHDR":
            ihdr = struct.unpack(">IIBBBBB", blob[off + 8:off + 8 + length])
        elif kind == b"IDAT":
            idat += blob[off + 8:off + 8 + length]
        off += 12 + length
    w, h, depth, ctype = ihdr[0], ihdr[1], ihdr[2], ihdr[3]
    if depth != 8 or ctype != 6:
        return w, None
    raw, bpp, stride = zlib.decompress(idat), 4, 4 * w
    out, prev, pos = bytearray(), bytearray(stride), 0
    for _ in range(h):
        f = raw[pos]; pos += 1
        line = bytearray(raw[pos:pos + stride]); pos += stride
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            b = prev[i]
            c = prev[i - bpp] if i >= bpp else 0
            if f == 1:
                line[i] = (line[i] + a) & 255
            elif f == 2:
                line[i] = (line[i] + b) & 255
            elif f == 3:
                line[i] = (line[i] + (a + b) // 2) & 255
            elif f == 4:
                pp = a + b - c
                pa, pb, pc = abs(pp - a), abs(pp - b), abs(pp - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 255
        out += line
        prev = line
    return w, bytes(out)


images = [(w, px) for w, px in icns_images(data) if px]
check("the icns carries decodable artwork at several sizes", len(images) >= 4,
      f"{len(images)} decodable images")

biggest = max(images, key=lambda i: i[0]) if images else (0, None)
size, px = biggest
if px:
    colours, opaque = set(), 0
    for i in range(0, size * size * 4, 4):
        colours.add(px[i:i + 4])
        opaque += px[i + 3] > 8
    coverage = opaque / (size * size)
    print(f"  largest entry: {size}x{size}, {len(colours)} distinct colours, "
          f"{coverage * 100:.1f}% opaque")

    # The failing icon had exactly ONE. Not a threshold anyone has to tune:
    # any drawing has hundreds, a placeholder has one.
    check("the icon is a drawing, not a flat colour", len(colours) > 32,
          f"{len(colours)} distinct RGBA values in the {size}x{size} entry")
    # A rounded plate with a margin: mostly-but-not-entirely opaque. A full
    # square (coverage 1.0) is the shape a placeholder has.
    check("...drawn as a rounded plate with the margin macOS icons have",
          0.45 < coverage < 0.95, f"{coverage * 100:.1f}% opaque")
    # And it has a MARK: the middle does not look like the corner.
    centre = px[4 * ((size // 2) * size + size // 2):][:4]
    corner = px[:4]
    check("...with a mark in the middle, distinct from the background",
          bytes(centre) != bytes(corner), f"centre {tuple(centre)} corner {tuple(corner)}")
else:
    not_run("the icon artwork checks", "no 8-bit RGBA entry in the icns to decode")

# The generator is in the tree, so the artwork can be reviewed as a description
# rather than trusted as a binary.
check("the artwork is generated by a script that ships with it",
      (ROOT / "ui/src-tauri/icons/generate.py").is_file())

plist = APP / "Contents/Info.plist"
raw = plist.read_bytes().decode("utf-8", "replace")
check("the app is NOT a background agent (no LSUIElement)",
      "LSUIElement" not in raw, "LSUIElement present — it would have no Dock icon")
check("Info.plist points at the icon", "icon.icns" in raw)
check("...at the name that is actually in Resources/",
      (APP / "Contents/Resources/icon.icns").is_file())
check("...and the bundled icns is the one in the source tree",
      (APP / "Contents/Resources/icon.icns").read_bytes()
      == (ROOT / "ui/src-tauri/icons/icon.icns").read_bytes(),
      "the build shipped a different icns than the repo holds")
check("tauri.conf.json declares that icon, so this is not a one-off copy",
      any("icon.icns" in str(i) for i in CONF["bundle"].get("icon", [])),
      json.dumps(CONF["bundle"].get("icon")))


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
rule("7. THE .dmg — the thing that is actually downloaded")
# ---------------------------------------------------------------------------

# The bug was reported as "the built .dmg is broken", and the .app inside the
# target directory is not the same file the user drags to /Applications. This
# mounts the installer read-only and asks the binary inside it.
dmgs = sorted((ROOT / "ui/src-tauri/target/release/bundle/dmg").glob("*.dmg")) \
    if (ROOT / "ui/src-tauri/target/release/bundle/dmg").is_dir() else []
if not dmgs:
    not_run("the .dmg installer",
            "no .dmg built. Run: cd ui && npx tauri build")
else:
    dmg = dmgs[-1]
    print(f"  dmg: {dmg.name}")
    attached = subprocess.run(
        ["hdiutil", "attach", "-nobrowse", "-readonly", str(dmg)],
        capture_output=True, text=True, timeout=300)
    mount = ""
    for line in attached.stdout.splitlines():
        if "/Volumes/" in line:
            mount = "/Volumes/" + line.split("/Volumes/", 1)[1].strip()
    if not mount:
        not_run("the .dmg installer",
                f"could not mount it: {attached.stderr.strip()[:200]}")
    else:
        try:
            inside = Path(mount) / "Aegis.app"
            check("the .dmg contains the app", inside.is_dir(), mount)
            check("...carrying the Python side, not just the binary",
                  (inside / "Contents/Resources/aegis/verify.py").is_file())
            check("...and a drop target for /Applications",
                  (Path(mount) / "Applications").exists())
            dmg_found = locate(inside)
            print(f"  --locate says: {json.dumps(dmg_found)[:200]}")
            check("the binary IN THE INSTALLER finds its Python side",
                  dmg_found.get("found") is True, json.dumps(dmg_found)[:300])
            check("...from its own bundle", dmg_found.get("source") == "bundled with the app",
                  str(dmg_found.get("source")))
        finally:
            subprocess.run(["hdiutil", "detach", mount], capture_output=True, timeout=300)


# ---------------------------------------------------------------------------
rule("8. IT PICKS A PYTHON THAT CAN ACTUALLY RUN AEGIS")
# ---------------------------------------------------------------------------

# The reported failure, in full:
#
#   File "/Applications/Aegis.app/Contents/Resources/aegis/cli.py", line 401
#   TypeError: unsupported operand type(s) for |: 'types.GenericAlias' and 'NoneType'
#   ...raised from /Library/Developer/CommandLineTools/.../python3.9
#
# Every call site said `python3`. An app launched from Finder inherits
# PATH=/usr/bin:/bin:/usr/sbin:/sbin, where python3 is the Command Line Tools
# shim — Python 3.9. Aegis has required 3.10 since its first commit, so the
# window ran the one interpreter on the machine that cannot load it. A
# developer never sees this: a terminal-launched build inherits the shell's
# PATH, where python3 is whatever they installed.
#
# So this section runs the shipped binary on the Finder PATH.

print(f"  PATH as Finder gives it: {FINDER_PATH}")
shim = subprocess.run(["/usr/bin/python3", "-c",
                       "import sys;print('%d.%d.%d' % sys.version_info[:3])"],
                      capture_output=True, text=True, timeout=60).stdout.strip()
print(f"  /usr/bin/python3 is Python {shim}")

chosen = ask(INSTALLED, "--python", PATH=FINDER_PATH)
print(f"  --python says: {json.dumps(chosen)[:260]}")

if chosen.get("found"):
    major_minor = tuple(int(n) for n in str(chosen["version"]).split(".")[:2])
    check("on the PATH a double-clicked app gets, it still finds a usable Python",
          True, "")
    check(f"...and it meets the minimum ({chosen.get('minimum')})",
          major_minor >= tuple(int(n) for n in str(chosen["minimum"]).split(".")),
          f"chose Python {chosen['version']} at {chosen.get('path')}")
    check("...which is NOT the 3.9 shim the old code would have run",
          "CommandLineTools" not in str(chosen.get("path", "")),
          str(chosen.get("path")))
elif shim.startswith("3.9"):
    # A machine with nothing but the shim: refusing is the correct answer and
    # is asserted in full below. Not a pass for "it found one", though.
    not_run("finding a usable Python on the Finder PATH",
            "this machine has no Python >= 3.10 outside the shell's PATH")
else:
    check("on the PATH a double-clicked app gets, it still finds a usable Python",
          False, json.dumps(chosen)[:300])

# It did not merely fail to look at the shim — it looked and turned it down.
rejected_versions = [r.get("version", "") for r in chosen.get("rejected", [])]
check("...having actually probed the 3.9 shim and rejected it",
      any(v.startswith("3.9") for v in rejected_versions) or not shim.startswith("3.9"),
      f"rejected: {rejected_versions}")

# ---- the refusal itself ----------------------------------------------------
#
# A machine with only an old Python must be told so in a sentence. To prove
# that on a machine that HAS a new one, the search is put in a world containing
# exactly one interpreter: the 3.9 shim. AEGIS_PYTHON_DIRS replaces the
# built-in search directories and can only ever narrow the search — the version
# gate is applied to whatever it finds, so no value of it can make Aegis accept
# an interpreter below the minimum.
ONLY_39 = LAB / "only39"
ONLY_39.mkdir(exist_ok=True)
(ONLY_39 / "python3").unlink(missing_ok=True)
(ONLY_39 / "python3").symlink_to("/usr/bin/python3")

starved = dict(PATH=str(ONLY_39), AEGIS_PYTHON_DIRS=str(ONLY_39))
refused = ask(INSTALLED, "--python", **starved)
print(f"  --python (only 3.9 reachable) says: {json.dumps(refused)[:300]}")

if not shim.startswith("3.9"):
    not_run("the refusal message",
            f"/usr/bin/python3 is {shim}, not a 3.9 — nothing here to refuse")
else:
    check("with only an old Python reachable, the app REFUSES to use it",
          refused.get("found") is False, json.dumps(refused)[:300])
    message = refused.get("message", "")
    check("...with a message naming the version it needs",
          "3.10" in message, message[:300])
    check("...and naming the version that is actually installed",
          "3.9" in message, message[:300])
    check("...and telling the user what to do about it",
          "AEGIS_PYTHON" in message and ("install" in message.lower()),
          message[:300])
    check("...in a sentence, not a traceback",
          not looks_like_a_traceback(message), message[:300])

# ---- and the same refusal reaches the chain banner -------------------------
starved_chain = ask(INSTALLED, "--chain", AEGIS_AUDIT_DB=str(DB), **starved)
print(f"  --chain (only 3.9 reachable) says: {json.dumps(starved_chain)[:300]}")
if shim.startswith("3.9"):
    check("a missing interpreter leaves the chain UNCHECKED",
          starved_chain.get("state") == "unchecked", json.dumps(starved_chain)[:300])
    check("...never reported as broken",
          starved_chain.get("state") != "broken", str(starved_chain.get("state")))
    check("...and the words on screen do not accuse the log",
          not any(w in (starved_chain.get("detail", "") or "").lower()
                  for w in ("altered", "tamper", "broken")),
          starved_chain.get("detail", "")[:300])
    check("...they name the version required instead",
          "3.10" in (starved_chain.get("detail", "") or ""),
          starved_chain.get("detail", "")[:300])
    check("...and carry the fix", "AEGIS_PYTHON" in (starved_chain.get("remedy") or ""),
          str(starved_chain.get("remedy"))[:300])

# ---- forced onto 3.9, the Python side says so in English -------------------
#
# The app will not choose an old interpreter. Someone can still force one, via
# AEGIS_PYTHON or by running the bundled files by hand — and what they get must
# be a sentence, because the traceback above is what a person actually saw.
bundled = INSTALLED / "Contents/Resources"
for label, argv in (
    ("the bundled verifier", ["/usr/bin/python3", str(bundled / "aegis/verify.py"), str(DB)]),
    ("the bundled policy editor", ["/usr/bin/python3", "-m", "aegis.cli", "policy", "show"]),
):
    done = subprocess.run(argv, capture_output=True, text=True, timeout=180,
                          cwd=str(bundled),
                          env=clean_env(PYTHONPATH=str(bundled), PATH=FINDER_PATH,
                                        AEGIS_POLICY=str(POLICY), AEGIS_AUDIT_DB=str(DB)))
    out = (done.stdout + done.stderr).strip()
    if not shim.startswith("3.9"):
        not_run(f"{label} on an old interpreter", f"/usr/bin/python3 is {shim}")
        continue
    check(f"{label} on Python 3.9 refuses rather than crashing",
          done.returncode == 2, f"exit {done.returncode}: {out[:200]}")
    check(f"...naming the version it needs", "3.10" in out, out[:300])
    check(f"...with no traceback anywhere in it",
          not looks_like_a_traceback(out), out[:400])

# ---- one minimum, stated in four places, none of which can import the others
def stated_minimum(path: Path, needle: str) -> str:
    """The version a line states, from the part after its last '='.

    Everything on the left is a name — and `u32` in the Rust one is full of
    digits, which is exactly the sort of thing a looser parser gets wrong and
    then reports as agreement.
    """
    for line in path.read_text().splitlines():
        if line.strip().startswith(needle):
            nums = re.findall(r"\d+", line.rsplit("=", 1)[-1])
            return ".".join(nums[:2])
    return ""

minimums = {
    "pyproject.toml requires-python":
        stated_minimum(ROOT / "pyproject.toml", "requires-python"),
    "aegis/__init__.py MIN_PYTHON":
        stated_minimum(ROOT / "aegis/__init__.py", "MIN_PYTHON"),
    "aegis/verify.py MIN_PYTHON":
        stated_minimum(ROOT / "aegis/verify.py", "MIN_PYTHON"),
    "python.rs MIN_PYTHON":
        stated_minimum(ROOT / "ui/src-tauri/src/python.rs", "pub const MIN_PYTHON"),
}
print(f"  minimums: {minimums}")
check("the minimum version is the same in all four places that state it",
      len(set(minimums.values())) == 1 and "" not in minimums.values(),
      json.dumps(minimums))
check("...and it is what the shipped binary reports",
      str(chosen.get("minimum") or refused.get("minimum")) in set(minimums.values()),
      f"binary says {chosen.get('minimum') or refused.get('minimum')}, sources say {set(minimums.values())}")


# ---------------------------------------------------------------------------
rule("9. A CRASHED VERIFIER IS NOT A TAMPERED CHAIN")
# ---------------------------------------------------------------------------

# The most damaging bug in the report. verify.py exits 1 for a broken chain;
# CPython also exits 1 for an uncaught exception. The UI read the exit code, so
# a verifier that died on the wrong interpreter rendered as:
#
#     The record of what happened has been altered.
#
# Nothing had been altered. Nothing had been checked. A false tamper alarm on
# the one screen whose purpose is honest tamper reporting is worse than no
# screen: an alarm that fires when nothing is wrong is an alarm that gets
# ignored when something is.
#
# The fix is that the verdict comes from a marker verify.py prints only after
# its check RETURNS — so no crash, import error, syntax error or wrong
# interpreter can produce one. These checks drive the shipped binary through
# all three states and assert they stay apart.

CHAINAPP = LAB / "Chain" / "Aegis.app"
CHAINAPP.parent.mkdir(parents=True, exist_ok=True)
shutil.copytree(APP, CHAINAPP, symlinks=True)
CHAIN_VERIFIER = CHAINAPP / "Contents/Resources/aegis/verify.py"
GOOD_VERIFIER = CHAIN_VERIFIER.read_bytes()

DB9 = LAB / "chain.db"
store = AuditStore.open(DB9)
for i in range(3):
    store.record(tool="read_file", effect="allow", rule_id="tool_rules.read_file",
                 reason=f"row {i} for the chain-state checks", paths=[])
store.close()


def chain_state(**over) -> dict:
    return ask(CHAINAPP, "--chain", AEGIS_AUDIT_DB=str(DB9), **over)


intact = chain_state()
print(f"  intact chain:  {json.dumps(intact)[:220]}")
check("a real chain reads as intact", intact.get("state") == "intact",
      json.dumps(intact)[:300])
check("...checked, and ok", intact.get("checked") is True and intact.get("ok") is True,
      json.dumps(intact)[:200])

# ---- a genuinely broken chain must still say so ---------------------------
con = sqlite3.connect(str(DB9))
con.execute("UPDATE audit SET reason='tampered' WHERE id=2")
con.commit()
con.close()

broken = chain_state()
print(f"  tampered chain: {json.dumps(broken)[:220]}")
check("a tampered chain reads as broken", broken.get("state") == "broken",
      json.dumps(broken)[:300])
check("...and is reported as checked, because it was",
      broken.get("checked") is True and broken.get("ok") is False,
      json.dumps(broken)[:200])
check("...naming the row, so the alarm is actionable",
      "row" in (broken.get("detail", "") or "").lower(), broken.get("detail", "")[:200])
check("...and offering no glib remedy, because a broken chain has none",
      not broken.get("remedy"), str(broken.get("remedy")))

# ---- the same database, with a verifier that cannot run -------------------
#
# Same rows, same tampering — the ONLY thing that changes is that the checker
# dies. If the state stays "broken" here, the app is guessing.
CRASHES = {
    # The reported crash, verbatim in shape: a module-level TypeError from a
    # 3.10 annotation evaluated by 3.9. Exit code 1, with a traceback.
    "the annotation TypeError a 3.9 interpreter raises":
        "raise TypeError(\"unsupported operand type(s) for |: "
        "'types.GenericAlias' and 'NoneType'\")\n",
    # A verifier that exits 1 saying nothing at all.
    "a verifier that exits 1 silently":
        "import sys\nsys.exit(1)\n",
    # A verifier that prints something that LOOKS like a failure but reached no
    # verdict. The old code would have shown this as tampering, in the
    # verifier's own words, which is the most convincing possible false alarm.
    "a verifier that prints FAIL and dies before deciding":
        "import sys\nprint('FAIL: audit chain broken at row id 2', file=sys.stderr)\n"
        "sys.exit(1)\n",
    # A syntax error: it never even imports.
    "a verifier that does not parse":
        "def verify(  # noqa\n",
}
for label, body in CRASHES.items():
    CHAIN_VERIFIER.write_text(body)
    crashed = chain_state()
    print(f"  {label}: state={crashed.get('state')}")
    check(f"{label} leaves the chain UNCHECKED",
          crashed.get("state") == "unchecked", json.dumps(crashed)[:300])
    check(f"...and is NEVER reported as broken",
          crashed.get("state") != "broken" and crashed.get("checked") is False,
          json.dumps(crashed)[:300])
    detail = (crashed.get("detail") or "")
    check(f"...and never claims the record was altered",
          not any(w in detail.lower() for w in ("altered", "tamper")), detail[:300])
    check(f"...saying instead that nothing was checked",
          "nothing was checked" in detail.lower(), detail[:300])
    check(f"...and never puts a traceback where the explanation goes",
          not looks_like_a_traceback(detail) and "TypeError:" not in detail,
          detail[:400])
    # The machine's own words are still shown — they are the only clue to why
    # — but in the secondary line, quoted, beside the command that reproduces
    # it. That is the difference between a report and a core dump.
    check(f"...while still quoting what it reported, somewhere secondary",
          "It reported:" in (crashed.get("remedy") or ""),
          str(crashed.get("remedy"))[:300])

# It still says the log is not to be trusted-as-verified: "could not check" is
# not "fine". A viewer that cannot check the chain keeps saying so.
CHAIN_VERIFIER.write_text(CRASHES["a verifier that exits 1 silently"])
crashed = chain_state()
check("an unchecked chain is never reported as ok",
      crashed.get("ok") is False, json.dumps(crashed)[:200])

# ---- and a missing verifier is unchecked too, not broken ------------------
CHAIN_VERIFIER.unlink()
# PATH and the search directories are emptied as well: with an importable
# aegis-mcp on this machine, the installed-package fallback would find a
# perfectly good verifier elsewhere and the answer would be about that one.
gone = chain_state(PATH="/nonexistent-for-this-check", AEGIS_PYTHON_DIRS="")
check("a bundle with no verifier at all is unchecked, not broken",
      gone.get("state") == "unchecked", json.dumps(gone)[:300])
check("...and says where it looked", "AEGIS_HOME" in (gone.get("detail") or ""),
      (gone.get("detail") or "")[:300])
CHAIN_VERIFIER.write_bytes(GOOD_VERIFIER)

# ---- the Permissions screen makes the same distinction --------------------
#
# policyedit.py runs the same verifier to decide whether the rules may be
# edited. It locks either way — an edit made against a record nobody can vouch
# for is an edit nobody can reconstruct — but the reason shown must not be an
# accusation when nothing was checked.
CHAIN_RES = CHAINAPP / "Contents/Resources"


def policy_show() -> dict:
    done = subprocess.run(
        ["python3", "-m", "aegis.cli", "policy", "show"],
        capture_output=True, text=True, timeout=180, cwd=str(CHAIN_RES),
        env=clean_env(PYTHONPATH=str(CHAIN_RES), AEGIS_POLICY=str(POLICY),
                      AEGIS_AUDIT_DB=str(DB9)),
    )
    return json.loads(done.stdout) if done.stdout.strip() else {"raw": done.stderr[-300:]}


shown = policy_show()
check("with a tampered chain the editor locks and SAYS it is tampered",
      shown.get("editable") is False and shown.get("chain_state") == "broken",
      json.dumps(shown)[:300])
check("...in words that name the failure",
      "does not verify" in (shown.get("not_editable_reason") or ""),
      (shown.get("not_editable_reason") or "")[:300])

CHAIN_VERIFIER.write_text(CRASHES["the annotation TypeError a 3.9 interpreter raises"])
shown = policy_show()
print(f"  policy show, crashed verifier: {json.dumps(shown)[:240]}")
check("with a CRASHED verifier the editor still locks",
      shown.get("editable") is False, json.dumps(shown)[:300])
check("...but reports it as unchecked, not as tampering",
      shown.get("chain_state") == "unchecked", json.dumps(shown)[:300])
reason = shown.get("not_editable_reason") or ""
check("...and the sentence on screen makes no accusation",
      "does not verify" not in reason
      and not any(w in reason.lower() for w in ("altered", "tamper")), reason[:300])
check("...it says nothing was checked", "nothing was checked" in reason.lower(),
      reason[:300])
check("...with no traceback and no exception class in it",
      not looks_like_a_traceback(reason) and "TypeError:" not in reason, reason[:400])
check("...while the raw output is still available, separately",
      bool(shown.get("chain_detail")), str(shown.get("chain_detail"))[:200])
CHAIN_VERIFIER.write_bytes(GOOD_VERIFIER)

# ---- the marker itself is spelled the same in all three places ------------
def contains_prefix(path: Path) -> bool:
    return "AEGIS-VERIFY-VERDICT:" in path.read_text()


for where in (ROOT / "aegis/verify.py", ROOT / "aegis/policyedit.py",
              ROOT / "ui/src-tauri/src/audit.rs"):
    check(f"the verdict marker is spelled the same in {where.name}",
          contains_prefix(where), str(where))
check("...and the SHIPPED verifier is the one that prints it",
      "AEGIS-VERIFY-VERDICT:" in (INSTALLED / "Contents/Resources/aegis/verify.py").read_text())


# ---------------------------------------------------------------------------
rule("10. THE WINDOW CAN ACTUALLY BE MAXIMIZED")
# ---------------------------------------------------------------------------

# Reported as "the green button only slightly enlarges the window". Two
# separate constraints have to be right, and only one of them is in
# tauri.conf.json:
#
#   1. The OS window must be allowed to grow. macOS greys the zoom button out
#      on a non-resizable window, and caps the zoomed size at the window's
#      maxSize — which Tauri sets from maxWidth/maxHeight. Either would stop
#      zoom dead.
#   2. The page inside it has to grow too. It did not: `.window` was a hard
#      `width: 1000px; height: 700px` from when the window could only ever be
#      that size, and index.html pinned the viewport to `width=1000`. So the
#      frame grew and the app stayed a 1000x700 panel in the corner with dead
#      background around it — which is what "it did not maximize" looked like.

win = CONF["app"]["windows"][0]
check("the window is minimizable", win.get("minimizable") is True, json.dumps(win))
check("the window is maximizable", win.get("maximizable") is True, json.dumps(win))
check("...which needs it to be resizable, or macOS greys the zoom button out",
      win.get("resizable") is True, json.dumps(win))
check("...and NO maximum size, which macOS would apply as the zoom limit",
      win.get("maxWidth") is None and win.get("maxHeight") is None,
      json.dumps({k: win.get(k) for k in ("maxWidth", "maxHeight")}))
check("...with a minimum that protects the layout the design was drawn against",
      win.get("minWidth", 0) >= 800 and win.get("minHeight", 0) >= 600,
      json.dumps(win))
check("...and it does not start locked into fullscreen",
      win.get("fullscreen") is not True, json.dumps(win))

# The BUILT frontend, not the source: this is what is embedded in the binary.
DIST = ROOT / "ui/dist"
built_css = sorted(DIST.glob("assets/*.css"))
if not built_css:
    not_run("the built stylesheet checks", f"no built CSS under {DIST}")
else:
    css = "".join(f.read_text() for f in built_css)
    css_flat = css.replace(" ", "")
    check("the built app shell fills the window rather than a fixed 1000x700",
          ".window{" in css_flat and "width:100%" in css_flat.split(".window{", 1)[1][:200],
          css_flat.split(".window{", 1)[1][:160] if ".window{" in css_flat else "no .window rule")
    check("...with no hard-coded 1000px width left in it",
          "width:1000px" not in css_flat,
          "width:1000px still present in the built CSS")
    check("...and no hard-coded 700px height",
          "height:700px" not in css_flat,
          "height:700px still present in the built CSS")

built_html = DIST / "index.html"
if not built_html.is_file():
    not_run("the built index.html check", f"no built HTML at {built_html}")
else:
    html = built_html.read_text()
    check("the built page does not pin the viewport to a fixed width",
          "width=1000" not in html.replace(" ", ""),
          [l for l in html.splitlines() if "viewport" in l][:1])

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
    "    - that the window renders. This asks the shipped binary questions and\n"
    "      runs the Python it finds; it does not open a window or click anything\n"
    "    - that pressing the green button fills the screen. §10 establishes that\n"
    "      nothing in the config or the built page PREVENTS it — no max size, a\n"
    "      resizable window, a shell that grows — which is where the bug was.\n"
    "      The click itself needs a human or an accessibility harness\n"
    "    - that the Dock draws the icon. §6 establishes that the icns is a real\n"
    "      picture at the sizes the Dock uses and that Info.plist names it.\n"
    "      macOS also caches icons, so a reinstall can show a stale one\n"
    "    - that a machine with NO Python at all refuses correctly. §8 proves the\n"
    "      refusal with only an old Python reachable; \"none at all\" is the same\n"
    "      code path with an empty rejected list\n"
    "    - code signing or notarisation, neither of which this build does\n"
)
sys.exit(1 if (FAILED or NOT_RUN) else 0)
