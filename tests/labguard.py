"""Aegis test harness guard — make it impossible to run against real state.

Five harnesses have written to the operator's real installation: S2 deleted a
row from the live audit database, S3a spent a day proving `audit.py` had not
skipped an id because of it, S4 reached for the login keychain, S5 engaged the
real kill switch, and S9b appended four rows and wrote a real sandbox profile.

The cause is the same every time, and it is **not** carelessness about whether
to pin — every one of those suites believed it had pinned. It is that the
pinning was done in shell-level or subprocess-level environment plumbing which
silently failed to apply:

    env $E python3 -m aegis.cli run ...      # $E unquoted; vars never applied
    ENV = {**os.environ, "AEGIS_AUDIT_DB": ...}   # set for children only,
                                                  # never for this process

Both look right. Both run happily. Neither raises anything. The suite then
writes to `~/Library/Application Support/Aegis` and reports success.

WHAT THIS MODULE DOES DIFFERENTLY

It does not check that the environment variables are *set*. It asks the real
Aegis resolvers **where they would actually put things**, and refuses to let the
suite continue unless every answer is inside the temp lab:

    aegis.audit.default_db_path()        -> the audit database
    aegis.proxy.default_policy_path()    -> policy.json
    aegis.killswitch.killswitch_path()   -> KILLSWITCH
    aegis.sandbox.profile_path()         -> the sandbox profile

and then asks the same question **again inside a child process**, with the env
the suite will hand to its subprocesses. That second check is the one that
matters: every failure in the list above was a parent/child divergence, and a
guard that only looked at `os.environ` in this process would have passed all
five.

A failure is `SystemExit`, raised at import time, before the suite has created
a file or spawned anything. There is no flag to override it. A test harness that
can be talked into touching real state is a test harness that eventually will.

USE

    import labguard
    LAB = labguard.pin("aegis-s9-")          # creates the lab, pins, verifies
    ...
    labguard.assert_untouched("after everything ran")

`pin(..., fake_home=True)` pins by pointing `HOME` at a directory inside the lab
instead of setting `AEGIS_*`, for suites that need to exercise the real
default-path logic (S7 does). The verification is identical either way, because
it checks where the resolvers land, not how they were told.
"""

import atexit
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The operator's true home, captured at import — BEFORE `pin(fake_home=True)`
# moves HOME into the lab. Computing it later would make `real_dir()` point at
# the lab's fake home, so the guard would fingerprint the lab, watch the wrong
# directory entirely, and never notice a real change. That bug was live for one
# run and is the reason this is a module-level constant rather than a call.
_REAL_HOME = Path.home()

# Everything the resolvers can be asked about. Adding a control with a new
# path means adding it here, or the guard silently stops covering it.
RESOLVERS = {
    "audit database": "from aegis.audit import default_db_path as f",
    "policy file": "from aegis.proxy import default_policy_path as f",
    "kill switch": "from aegis.killswitch import killswitch_path as f",
    "sandbox profile": "from aegis.sandbox import profile_path as f",
}

_CHILD_PROBE = (
    "import json,sys;"
    "sys.path.insert(0, %r);"
    "out={};"
    + "".join(
        f"exec({body!r}); out[{name!r}]=str(f());"
        for name, body in RESOLVERS.items()
    )
    + "print(json.dumps(out))"
)

_LAB: Path | None = None
_BASELINE: dict = {}


# ---------------------------------------------------------------------------
# what "real state" means, so the guard can prove it is untouched
# ---------------------------------------------------------------------------


def real_dir() -> Path:
    """The operator's actual Aegis directory, computed WITHOUT the env pins.

    Deliberately not via `default_db_path()`: that is the thing being redirected,
    and asking it would return the lab. This has to be the real place.
    """
    if sys.platform == "darwin":
        return _REAL_HOME / "Library" / "Application Support" / "Aegis"
    return Path(
        os.environ.get("XDG_DATA_HOME", _REAL_HOME / ".local" / "share")
    ) / "aegis"


def _real_watch() -> list[Path]:
    base = real_dir()
    return [
        base / "audit.db", base / "audit.db-wal", base / "policy.json",
        base / "KILLSWITCH", base / "sandbox-profile.json",
        base / "aegis-head.txt", base / "trash",
        _REAL_HOME / ".mcp.json", _REAL_HOME / ".claude.json",
    ]


def _fingerprint() -> dict:
    out = {}
    for path in _real_watch():
        try:
            if path.is_dir():
                out[str(path)] = f"dir:{len(list(path.iterdir()))}"
            else:
                out[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            out[str(path)] = "absent"
    return out


# ---------------------------------------------------------------------------
# the guard
# ---------------------------------------------------------------------------


def _abort(reason: str, detail: str = "") -> None:
    raise SystemExit(
        "\n"
        "================================================================\n"
        "  HARNESS ABORTED — a path resolves to the operator's real state\n"
        "================================================================\n"
        f"{reason}\n"
        + (detail + "\n" if detail else "")
        + "\n"
        "Nothing has been created and nothing has run. This is the guard in\n"
        "tests/labguard.py, and it has no override: five suites have written to\n"
        "the real installation because environment pinning failed silently, and\n"
        "a harness that can be talked past is one that eventually is.\n"
        "\n"
        "Fix the pinning, not the guard.\n"
    )


def _inside(path: Path, lab: Path) -> bool:
    try:
        resolved = Path(path).expanduser().resolve()
    except (OSError, ValueError):
        return False
    return resolved == lab or resolved.is_relative_to(lab)


def _resolve_in_process() -> dict:
    """Where this process would put each thing, right now.

    The repository goes on sys.path here rather than being assumed: the guard
    runs before the suite's own `sys.path.insert`, because it has to run before
    anything at all.
    """
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    found = {}
    for name, body in RESOLVERS.items():
        namespace: dict = {}
        exec(body, namespace)  # noqa: S102 - the statements are literals above
        found[name] = Path(namespace["f"]())
    return found


def _resolve_in_child(env: dict) -> dict:
    """Where a CHILD process with this env would put each thing.

    The check the other five failures needed. Run from a neutral cwd so nothing
    resolves relative to the repository by accident.
    """
    done = subprocess.run(
        [sys.executable, "-c", _CHILD_PROBE % str(ROOT)],
        capture_output=True, text=True, timeout=120, cwd=os.path.sep,
        env={**env, "PYTHONPATH": os.pathsep.join(
            [str(ROOT), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)},
    )
    if done.returncode != 0:
        _abort(
            "the guard could not ask a child process where it would write.",
            f"  exit {done.returncode}\n  {done.stderr.strip()[-400:]}",
        )
    try:
        return {k: Path(v) for k, v in json.loads(done.stdout).items()}
    except (json.JSONDecodeError, AttributeError):
        _abort("the child probe returned nothing usable.", done.stdout[:300])
    return {}


def pin(prefix: str, *, fake_home: bool = False, extra_env: dict | None = None) -> Path:
    """Create the lab, pin every Aegis path into it, and verify. Returns the lab.

    Call this before importing anything from `aegis` and before creating any
    file. On any doubt it raises SystemExit.
    """
    global _LAB, _BASELINE

    lab = Path(tempfile.mkdtemp(prefix=prefix)).resolve()

    if fake_home:
        home = lab / "home"
        home.mkdir(parents=True, exist_ok=True)
        os.environ["HOME"] = str(home)
        # A stale AEGIS_* from the caller's shell would defeat the point of
        # exercising the default-path logic, and could point outside the lab.
        for key in ("AEGIS_AUDIT_DB", "AEGIS_POLICY", "AEGIS_KILLSWITCH",
                    "AEGIS_SANDBOX_PROFILE"):
            os.environ.pop(key, None)
        os.environ.pop("XDG_DATA_HOME", None)
        os.environ.pop("XDG_CONFIG_HOME", None)
    else:
        # Pin the minimum and let the rest DERIVE, then verify where they land.
        # The kill switch and the sandbox profile are deliberately not set: both
        # derive from the audit database's directory, and that derivation is
        # itself a property under test (S5 asserts the kill switch sits beside
        # audit.db). Forcing them would mask the behaviour instead of checking
        # it, and would make the guard weaker while looking stricter.
        os.environ["AEGIS_AUDIT_DB"] = str(lab / "audit.db")
        os.environ["AEGIS_POLICY"] = str(lab / "policy.json")
        os.environ.pop("AEGIS_KILLSWITCH", None)
        os.environ.pop("AEGIS_SANDBOX_PROFILE", None)

    for key, value in (extra_env or {}).items():
        os.environ[key] = str(value)

    # 1. this process
    for name, path in _resolve_in_process().items():
        if not _inside(path, lab):
            _abort(
                f"the {name} would be written OUTSIDE the lab, in this process.",
                f"  resolves to: {Path(path).expanduser().resolve()}\n"
                f"  lab:         {lab}",
            )

    # 2. a child process, with the env subprocesses will be given. This is the
    #    check S2, S3a, S4, S5 and S9b all needed and none of them had.
    for name, path in _resolve_in_child(dict(os.environ)).items():
        if not _inside(path, lab):
            _abort(
                f"the {name} would be written OUTSIDE the lab BY A CHILD PROCESS.",
                f"  child resolves to: {Path(path).expanduser().resolve()}\n"
                f"  lab:               {lab}\n"
                f"  The parent is pinned correctly and the child is not — which\n"
                f"  is exactly how the previous five incidents happened.",
            )

    _LAB = lab
    _BASELINE = _fingerprint()
    atexit.register(_atexit_check)
    return lab


def repin(**overrides) -> None:
    """Move a pinned path and re-verify, for suites that relocate one.

    A suite that re-points `AEGIS_AUDIT_DB` after `pin()` — several do, to put
    the database in a subdirectory — must come through here rather than writing
    `os.environ` directly, or the new location is never checked. Both the
    in-process and the child-process verifications run again.
    """
    for key, value in overrides.items():
        os.environ[key] = str(value)
    for name, path in _resolve_in_process().items():
        if not _inside(path, lab()):
            _abort(f"after repin(), the {name} is outside the lab.",
                   f"  resolves to: {Path(path).expanduser().resolve()}\n"
                   f"  overrides:   {overrides}")
    for name, path in _resolve_in_child(dict(os.environ)).items():
        if not _inside(path, lab()):
            _abort(f"after repin(), a CHILD would put the {name} outside the lab.",
                   f"  resolves to: {Path(path).expanduser().resolve()}")


def lab() -> Path:
    if _LAB is None:
        _abort("labguard.pin() was never called, so nothing is pinned.")
    return _LAB  # type: ignore[return-value]


def subprocess_env(**overrides) -> dict:
    """The environment to hand a subprocess, verified to stay inside the lab.

    Use this instead of building `{**os.environ, ...}` by hand: an override that
    points a path out of the lab is caught here rather than on disk.
    """
    env = {**os.environ, **{k: str(v) for k, v in overrides.items()}}
    for name, path in _resolve_in_child(env).items():
        if not _inside(path, lab()):
            _abort(
                f"a subprocess override would put the {name} outside the lab.",
                f"  resolves to: {Path(path).expanduser().resolve()}\n"
                f"  overrides:   {overrides}",
            )
    return env


def check_policy_doc(doc: dict) -> dict:
    """Assert a policy document keeps its own paths inside the lab.

    `workspace_roots` and `trash_dir` come from the policy, not the environment,
    so no amount of env pinning constrains them. A suite whose policy points at
    a real directory would have Aegis write there legitimately.
    """
    for root in doc.get("workspace_roots") or []:
        if not _inside(Path(root), lab()):
            _abort("a policy workspace_root points outside the lab.",
                   f"  {root}")
    trash = doc.get("trash_dir")
    if trash and not _inside(Path(trash), lab()):
        _abort("a policy trash_dir points outside the lab.", f"  {trash}")
    return doc


def assert_untouched(when: str = "") -> tuple[bool, list]:
    """(ok, changed paths). Fingerprints the real installation and compares."""
    now = _fingerprint()
    moved = [k for k in _BASELINE if _BASELINE.get(k) != now.get(k)]
    return (not moved), moved


def _atexit_check() -> None:
    """Last line of defence: shout on the way out if real state moved.

    A suite that forgets to call `assert_untouched` still cannot damage the
    operator's installation quietly.
    """
    ok, moved = assert_untouched()
    if not ok:
        print(
            "\n*** labguard: THE OPERATOR'S REAL AEGIS STATE CHANGED DURING THIS "
            "RUN ***\n    " + "\n    ".join(moved)
            + "\n    This is the incident the guard exists to prevent. Investigate "
              "before\n    trusting anything this run reported.\n",
            file=sys.stderr,
        )
