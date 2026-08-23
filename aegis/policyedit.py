"""Aegis S10 — editing policy.json safely, from the UI or the CLI.

Until now policy.json was written by `aegis init` once and by a human with an
editor after that. S10 lets a user change what an agent may touch from a
Permissions screen. **That is new attack surface and this file is where it
lives**, so it is worth being explicit about what it is guarding against.

A7 — "Aegis's own policy configuration. Compromise it and every other control
falls" — is the second-most-valuable asset in the threat model. Anything that
writes this file is a path to widening every control at once. The mitigations,
in the order they run:

  1. **The audit chain must verify first.** If the tamper-evident log is broken,
     Aegis will not also let you change the rules: an edit made while the record
     is untrustworthy is an edit nobody can reconstruct afterwards. Refusing is
     the only answer that does not compound the problem.
  2. **The document is validated by the real loader.** Not by a second
     implementation that can drift — `Policy(doc, path)` is the same class the
     proxy calls at startup, so "the proxy would reject this" is a fact rather
     than a prediction. Same reasoning that made the UI shell out to verify.py
     rather than reimplement the hash rule (S6).
  3. **Widening requires an explicit confirmation naming what is granted.**
     Narrowing does not. The asymmetry is deliberate: a user who removes access
     in a hurry has lost nothing they cannot restore, and a user who grants it
     in a hurry has.
  4. **Atomic write at 0600, into the data directory, never a workspace root.**
     `Policy` already refuses to load a policy inside a workspace root; this
     refuses to write one there, so the failure arrives as a sentence instead of
     as a proxy that will not start.
  5. **Every change is audited as `policy_edited`, recording WHAT changed** —
     the folder and the two effects — and never the whole file. A policy can
     name private paths, and a log that copied the file on every edit would be
     a second place those paths live.

WHAT THIS DOES NOT DO

It does not make the change take effect in a running proxy. `Policy.load()` runs
once at startup and the result is cached for the process, so an edit applies to
the **next** session. Every caller here says so, and `aegis doctor` detects a
proxy that has been running since before the last edit.
"""

import fnmatch
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

try:  # S7 import plumbing
    from .audit import AuditError, AuditStore, default_db_path
    from .policy import Effect, Policy, PolicyError, _within
    from .proxy import default_policy_path
except ImportError:  # pragma: no cover
    from audit import AuditError, AuditStore, default_db_path
    from policy import Effect, Policy, PolicyError, _within
    from proxy import default_policy_path

VERIFIER = Path(__file__).with_name("verify.py")

EFFECT_WORDS = {
    Effect.ALLOW: "Allow",
    Effect.ASK: "Ask",
    Effect.DENY: "Deny",
}


class EditError(Exception):
    """A refusal. The message is written to be shown to a person."""


# ---------------------------------------------------------------------------
# describing a change in words a person can check
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Change:
    """One difference, in plain English, with whether it grants anything.

    `widening` is the field the confirmation gate reads. It is computed per
    change rather than by diffing the documents, because "did this grant
    something" is a question about meaning and a JSON diff only knows about
    text.
    """

    kind: str
    target: str
    before: str
    after: str
    widening: bool
    sentence: str


def folder_effect(doc: dict, path: Path) -> Effect:
    """What the current document says about this folder, as one of three states.

    Reads the document rather than a loaded Policy so it can describe a document
    that has not been accepted yet — the UI needs to show the pending state.
    """
    resolved = Path(path).expanduser().resolve()
    best: tuple[Path, Effect] | None = None
    for entry in doc.get("folder_rules") or []:
        folder = Path(entry["path"]).expanduser().resolve()
        if _within(resolved, folder) and (
            best is None or len(str(folder)) > len(str(best[0]))
        ):
            best = (folder, Effect(entry["effect"]))
    if best is not None:
        return best[1]
    for root in doc.get("workspace_roots") or []:
        if _within(resolved, Path(root).expanduser().resolve()):
            return Effect.ALLOW
    return Effect.DENY


def describe_folder(path: Path, effect: Effect) -> str:
    """'Can read and change your Robotics folder' — never 'filesystem.read'.

    The Permissions screen is the one place a person decides what an agent may
    touch, and a rule_id is not a decision anyone can make. Same discipline as
    S6's translate layer, which a test there asserts never leaks snake_case.
    """
    name = Path(path).name or str(path)
    if effect is Effect.ALLOW:
        return f"Can read and change your {name} folder"
    if effect is Effect.ASK:
        return f"Must ask you first before touching your {name} folder"
    return f"Cannot open your {name} folder at all"


def plan_folder(doc: dict, path, effect: Effect) -> tuple[dict, list[Change]]:
    """(new document, changes) for setting one folder to one of the three states.

    Allow is expressed as a workspace root when the folder is not already
    covered, because that is the shape the rest of Aegis reads — the sandbox
    profile derives writable roots from `workspace_roots` (S9), so a folder
    allowed only by a folder rule would be readable at the MCP layer and not
    writable at the kernel one. Keeping the two in agreement matters more than
    the schema being tidy.
    """
    resolved = Path(path).expanduser().resolve()
    if not resolved.exists():
        raise EditError(
            f"{resolved} does not exist. Aegis will not grant access to a folder "
            f"that is not there — a typo would quietly permit whatever is created "
            f"at that path later."
        )
    if not resolved.is_dir():
        raise EditError(f"{resolved} is not a folder")

    before = folder_effect(doc, resolved)
    if before is effect:
        return json.loads(json.dumps(doc)), []

    new = json.loads(json.dumps(doc))
    rules = [
        e for e in (new.get("folder_rules") or [])
        if Path(e["path"]).expanduser().resolve() != resolved
    ]
    roots = [
        r for r in (new.get("workspace_roots") or [])
        if Path(r).expanduser().resolve() != resolved
    ]

    if effect is Effect.ALLOW:
        roots.append(str(resolved))
    else:
        rules.append({"path": str(resolved), "effect": effect.value})
        # Setting a folder to Ask or Deny used to DROP it from workspace_roots.
        # For anyone with a single working folder — which is what `aegis init`
        # writes — that emptied the list, `Policy` refused the document
        # ("workspace_roots must be a non-empty list"), and the write failed. On
        # screen the selector simply never moved.
        #
        # So the root stays and the folder rule carries the restriction. That is
        # sound because folder rules are evaluated at containment and Deny/Ask
        # win there, and it is what lets someone shut their only folder without
        # first inventing a second one. `sandbox.py` reads the same rules so the
        # kernel agrees with the MCP layer.
        if not roots:
            roots = [str(resolved)]

    new["workspace_roots"] = roots
    if rules:
        new["folder_rules"] = rules
    else:
        new.pop("folder_rules", None)

    # Ranked so "did this grant something" is a comparison, not a special case.
    rank = {Effect.DENY: 0, Effect.ASK: 1, Effect.ALLOW: 2}
    widening = rank[effect] > rank[before]
    change = Change(
        kind="folder",
        target=str(resolved),
        before=EFFECT_WORDS[before],
        after=EFFECT_WORDS[effect],
        widening=widening,
        sentence=(
            f"{Path(resolved).name}: {EFFECT_WORDS[before]} -> "
            f"{EFFECT_WORDS[effect]} ({describe_folder(resolved, effect)})"
        ),
    )
    return new, [change]


def plan_deny(doc: dict, pattern: str, add: bool = True) -> tuple[dict, list[Change]]:
    """(new document, changes) for adding or removing a deny-list entry.

    Removing one is widening — it is the strongest rule in the file, checked
    before everything else, so taking one out grants more than any folder change
    can.
    """
    pattern = (pattern or "").strip()
    if not pattern:
        raise EditError("a deny-list entry cannot be empty")
    new = json.loads(json.dumps(doc))
    current = list(new.get("deny_paths") or [])
    if add and pattern in current:
        return new, []
    if not add and pattern not in current:
        return new, []

    if add:
        current.append(pattern)
        sentence = (
            f"Never open anything matching {pattern!r}, in any folder, "
            f"whatever else is allowed"
        )
    else:
        current.remove(pattern)
        sentence = (
            f"STOP blocking {pattern!r}. Files matching it become readable "
            f"wherever a folder already allows access"
        )
    new["deny_paths"] = current
    return new, [Change(
        kind="deny_paths",
        target=pattern,
        before="blocked" if not add else "not blocked",
        after="blocked" if add else "not blocked",
        widening=not add,
        sentence=sentence,
    )]


# ---------------------------------------------------------------------------
# the gates
# ---------------------------------------------------------------------------


def chain_verifies(db: Path | None = None) -> tuple[bool, str]:
    """(ok, first line of the verifier's output).

    Shells out to verify.py rather than importing it: it is the authority (S2),
    it carries its own independent copy of the chain rule on purpose, and a
    second caller reimplementing the check would be a third thing to keep in
    agreement.
    """
    db = db or default_db_path()
    if not db.exists():
        return True, "no audit database yet — nothing to verify"
    try:
        done = subprocess.run(
            [sys.executable, str(VERIFIER), str(db)],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"could not run the verifier ({type(exc).__name__}: {exc})"
    out = (done.stdout + done.stderr).strip().splitlines()
    return done.returncode == 0, (out[0] if out else "(no output)")


def assert_writable_location(path: Path, doc: dict) -> None:
    """Refuse to write the policy inside a folder the agent can reach."""
    resolved = Path(path).expanduser().resolve()
    for root in doc.get("workspace_roots") or []:
        if _within(resolved, Path(root).expanduser().resolve()):
            raise EditError(
                f"REFUSING: the policy file is {resolved}, which is inside the "
                f"workspace root {root}. The agent can write everywhere inside a "
                f"workspace root, so a policy there is a policy the agent can "
                f"rewrite. Nothing was written."
            )
    # Both sides resolved, or macOS's /tmp -> /private/tmp and /var ->
    # /private/var make every legitimate write look like an escape. Caught by
    # running the demo on a raw mktemp path; the suite missed it because
    # labguard hands out an already-resolved lab, so both sides matched. Same
    # bug S9's sandbox profile had, for the same reason.
    data_dir = Path(default_db_path().parent).expanduser().resolve()
    if resolved.parent != data_dir:
        raise EditError(
            f"REFUSING: the policy file is {resolved}, which is not in the Aegis "
            f"data directory ({data_dir}). This editor only writes there."
        )


def validate(doc: dict, path: Path) -> Policy:
    """Load the document with the proxy's own loader, or refuse with its words."""
    try:
        return Policy(doc, Path(path))
    except PolicyError as exc:
        raise EditError(
            f"REFUSING: the proxy would reject this policy at startup, so it is "
            f"not being written.\n  {exc}"
        ) from None
    except Exception as exc:  # noqa: BLE001 - anything unexpected is still a refusal
        raise EditError(
            f"REFUSING: the policy could not be validated "
            f"({type(exc).__name__}: {exc}); nothing was written."
        ) from None


def grant_summary(changes: list[Change]) -> str:
    return "; ".join(c.sentence for c in changes if c.widening)


# ---------------------------------------------------------------------------
# applying
# ---------------------------------------------------------------------------


def apply(
    new_doc: dict,
    changes: list[Change],
    *,
    path: Path | None = None,
    confirm_grant: bool = False,
    db: Path | None = None,
) -> dict:
    """Write the policy, after every gate. Raises EditError on any refusal.

    Returns a small result dict for the caller to show; it never returns the
    document, because a caller that echoes the file has undone the point of
    recording only what changed.
    """
    path = Path(path) if path is not None else default_policy_path()
    db = db or default_db_path()

    if not changes:
        return {"written": False, "reason": "nothing to change", "changes": []}

    # 1. the record must be trustworthy before the rules are changed
    ok, detail = chain_verifies(db)
    if not ok:
        raise EditError(
            "REFUSING: the audit chain does not verify, so Aegis will not also "
            "change the rules.\n"
            f"  {detail}\n"
            "  An edit made while the record cannot be trusted is an edit nobody "
            "can reconstruct. Investigate the log first — `python3 -m aegis.verify`."
        )

    # 2. where it is going
    assert_writable_location(path, new_doc)

    # 3. the proxy's own loader decides whether this is a valid policy
    validate(new_doc, path)

    # 4. widening needs to be said out loud
    widening = [c for c in changes if c.widening]
    if widening and not confirm_grant:
        raise EditError(
            "REFUSING: this grants access and has not been confirmed.\n  "
            + "\n  ".join(c.sentence for c in widening)
            + "\n  Confirm the grant explicitly to proceed. Removing access "
              "needs no confirmation; adding it does."
        )

    # 5. record BEFORE the write, so a crash between the two leaves evidence
    #    that a change was attempted rather than a changed file nobody logged.
    store = None
    try:
        store = AuditStore.open(db)
        store.record(
            tool="aegis policy",
            effect="allow" if not widening else "ask",
            rule_id="policy_edited",
            reason=(
                ("granted: " if widening else "changed: ")
                + "; ".join(c.sentence for c in changes)
                + f" (policy {path.name}; applies to the NEXT proxy session — a "
                  f"running proxy cached the old policy at startup)"
            ),
            paths=[c.target for c in changes],
        )
    except AuditError as exc:
        raise EditError(
            f"REFUSING: the change could not be recorded ({exc}), so it was not "
            f"made. Same rule as every other decision: what cannot be recorded "
            f"does not happen."
        ) from None
    finally:
        if store is not None:
            store.close()

    # 6. the write itself
    write_atomic(path, new_doc)
    return {
        "written": True,
        "path": str(path),
        "changes": [c.sentence for c in changes],
        "granted": bool(widening),
        "applies": "next session",
    }


def write_atomic(path: Path, doc: dict) -> Path:
    """0600, atomic, never a partial policy on disk.

    A half-written policy is a policy the proxy refuses to load, which fails
    closed — but it also means the next launch mysteriously will not start, and
    `os.replace` costs nothing.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".aegis-edit{os.getpid()}")
    body = json.dumps(doc, indent=2) + "\n"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, body.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise EditError(f"could not write {path}: {exc}") from None
    return path


# ---------------------------------------------------------------------------
# what the UI reads
# ---------------------------------------------------------------------------


def load_doc(path: Path | None = None) -> dict:
    path = Path(path) if path is not None else default_policy_path()
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise EditError(f"no policy at {path}. Run `aegis init` first.") from None
    except (OSError, json.JSONDecodeError) as exc:
        raise EditError(f"cannot read {path}: {exc}") from None


def snapshot(path: Path | None = None, db: Path | None = None) -> dict:
    """Everything the Permissions screen needs, in one read.

    Includes `editable` and the reason, so the screen can disable its controls
    for the right reason rather than failing at the moment someone clicks.
    """
    path = Path(path) if path is not None else default_policy_path()
    doc = load_doc(path)
    ok, detail = chain_verifies(db)

    # ONE row per folder, carrying its EFFECTIVE state.
    #
    # A folder can appear in both `workspace_roots` and `folder_rules` — that is
    # exactly what happens when someone sets their only working folder to Deny,
    # since the root has to stay for the document to remain valid. Listing the
    # two sources separately showed that folder twice, once as Allow and once as
    # Deny, which is worse than showing it wrong: it makes the screen look like
    # it does not know its own state. `folder_effect` already resolves the
    # precedence, so it decides here too.
    seen: dict[str, None] = {}
    for source in ((doc.get("workspace_roots") or [])
                   + [e["path"] for e in (doc.get("folder_rules") or [])]):
        key = str(Path(source).expanduser())
        if key not in seen:
            seen[key] = None

    folders = []
    for key in seen:
        resolved = Path(key)
        effect = folder_effect(doc, resolved)
        folders.append({
            "path": key,
            "name": resolved.name or key,
            "effect": effect.value,
            "label": EFFECT_WORDS[effect],
            "sentence": describe_folder(resolved, effect),
        })

    return {
        "policy_path": str(path),
        "folders": folders,
        "deny_paths": [
            {"pattern": p, "sentence": f"Never open anything matching {p}, in any folder"}
            for p in (doc.get("deny_paths") or [])
        ],
        "editable": ok,
        "not_editable_reason": "" if ok else (
            "The audit chain does not verify, so Aegis will not let the rules be "
            "changed until that is investigated. " + detail
        ),
        "applies_note": (
            "Changes apply the NEXT time your agent starts. A proxy that is "
            "already running read the policy once, when it launched, and is "
            "still enforcing that copy."
        ),
    }


def policy_digest(path: Path | None = None) -> str:
    """Stable digest of the policy as loaded, for staleness detection."""
    import hashlib

    path = Path(path) if path is not None else default_policy_path()
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return ""
    return hashlib.sha256(
        json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def last_edit(db: Path | None = None) -> dict | None:
    """The newest `policy_edited` row, or None. Read-only, never writes."""
    import sqlite3

    db = db or default_db_path()
    if not db.exists():
        return None
    try:
        conn = sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True, timeout=10.0)
    except (sqlite3.Error, ValueError):
        try:
            conn = sqlite3.connect(str(db), timeout=10.0)
        except sqlite3.Error:
            return None
    try:
        row = conn.execute(
            "SELECT id, ts, reason FROM audit WHERE rule_id='policy_edited' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if row is None:
        return None
    return {"id": int(row[0]), "ts": float(row[1]), "reason": str(row[2]),
            "age_seconds": max(0.0, time.time() - float(row[1]))}
