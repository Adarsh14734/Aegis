#!/usr/bin/env python3
"""Aegis audit chain verifier — standalone, offline, stdlib only.

    python3 aegis/verify.py [path/to/audit.db] [--expect-head HASH] [--quiet]
                            [--no-anchor] [--verdict]

    exit 0  chain intact
    exit 1  chain broken (prints the first bad row and what mismatched)
    exit 2  cannot read the database at all — or cannot run at all

    --verdict adds one machine-readable last line of stdout,
    "AEGIS-VERIFY-VERDICT: intact|broken|unreadable", printed only once a
    verdict has actually been reached. A caller that sees no marker knows the
    checker never got to an answer, which is NOT the same as an answer of
    "broken" — see the comment above VERDICT_PREFIX.

S0 open question #4: "Does the audit verifier run offline, without the control
plane? It must, or a compromised control plane can lie about its own
integrity."

This file therefore imports **nothing from Aegis** — not policy.py, not
proxy.py, not audit.py. The hash function below is deliberately a second,
independent copy. If someone edits the chain rule in audit.py to make forged
rows validate, this file keeps computing the old rule and the forgery shows up.
Copy this file to another machine and it still works with the rest of Aegis
absent. Keeping the two copies in agreement is a maintenance cost that is
being paid on purpose.

TWO PAYLOAD RULES (S8)
  S8 added host/status/byte columns to the row, which changes what is hashed.
  Rather than invalidate every database written before it — an event
  indistinguishable from an attack — the payload is versioned per row and both
  rules live here, each an independent copy of audit.py's:

    v NULL or 1   the seven original fields          (every pre-S8 row)
    v = 2         those plus v, host, status, req_bytes, resp_bytes

  The version comes from the row's own `v` column and is itself hashed under
  v2, so a row cannot be moved between rules without invalidating itself. A
  database with no `v` column at all — written before S8 and never opened
  since — is read with the old query and verifies exactly as it always did. A
  version this file does not implement is a failure, not a pass.

WHAT A PASS DOES AND DOES NOT MEAN
  Detected: any edited field, any deleted row (ids go non-contiguous), any
  reordering, any inserted row, any re-hashed row whose successors were not
  also re-hashed.
  NOT detected without an external anchor: deleting the whole database, or
  truncating rows off the end and rehashing nothing (a short chain is still a
  valid chain). Record the head hash somewhere Aegis cannot reach and pass it
  back with --expect-head to close that gap.

  The `aegis-head.txt` file written next to the database on clean shutdown is
  used automatically when --expect-head is absent, but it is NOT an external
  anchor: it lives in the same directory, owned by the same user, unsigned.
  Anyone who can rewrite the database can rewrite it. It catches accidents —
  a half-copied database, a restored backup, a truncation by something that
  did not know the anchor existed — and it makes a deliberate truncation cost
  a second edit. Nothing more. A hash you wrote down elsewhere and passed with
  --expect-head is worth strictly more.
  NOT detected at all: an attacker with write access who recomputes the entire
  chain from the edited row forward. Nothing local can prevent that — see
  THREAT-MODEL.md §7.2. External anchoring of the head hash is the only fix.
"""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Minimum interpreter, checked before anything else in this file runs.
#
# This module's own annotations use `str | None`, which is valid *syntax* on
# 3.9 but a TypeError the moment a `def` line is evaluated. Without this guard
# an old interpreter produces a traceback, and a traceback is exit code 1 —
# the same code this file uses for "the chain is broken". A crashed verifier
# then reads as a tampered log, which is the worst lie this program can tell.
#
# So the check runs at import, above every `def`, and exits 2 (cannot check)
# with a sentence naming the version required. Deliberately a second copy of
# the constant in aegis/__init__.py: this file imports nothing from Aegis (S0
# open question #4) and that rule is worth more than the duplication.
# Written in the oldest Python that could possibly reach it — no f-strings, no
# annotations — because the whole point is to run where the rest does not.
# ---------------------------------------------------------------------------

MIN_PYTHON = (3, 10)


def _require_python():
    if sys.version_info >= MIN_PYTHON:
        return
    need = ".".join(str(n) for n in MIN_PYTHON)
    have = ".".join(str(n) for n in sys.version_info[:3])
    sys.stderr.write(
        "Aegis needs Python %s or newer, and this is Python %s.\n"
        "  interpreter: %s\n"
        "The audit chain was NOT checked. This says nothing about whether the\n"
        "log is intact — only that this interpreter cannot run the checker.\n"
        "Install Python %s or newer and run the verifier with it.\n"
        % (need, have, sys.executable, need)
    )
    raise SystemExit(2)


_require_python()

GENESIS_PREV_HASH = "0" * 64
FIELDS = ("id", "ts", "tool", "effect", "rule_id", "reason", "paths")

# S8 added four columns to the row and therefore a second hash rule. Both are
# implemented below, independently of audit.py as always. Which one applies to
# a row is read from that row's own `v` column, not guessed from whether the
# new columns happen to be NULL — a v2 row for a file read has NULL in all four
# and must still verify under v2.
V2_FIELDS = (
    "v", "id", "ts", "tool", "effect", "rule_id", "reason", "paths",
    "host", "status", "req_bytes", "resp_bytes",
)
KNOWN_VERSIONS = (None, 1, 2)

# Deliberately a second copy of the name audit.py uses. This file imports
# nothing from Aegis (S0 #4) and that rule is worth more than the duplication.
HEAD_FILE_NAME = "aegis-head.txt"


class AnchorError(Exception):
    """An anchor file exists but cannot be trusted. Present-but-broken is
    suspicious, so it is an error; absent is normal and is not."""


def read_anchor(db_path: Path):
    """(hash, id, source) from aegis-head.txt next to the db, or None.

    Returns None when there is no anchor file, or when the file anchors a
    different database — the default directory can hold several (audit.db and
    an archived audit.db.pre-reset-*), and applying one database's anchor to
    another would manufacture a failure.
    """
    path = db_path.parent / HEAD_FILE_NAME
    if not path.exists():
        return None
    try:
        text = path.read_text()
    except OSError as exc:
        raise AnchorError(f"{path} exists but cannot be read: {exc}") from exc

    fields = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        fields[key.strip()] = value.strip()

    named_db = fields.get("db")
    if named_db and named_db != db_path.name:
        return None

    head_hash = (fields.get("head_hash") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", head_hash):
        raise AnchorError(
            f"{path} exists but has no usable head_hash. An anchor file that "
            f"cannot be parsed is treated as a failure, not as absence."
        )
    try:
        head_id = int(fields.get("head_id", "-1"))
    except ValueError:
        head_id = -1
    return head_hash, head_id, str(path)


def default_db_path() -> Path:
    if override := os.environ.get("AEGIS_AUDIT_DB"):
        return Path(override).expanduser()
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "Aegis"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "aegis"
    return base / "audit.db"


def row_hash(values: dict, prev_hash: str) -> str:
    """The v1 rule. Every row written before S8 hashes under this and always
    will. Deliberately a second, independent copy of audit.py's — see the
    module docstring."""
    payload = json.dumps(
        {k: values[k] for k in FIELDS}, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256((payload + prev_hash).encode("utf-8")).hexdigest()


def row_hash_v2(values: dict, prev_hash: str) -> str:
    """The v2 rule, S8 onward. Also an independent second copy.

    The version is part of what is hashed, so a row cannot be moved between
    rules without invalidating itself. `host` is TEXT and the other three are
    INTEGER; SQLite hands back None for NULL, which json renders as null — the
    same shape audit.py fed in.
    """
    payload = json.dumps(
        {k: values[k] for k in V2_FIELDS}, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256((payload + prev_hash).encode("utf-8")).hexdigest()


def has_s8_columns(conn: sqlite3.Connection) -> bool:
    """Whether this database has ever been opened by S8 or later.

    A database written before S8 and never opened since has no `v` column at
    all, and asking for one is an OperationalError rather than a NULL. Such a
    database is entirely valid and must verify unchanged — so the column list
    is read first and the query built to match.
    """
    return "v" in {row[1] for row in conn.execute("PRAGMA table_info(audit)")}


def connect(path: Path) -> sqlite3.Connection:
    """Read-only if the platform allows it. A verifier that can write to the
    thing it is verifying is a bad shape, so read-only is tried first; SQLite
    refuses read-only opens of a WAL database that still needs recovery, and
    in that case a normal open is the only way to read it at all.

    Path.as_uri() rather than an f-string: the default macOS location contains
    a space, and a path containing '?' or '#' interpolated raw would be parsed
    as URI query/fragment and silently open a *different* database. A verifier
    that reports OK against the wrong file is worse than one that crashes.
    """
    try:
        return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=10.0)
    except (sqlite3.Error, ValueError):
        return sqlite3.connect(str(path), timeout=10.0)


def verify(path: Path, expect_head: str | None = None, quiet: bool = False,
           use_anchor: bool = True) -> int:
    if not path.exists():
        print(f"FAIL: no audit database at {path}", file=sys.stderr)
        return 2

    # An explicit --expect-head always wins: it is the stronger anchor, since
    # it came from outside this directory.
    #
    # The two anchors are checked differently, on purpose:
    #
    #   --expect-head    asserts what the head is *now*. Strict equality,
    #                    unchanged from S2.
    #   aegis-head.txt   records the head as of the last clean shutdown. The
    #                    log legitimately grows past it — another proxy was
    #                    still running, or a proxy was killed before it could
    #                    update the file. So the check is that the anchored
    #                    hash is still present *at its recorded id*: the
    #                    anchored prefix must be intact, and rows may only have
    #                    been appended after it. Demanding equality here would
    #                    cry wolf on ordinary operation, and an alarm that
    #                    fires on ordinary operation gets muted.
    anchor_source = "none"
    anchor_id = None
    anchor_hash = None
    if expect_head is not None:
        anchor_source = "--expect-head (supplied on the command line)"
    elif use_anchor:
        try:
            found = read_anchor(path)
        except AnchorError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
        if found is not None:
            anchor_hash, anchor_id, anchor_path = found
            anchor_source = f"{anchor_path} (written next to the db; not tamper-proof)"
    try:
        conn = connect(path)
        # Never let a missing table read as "an empty, intact log" — that is
        # how a verifier ends up blessing the wrong file.
        if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit'"
        ).fetchone():
            print(f"FAIL: {path} has no 'audit' table — not an Aegis audit log", file=sys.stderr)
            return 2
        versioned = has_s8_columns(conn)
        if versioned:
            cur = conn.execute(
                "SELECT id, ts, tool, effect, rule_id, reason, paths, prev_hash, "
                "row_hash, v, host, status, req_bytes, resp_bytes "
                "FROM audit ORDER BY id ASC"
            )
        else:
            cur = conn.execute(
                "SELECT id, ts, tool, effect, rule_id, reason, paths, prev_hash, row_hash "
                "FROM audit ORDER BY id ASC"
            )
    except sqlite3.Error as exc:
        print(f"FAIL: cannot read {path}: {exc}", file=sys.stderr)
        return 2

    prev_hash = GENESIS_PREV_HASH
    expected_id = 1
    count = 0
    hash_at_anchor_id = None

    counted = {1: 0, 2: 0}

    for raw in cur:
        values = dict(zip(FIELDS, raw[:7]))
        stored_prev, stored_hash = raw[7], raw[8]
        row_id = values["id"]
        version = raw[9] if versioned else None
        if versioned:
            values.update(
                {"v": raw[9], "host": raw[10], "status": raw[11],
                 "req_bytes": raw[12], "resp_bytes": raw[13]}
            )

        # An unknown version is a failure, never a pass. A row claiming a rule
        # this verifier does not implement cannot be checked, and "could not
        # check it" must not read the same as "checked it and it was fine".
        if version not in KNOWN_VERSIONS:
            return _broken(
                row_id,
                f"row declares payload version {version!r}, which this verifier "
                f"does not implement. It cannot be checked, so it is not "
                f"accepted. Use a verifier from the build that wrote it.",
                count,
            )

        # A deleted row leaves a hole in the sequence. AUTOINCREMENT never
        # reuses ids, so a hole is always evidence, never normal operation.
        if row_id != expected_id:
            return _broken(
                row_id,
                f"id sequence gap: expected id {expected_id}, found {row_id} "
                f"({row_id - expected_id} row(s) deleted or reordered)",
                count,
            )

        if stored_prev != prev_hash:
            return _broken(
                row_id,
                f"prev_hash mismatch\n  stored:     {stored_prev}\n"
                f"  chain says: {prev_hash}",
                count,
            )

        applied = 2 if version == 2 else 1
        recomputed = row_hash_v2(values, prev_hash) if applied == 2 else row_hash(values, prev_hash)
        if recomputed != stored_hash:
            return _broken(
                row_id,
                f"row_hash mismatch — row contents were altered\n"
                f"  stored:     {stored_hash}\n  recomputed: {recomputed}\n"
                f"  payload rule applied: v{applied}"
                + ("  (v NULL, so this row predates S8)" if version is None else "")
                + f"\n  row: tool={values['tool']!r} effect={values['effect']!r} "
                f"rule_id={values['rule_id']!r}",
                count,
            )
        counted[applied] += 1

        if anchor_id is not None and row_id == anchor_id:
            hash_at_anchor_id = stored_hash

        prev_hash = stored_hash
        expected_id += 1
        count += 1

    if expect_head is not None and prev_hash != expect_head.strip().lower():
        print(
            f"FAIL: head hash does not match the anchor. The log is internally "
            f"consistent but is not the log you anchored — rows were removed "
            f"from the end, or the chain was rewritten wholesale.\n"
            f"  anchor source: {anchor_source}\n"
            f"  anchored head: {expect_head.strip().lower()}\n"
            f"  actual head:   {prev_hash}\n"
            f"  rows present:  {count}",
            file=sys.stderr,
        )
        return 1

    if anchor_hash is not None and anchor_id:
        if anchor_id > count:
            print(
                f"FAIL: the log is shorter than its own anchor — rows were "
                f"removed from the end.\n"
                f"  anchor source: {anchor_source}\n"
                f"  anchor recorded {anchor_id} row(s) at shutdown; {count} present",
                file=sys.stderr,
            )
            return 1
        if hash_at_anchor_id != anchor_hash:
            print(
                f"FAIL: row {anchor_id} does not match the anchor — the log was "
                f"rewritten at or before the anchored point.\n"
                f"  anchor source: {anchor_source}\n"
                f"  anchored hash: {anchor_hash}\n"
                f"  actual hash:   {hash_at_anchor_id}",
                file=sys.stderr,
            )
            return 1

    if not quiet:
        print(f"OK: {count} row(s) verified, chain intact")
        if counted[1] and counted[2]:
            print(
                f"rules:  {counted[1]} row(s) under the v1 payload (written "
                f"before S8), {counted[2]} under v2. A mixed chain is normal "
                f"after an upgrade and is not evidence of anything."
            )
        print(f"db:     {path}")
        print(f"head:   {prev_hash}")
        print(f"anchor: {anchor_source}")
        if count == 0:
            print(
                "note: the log is empty. An empty chain is a valid chain — if you "
                "expected rows here, the database was replaced, not edited."
            )
        elif anchor_source == "none":
            print(
                "note: nothing anchored this head, so truncation of the newest "
                "rows would not be visible. Record the hash above and re-check "
                "with --expect-head."
            )
        elif anchor_hash is not None:
            appended = count - anchor_id
            print(
                f"anchor verified at row {anchor_id}"
                + (f", {appended} row(s) appended since" if appended > 0 else "")
            )
            print(
                "note: the anchor file lives beside the database and is not "
                "signed — it raises the effort of a silent truncation, it does "
                "not prevent one. A hash held outside this machine is worth more."
            )
    return 0


def _broken(row_id: int, detail: str, verified_before: int) -> int:
    print(
        f"FAIL: audit chain broken at row id {row_id}\n  {detail}\n"
        f"  {verified_before} row(s) verified before this point",
        file=sys.stderr,
    )
    return 1


# What --verdict prints, keyed by the exit code the checker actually reached.
#
# The marker exists because an exit code cannot distinguish "I checked and the
# chain is broken" from "I died before I could check". Both are 1: the first by
# `return 1` below, the second because that is what CPython exits with on an
# uncaught exception. A caller that reads the code alone must either treat a
# crash as tampering (a false alarm on the one screen whose job is honest
# tamper reporting) or treat tampering as a crash (silence when it matters).
#
# This line is printed only after verify() has RETURNED — so it cannot be
# produced by an import error, a syntax error, a missing module, a wrong
# interpreter, or an exception anywhere in the check. Its absence is therefore
# positive evidence that no verdict was reached, and callers are expected to
# treat "no marker" as "not checked" rather than as anything about the log.
VERDICT_PREFIX = "AEGIS-VERIFY-VERDICT:"
VERDICT_BY_CODE = {0: "intact", 1: "broken", 2: "unreadable"}


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify the Aegis audit hash chain.")
    ap.add_argument("db", nargs="?", default=None, help="path to audit.db")
    ap.add_argument("--expect-head", default=None, metavar="HASH",
                    help="externally anchored head row_hash; detects tail truncation")
    ap.add_argument("--quiet", action="store_true", help="print nothing on success")
    ap.add_argument("--verdict", action="store_true",
                    help="print a machine-readable verdict line as the last line "
                         "of stdout. Absent output means no verdict was reached.")
    ap.add_argument("--no-anchor", action="store_true",
                    help=f"ignore any {HEAD_FILE_NAME} beside the database and "
                         f"check the chain alone")
    args = ap.parse_args()
    path = Path(args.db).expanduser() if args.db else default_db_path()
    code = verify(path, args.expect_head, args.quiet, use_anchor=not args.no_anchor)
    if args.verdict:
        # Reached only because verify() returned. See VERDICT_PREFIX above.
        print(f"{VERDICT_PREFIX} {VERDICT_BY_CODE.get(code, 'unreadable')}")
    return code


if __name__ == "__main__":
    sys.exit(main())
