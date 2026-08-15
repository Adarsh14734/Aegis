#!/usr/bin/env python3
"""Aegis audit chain verifier — standalone, offline, stdlib only.

    python3 aegis/verify.py [path/to/audit.db] [--expect-head HASH] [--quiet]
                            [--no-anchor]

    exit 0  chain intact
    exit 1  chain broken (prints the first bad row and what mismatched)
    exit 2  cannot read the database at all

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

GENESIS_PREV_HASH = "0" * 64
FIELDS = ("id", "ts", "tool", "effect", "rule_id", "reason", "paths")

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
    payload = json.dumps(
        {k: values[k] for k in FIELDS}, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256((payload + prev_hash).encode("utf-8")).hexdigest()


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

    for raw in cur:
        values = dict(zip(FIELDS, raw[:7]))
        stored_prev, stored_hash = raw[7], raw[8]
        row_id = values["id"]

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

        recomputed = row_hash(values, prev_hash)
        if recomputed != stored_hash:
            return _broken(
                row_id,
                f"row_hash mismatch — row contents were altered\n"
                f"  stored:     {stored_hash}\n  recomputed: {recomputed}\n"
                f"  row: tool={values['tool']!r} effect={values['effect']!r} "
                f"rule_id={values['rule_id']!r}",
                count,
            )

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


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify the Aegis audit hash chain.")
    ap.add_argument("db", nargs="?", default=None, help="path to audit.db")
    ap.add_argument("--expect-head", default=None, metavar="HASH",
                    help="externally anchored head row_hash; detects tail truncation")
    ap.add_argument("--quiet", action="store_true", help="print nothing on success")
    ap.add_argument("--no-anchor", action="store_true",
                    help=f"ignore any {HEAD_FILE_NAME} beside the database and "
                         f"check the chain alone")
    args = ap.parse_args()
    path = Path(args.db).expanduser() if args.db else default_db_path()
    return verify(path, args.expect_head, args.quiet, use_anchor=not args.no_anchor)


if __name__ == "__main__":
    sys.exit(main())
