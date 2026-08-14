"""Aegis S2 tamper-evident audit store — control C3.

Every policy decision is appended to a local SQLite database as a hash-chained
row. Each row commits to its own contents *and* to the hash of the row before
it, so any edit, deletion, or reordering breaks the chain from that point on.

    row_hash = sha256(canonical_json(payload) + prev_hash)

This is *tamper-evident*, not tamper-proof. THREAT-MODEL.md §7.2 is explicit:
anyone with root or with write access to this file can rewrite the database.
What they cannot do is rewrite it without the breakage being detectable by
`aegis/verify.py`, which recomputes the chain with no help from this module.

Append-only is a property of the code, not of SQLite: no UPDATE or DELETE
statement appears anywhere in this file. Enforcement triggers were considered
and rejected — anyone able to run UPDATE can also run DROP TRIGGER, so they
would add ceremony without adding a guarantee. Detection is the guarantee.

Fail-closed (S0 decision #3): every failure path here raises AuditError. The
caller must treat an unwritable audit log as a denied call. An action nobody
can reconstruct afterwards is worse than an action that did not happen.
"""

import hashlib
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

GENESIS_PREV_HASH = "0" * 64

# Kept verbatim in aegis/verify.py's docstring-level expectations. If this
# changes, the verifier must change with it, and old databases stop verifying.
SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL    NOT NULL,
    tool      TEXT    NOT NULL,
    effect    TEXT    NOT NULL,
    rule_id   TEXT    NOT NULL,
    reason    TEXT    NOT NULL,
    paths     TEXT    NOT NULL,
    prev_hash TEXT    NOT NULL,
    row_hash  TEXT    NOT NULL
)
"""


class AuditError(Exception):
    """Any failure to durably record a decision. Callers must fail closed."""


def default_db_path() -> Path:
    """Same protected application-data directory as the policy file (S0 #2)."""
    if override := os.environ.get("AEGIS_AUDIT_DB"):
        return Path(override).expanduser()
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / "Aegis"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "aegis"
    return base / "audit.db"


def canonical_json(obj) -> str:
    """Byte-stable JSON. Key order and spacing must never vary: the hash is
    taken over this exact string, and the verifier reproduces it from the
    stored column values alone."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def compute_row_hash(
    row_id: int,
    ts: float,
    tool: str,
    effect: str,
    rule_id: str,
    reason: str,
    paths: str,
    prev_hash: str,
) -> str:
    """The chain link. `paths` is the stored TEXT column, not the original
    list — the verifier only ever sees columns, so the hash must be a function
    of columns."""
    payload = canonical_json(
        {
            "id": row_id,
            "ts": ts,
            "tool": tool,
            "effect": effect,
            "rule_id": rule_id,
            "reason": reason,
            "paths": paths,
        }
    )
    return hashlib.sha256((payload + prev_hash).encode("utf-8")).hexdigest()


class AuditStore:
    """Append-only hash-chained decision log. One process, one connection."""

    def __init__(self, conn: sqlite3.Connection, path: Path):
        self.conn = conn
        self.path = path

    # ---- lifecycle -------------------------------------------------------

    @classmethod
    def open(cls, path: Path | None = None) -> "AuditStore":
        path = Path(path) if path is not None else default_db_path()
        try:
            created = cls._create_file_if_missing(path)
            cls._assert_not_group_or_world_writable(path)
            conn = sqlite3.connect(
                str(path),
                timeout=10.0,
                isolation_level=None,  # explicit BEGIN IMMEDIATE; no implicit txns
            )
            conn.execute("PRAGMA journal_mode=WAL")
            # An audit row must be on disk before the call it describes is
            # forwarded. WAL's default synchronous=NORMAL can lose the most
            # recent commits on power loss; for a log of security decisions
            # that is the wrong trade.
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute(SCHEMA)
        except AuditError:
            raise
        except (sqlite3.Error, OSError) as exc:
            raise AuditError(f"cannot open audit store at {path}: {exc}") from exc

        store = cls(conn, path)
        store._tighten_sidecars()
        if created:
            store._log_created()
        return store

    @staticmethod
    def _create_file_if_missing(path: Path) -> bool:
        """Create the db at 0600 ourselves rather than letting SQLite pick a
        mode from the umask."""
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            return False
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)  # O_CREAT mode is masked by umask; this is not
        return True

    @staticmethod
    def _assert_not_group_or_world_writable(path: Path) -> None:
        """A6: an audit log anyone can write is an audit log nobody can cite.
        Same bar as the policy file in policy.py."""
        mode = path.stat().st_mode
        if mode & 0o022:
            raise AuditError(
                f"audit db {path} is group/world writable (mode {oct(mode & 0o777)})"
            )

    def _tighten_sidecars(self) -> None:
        """WAL puts committed rows in -wal until checkpoint. Those bytes are as
        sensitive as the db itself."""
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            try:
                if sidecar.exists():
                    os.chmod(sidecar, 0o600)
            except OSError:
                pass  # best effort; the db file's own mode is the real gate

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    # ---- append ----------------------------------------------------------

    def head(self) -> tuple[int, str]:
        """(last id, last row_hash). (0, GENESIS_PREV_HASH) on an empty log."""
        row = self.conn.execute(
            "SELECT id, row_hash FROM audit ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return 0, GENESIS_PREV_HASH
        return int(row[0]), str(row[1])

    def record(
        self,
        *,
        tool: str,
        effect: str,
        rule_id: str,
        reason: str,
        paths,
        ts: float | None = None,
    ) -> tuple[int, str]:
        """Append one decision. Returns (row id, row_hash).

        Raises AuditError on any failure — the caller denies the call.
        """
        ts = round(time.time() if ts is None else ts, 6)
        paths_text = canonical_json([str(p) for p in (paths or ())])
        try:
            # IMMEDIATE takes the write lock before we read the head, so two
            # proxies sharing one db cannot compute the same next id or chain
            # onto the same prev_hash.
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                prev_id, prev_hash = self.head()
                row_id = prev_id + 1
                digest = compute_row_hash(
                    row_id, ts, str(tool), str(effect), str(rule_id), str(reason),
                    paths_text, prev_hash,
                )
                self.conn.execute(
                    "INSERT INTO audit "
                    "(id, ts, tool, effect, rule_id, reason, paths, prev_hash, row_hash) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (row_id, ts, str(tool), str(effect), str(rule_id), str(reason),
                     paths_text, prev_hash, digest),
                )
                self.conn.execute("COMMIT")
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
        except sqlite3.Error as exc:
            raise AuditError(f"audit write failed: {type(exc).__name__}: {exc}") from exc
        return row_id, digest

    def _log_created(self) -> None:
        print(
            f"[aegis] created audit store {self.path} (mode 0600)",
            file=sys.stderr,
            flush=True,
        )
