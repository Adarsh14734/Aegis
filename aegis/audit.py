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

THE PAYLOAD VERSION (S8)

S8 needed four more fields in the row — the destination host, the HTTP status,
and the byte counts of a request Aegis performed itself. Adding a field to the
hashed payload changes every hash, which would have silently invalidated every
audit database in existence. That is the same observable event as an attack on
the log, so it is not an acceptable upgrade.

Instead the payload is versioned, and the version is stored per row:

    v NULL or 1  ->  sha256(canonical_json({id,ts,tool,effect,rule_id,reason,
                                            paths}) + prev_hash)
    v = 2        ->  sha256(canonical_json({v,id,ts,tool,effect,rule_id,reason,
                                            paths,host,status,req_bytes,
                                            resp_bytes}) + prev_hash)

Old rows keep hashing under the rule they were written with, forever. New rows
use v2. A database may hold both, and the chain still links across the boundary
because `prev_hash` is version-independent — it is just the previous row's
stored hash, whatever rule produced it.

`v` is NULL rather than 1 on old rows because that is what ADD COLUMN leaves
behind, and back-filling it would mean rewriting rows: the one thing this
module must never do.
"""

import hashlib
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

GENESIS_PREV_HASH = "0" * 64

# S3b fix 2: bounded retry for a database locked by another booting proxy.
# Bounded, because "wait forever for the audit log" is just fail-open wearing
# a hat — after this many attempts the proxy refuses to start.
OPEN_MAX_ATTEMPTS = 8
OPEN_RETRY_INITIAL_DELAY = 0.05
OPEN_RETRY_MAX_DELAY = 1.0
OPEN_BUSY_TIMEOUT = 10.0

# S3b fix 3: the head anchor written next to the database on clean shutdown.
HEAD_FILE_NAME = "aegis-head.txt"

# S8: the payload version this build writes. Every row records the rule its
# hash was computed under, so a schema change can never invalidate a chain
# written before it. See §The payload version below.
PAYLOAD_VERSION = 2

# Kept verbatim in aegis/verify.py's docstring-level expectations. If this
# changes, the verifier must change with it, and old databases stop verifying.
#
# S8 adds five columns. They are added by ALTER TABLE on an existing database,
# which does not rewrite a single stored byte of an existing row — old rows
# simply read NULL for all five, and NULL in `v` is what marks them as hashing
# under the v1 rule.
SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL    NOT NULL,
    tool       TEXT    NOT NULL,
    effect     TEXT    NOT NULL,
    rule_id    TEXT    NOT NULL,
    reason     TEXT    NOT NULL,
    paths      TEXT    NOT NULL,
    prev_hash  TEXT    NOT NULL,
    row_hash   TEXT    NOT NULL,
    v          INTEGER,
    host       TEXT,
    status     INTEGER,
    req_bytes  INTEGER,
    resp_bytes INTEGER
)
"""

# The five S8 columns, in the order the v2 payload names them. Existing
# databases are brought up to this shape by ADD COLUMN, never by a rebuild.
S8_COLUMNS = (
    ("v", "INTEGER"),
    ("host", "TEXT"),
    ("status", "INTEGER"),
    ("req_bytes", "INTEGER"),
    ("resp_bytes", "INTEGER"),
)


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
    """The v1 chain link — every row written before S8.

    Kept byte-identical and permanently. This is not dead code and must never
    be "tidied up" into the v2 function: every audit database in existence
    before S8 has rows whose stored hash is this function's output, and the
    moment this changes those chains stop verifying. `paths` is the stored TEXT
    column, not the original list — the verifier only ever sees columns, so the
    hash must be a function of columns.
    """
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


def compute_row_hash_v2(
    row_id: int,
    ts: float,
    tool: str,
    effect: str,
    rule_id: str,
    reason: str,
    paths: str,
    host,
    status,
    req_bytes,
    resp_bytes,
    prev_hash: str,
) -> str:
    """The v2 chain link — every row written by S8 onward.

    Two things make this safe to introduce next to v1:

      - **The version is inside the payload.** A row cannot be reinterpreted
        under the other rule without changing its hash, so "which rule applies"
        is not a decision an attacker can flip for free. They would have to
        recompute the hash, which breaks the chain forward exactly as any other
        edit does.
      - **The four new fields are always present**, carrying JSON null when the
        decision was not an outbound request. A field that appears only
        sometimes would make two different payloads for the same row shape, and
        the verifier would have to guess which one was used.
    """
    payload = canonical_json(
        {
            "v": 2,
            "id": row_id,
            "ts": ts,
            "tool": tool,
            "effect": effect,
            "rule_id": rule_id,
            "reason": reason,
            "paths": paths,
            "host": host,
            "status": status,
            "req_bytes": req_bytes,
            "resp_bytes": resp_bytes,
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
        """Open the store, retrying briefly if another proxy is booting.

        S3b fix 2. `PRAGMA journal_mode=WAL` takes a brief exclusive lock, and
        SQLite returns SQLITE_BUSY for it immediately rather than honouring
        busy_timeout — so with several proxies starting at once (one per MCP
        server, all sharing one database) a proxy could fail to boot. It failed
        closed, which is correct, but a control that refuses to start under
        ordinary concurrency is a control that gets removed.

        Two changes: the pragma is only issued when the database is not
        already in WAL, which removes it from the steady-state path entirely;
        and the whole open is retried with backoff when the database is locked.
        """
        path = Path(path) if path is not None else default_db_path()
        last: Exception | None = None
        delay = OPEN_RETRY_INITIAL_DELAY

        for attempt in range(OPEN_MAX_ATTEMPTS):
            try:
                return cls._open_once(path)
            except AuditError:
                raise
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc) and "busy" not in str(exc).lower():
                    raise AuditError(f"cannot open audit store at {path}: {exc}") from exc
                last = exc
                if attempt < OPEN_MAX_ATTEMPTS - 1:
                    time.sleep(delay)
                    delay = min(delay * 2, OPEN_RETRY_MAX_DELAY)
            except (sqlite3.Error, OSError) as exc:
                raise AuditError(f"cannot open audit store at {path}: {exc}") from exc

        raise AuditError(
            f"cannot open audit store at {path} after {OPEN_MAX_ATTEMPTS} attempts: {last}"
        )

    @classmethod
    def _open_once(cls, path: Path) -> "AuditStore":
        created = cls._create_file_if_missing(path)
        cls._assert_not_group_or_world_writable(path)
        conn = sqlite3.connect(
            str(path),
            timeout=OPEN_BUSY_TIMEOUT,
            isolation_level=None,  # explicit BEGIN IMMEDIATE; no implicit txns
        )
        try:
            # Reading the mode takes no write lock. Setting it does, and on an
            # existing WAL database setting it is a no-op worth avoiding.
            mode = conn.execute("PRAGMA journal_mode").fetchone()
            if (mode[0] if mode else "").lower() != "wal":
                conn.execute("PRAGMA journal_mode=WAL")
            # An audit row must be on disk before the call it describes is
            # forwarded. WAL's default synchronous=NORMAL can lose the most
            # recent commits on power loss; for a log of security decisions
            # that is the wrong trade.
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute(SCHEMA)
            cls._migrate(conn)
        except BaseException:
            conn.close()  # do not leak the handle into the retry loop
            raise

        store = cls(conn, path)
        store._tighten_sidecars()
        if created:
            store._log_created()
        return store

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Bring a pre-S8 database up to the current column set.

        `ALTER TABLE ... ADD COLUMN` is the only statement used, and it is the
        only one that could be: it appends a column to the table definition
        without touching a single stored row. Every existing row keeps its
        bytes, keeps its `row_hash`, and reads NULL in the new columns — which
        is exactly what marks it as a v1 row to the verifier.

        Anything that rewrote rows here would be indistinguishable from an
        attack on the log, and would break every anchor ever recorded. There is
        no code path in Aegis that rewrites an audit row, and this must not
        become the first one.
        """
        existing = {row[1] for row in conn.execute("PRAGMA table_info(audit)")}
        for name, kind in S8_COLUMNS:
            if name not in existing:
                conn.execute(f"ALTER TABLE audit ADD COLUMN {name} {kind}")

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

    def head_file_path(self) -> Path:
        return self.path.parent / HEAD_FILE_NAME

    def write_head_anchor(self) -> tuple[int, str] | None:
        """S3b fix 3. Record the head id and hash next to the database on clean
        shutdown, so `verify.py` has something to compare against without the
        operator having copied a hash by hand.

        THIS IS NOT TRUNCATION DETECTION. Anyone who can rewrite the database
        can rewrite this file — it sits in the same directory, owned by the
        same user, and nothing signs it. It converts a silent truncation into
        one that requires the attacker to update two files instead of one, and
        it catches the accidental cases: a half-copied database, a restored
        backup, a rolled-back filesystem. Real truncation detection needs the
        head hash somewhere Aegis cannot write. See S3b-REPORT.md.

        Returns the anchored (id, hash), or None if it could not be written —
        a failure here is logged by the caller and is NOT fail-closed, because
        the session is already over and the rows are already committed.
        """
        # Read the head under the write lock. Without it, another proxy
        # sharing this database can commit a row between the read and the
        # write, and the anchor lands describing a log that already moved on.
        # (verify.py tolerates a stale anchor by design, but a needlessly
        # stale one is still a worse record.)
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                head_id, head_hash = self.head()
            finally:
                self.conn.execute("COMMIT")
        except sqlite3.Error:
            try:
                head_id, head_hash = self.head()  # unlocked fallback
            except sqlite3.Error:
                return None

        target = self.head_file_path()
        tmp = target.with_name(target.name + f".tmp{os.getpid()}")
        body = (
            "# Aegis audit head anchor. Written on clean shutdown.\n"
            "# NOT tamper-proof: an attacker who can rewrite the database can\n"
            "# rewrite this file too. Keep a copy somewhere Aegis cannot write.\n"
            f"db={self.path.name}\n"
            f"head_id={head_id}\n"
            f"head_hash={head_hash}\n"
            f"written_at={round(time.time(), 3)}\n"
        )
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, body.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.chmod(tmp, 0o600)
            os.replace(tmp, target)  # atomic: never a half-written anchor
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return None
        return head_id, head_hash

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
        host: str | None = None,
        status: int | None = None,
        req_bytes: int | None = None,
        resp_bytes: int | None = None,
    ) -> tuple[int, str]:
        """Append one decision. Returns (row id, row_hash).

        S8: `host`, `status`, `req_bytes` and `resp_bytes` describe an outbound
        request Aegis performed itself (aegis/fetch.py). They are None for
        every other decision, which is most of them — a file read has no
        destination and no status. `host` is the host actually connected to
        after any redirects, not the one the model asked for.

        Every row written here is v2. A v1 row is, by definition, a row written
        before S8 existed.

        Raises AuditError on any failure — the caller denies the call.
        """
        ts = round(time.time() if ts is None else ts, 6)
        paths_text = canonical_json([str(p) for p in (paths or ())])
        host = str(host) if host is not None else None
        status = int(status) if status is not None else None
        req_bytes = int(req_bytes) if req_bytes is not None else None
        resp_bytes = int(resp_bytes) if resp_bytes is not None else None
        try:
            # IMMEDIATE takes the write lock before we read the head, so two
            # proxies sharing one db cannot compute the same next id or chain
            # onto the same prev_hash.
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                prev_id, prev_hash = self.head()
                row_id = prev_id + 1
                digest = compute_row_hash_v2(
                    row_id, ts, str(tool), str(effect), str(rule_id), str(reason),
                    paths_text, host, status, req_bytes, resp_bytes, prev_hash,
                )
                self.conn.execute(
                    "INSERT INTO audit "
                    "(id, ts, tool, effect, rule_id, reason, paths, prev_hash, "
                    " row_hash, v, host, status, req_bytes, resp_bytes) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (row_id, ts, str(tool), str(effect), str(rule_id), str(reason),
                     paths_text, prev_hash, digest, PAYLOAD_VERSION,
                     host, status, req_bytes, resp_bytes),
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
