"""Aegis S5 soft delete — control C9.

Before a destructive tool call is forwarded, every path it names is copied into
the trash directory. If the copy fails, the call is denied: an unrecoverable
destructive action is worse than a blocked one.

This is T1 insurance — THREAT-MODEL.md's "confused agent" that globs too widely
and deletes 800 files. It is not a backup system and not a versioned store.
Retention and expiry are deliberately absent: the trash grows until a human
clears it, because a control that quietly discards the thing you need is a
control that fails on the one day it matters.

What it does NOT cover, stated plainly:

  - Deletion through Bash, which never crosses this proxy (S1 gap #4). The real
    MCP filesystem server exposes no delete tool at all, so on that server this
    control has nothing to protect — see S1-REPORT.md's structural limitation.
  - In-place truncation or overwrite by a tool not marked `"destructive": true`.
  - Anything the server does beyond the paths named in the arguments.
"""

import json
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

MANIFEST_NAME = "manifest.json"


class TrashError(Exception):
    """A path could not be preserved. The caller must deny the call."""


@dataclass
class Snapshot:
    snapshot_id: str
    root: Path
    saved: list = field(default_factory=list)    # (original, stored)
    missing: list = field(default_factory=list)  # nothing there to preserve

    def summary(self) -> str:
        parts = [f"{len(self.saved)} path(s) copied to trash as {self.snapshot_id}"]
        if self.missing:
            parts.append(f"{len(self.missing)} did not exist")
        return "; ".join(parts)


def _relative_inside(path: Path) -> Path:
    """/Users/x/notes.txt -> Users/x/notes.txt

    Keeping the full path structure under the snapshot makes restore
    unambiguous and stops two files with the same basename colliding.
    """
    return Path(*Path(path).resolve().parts[1:])


def stage(paths, trash_dir, tool: str = "") -> Snapshot:
    """Copy every path into a fresh timestamped snapshot. Raises TrashError.

    A path that does not exist is recorded as missing rather than failing the
    call: you cannot lose what was not there, and denying a delete of an
    already-absent file would be a confusing false positive. A path that exists
    but cannot be copied — permissions, disk full, a vanishing race — is a hard
    failure, because that is precisely the case where forwarding the call would
    destroy something unrecoverably.
    """
    trash_dir = Path(trash_dir).expanduser()
    snapshot_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}-{int(time.time() * 1000) % 1000:03d}"
    root = trash_dir / snapshot_id
    snap = Snapshot(snapshot_id, root)

    try:
        root.mkdir(parents=True, exist_ok=False)
        os.chmod(trash_dir, 0o700)
    except OSError as exc:
        raise TrashError(f"cannot create trash snapshot at {root}: {exc}") from None

    for raw in paths:
        src = Path(raw)
        if not src.exists() and not src.is_symlink():
            snap.missing.append(str(src))
            continue
        dest = root / "files" / _relative_inside(src)
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir() and not src.is_symlink():
                shutil.copytree(src, dest, symlinks=True, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dest, follow_symlinks=False)
        except (OSError, shutil.Error) as exc:
            raise TrashError(
                f"could not preserve {src} before a destructive call: {exc}"
            ) from None
        snap.saved.append((str(src), str(dest)))

    manifest = {
        "snapshot_id": snapshot_id,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "created_unix": round(time.time(), 3),
        "tool": tool,
        "saved": [{"original": o, "stored": s} for o, s in snap.saved],
        "missing": snap.missing,
    }
    try:
        (root / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2))
    except OSError as exc:
        raise TrashError(f"could not write the trash manifest: {exc}") from None
    return snap


# ---- aegis-restore -------------------------------------------------------


def snapshots(trash_dir) -> list:
    out = []
    trash_dir = Path(trash_dir).expanduser()
    if not trash_dir.is_dir():
        return out
    for child in sorted(trash_dir.iterdir()):
        manifest = child / MANIFEST_NAME
        if manifest.is_file():
            try:
                out.append(json.loads(manifest.read_text()))
            except (OSError, json.JSONDecodeError):
                out.append({"snapshot_id": child.name, "saved": [], "missing": [],
                            "tool": "?", "created_at": "unreadable manifest"})
    return out


def restore(trash_dir, snapshot_id: str, force: bool = False) -> tuple[int, list]:
    """Copy a snapshot's files back where they came from. Returns (restored,
    skipped). Never overwrites without --force: the whole point is not
    destroying things by surprise, and that applies to the recovery path too."""
    for manifest in snapshots(trash_dir):
        if manifest["snapshot_id"] == snapshot_id:
            break
    else:
        raise TrashError(f"no snapshot {snapshot_id!r} in {trash_dir}")

    restored, skipped = 0, []
    for entry in manifest["saved"]:
        src, dest = Path(entry["stored"]), Path(entry["original"])
        if not src.exists():
            skipped.append(f"{dest} (missing from trash)")
            continue
        if dest.exists() and not force:
            skipped.append(f"{dest} (already exists; --force to overwrite)")
            continue
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, dest, symlinks=True, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dest, follow_symlinks=False)
            restored += 1
        except (OSError, shutil.Error) as exc:
            skipped.append(f"{dest} ({exc})")
    return restored, skipped


def _trash_dir_from_policy() -> Path | None:
    """Read trash_dir out of policy.json without importing the policy engine —
    the CLI must work even if the policy is currently unloadable."""
    if override := os.environ.get("AEGIS_TRASH_DIR"):
        return Path(override).expanduser()
    if override := os.environ.get("AEGIS_POLICY"):
        policy_path = Path(override).expanduser()
    elif sys.platform == "darwin":
        policy_path = Path.home() / "Library" / "Application Support" / "Aegis" / "policy.json"
    else:
        base = os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")
        policy_path = Path(base) / "aegis" / "policy.json"
    try:
        value = json.loads(policy_path.read_text()).get("trash_dir")
    except (OSError, json.JSONDecodeError):
        return None
    return Path(value).expanduser() if value else None


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    usage = (
        "usage: aegis-restore list\n"
        "       aegis-restore restore <snapshot-id> [--force]\n"
        "\n"
        "Snapshots are written by Aegis before a destructive tool call.\n"
        "Nothing is ever deleted from the trash automatically.\n"
    )
    trash_dir = _trash_dir_from_policy()
    if trash_dir is None:
        print("aegis-restore: no trash_dir configured in policy.json "
              "(or set AEGIS_TRASH_DIR)", file=sys.stderr)
        return 1

    if not argv or argv[0] in ("-h", "--help"):
        print(usage)
        return 0 if argv else 64

    if argv[0] == "list":
        found = snapshots(trash_dir)
        if not found:
            print(f"no snapshots in {trash_dir}")
            return 0
        print(f"snapshots in {trash_dir}:\n")
        for m in found:
            print(f"  {m['snapshot_id']}   {m.get('created_at', '?')}   "
                  f"tool={m.get('tool') or '?'}   {len(m.get('saved', []))} file(s)")
            for entry in m.get("saved", [])[:4]:
                print(f"      {entry['original']}")
            if len(m.get("saved", [])) > 4:
                print(f"      ...and {len(m['saved']) - 4} more")
        print("\nrestore one with: aegis-restore restore <snapshot-id>")
        return 0

    if argv[0] == "restore" and len(argv) >= 2:
        try:
            restored, skipped = restore(trash_dir, argv[1], "--force" in argv)
        except TrashError as exc:
            print(f"aegis-restore: {exc}", file=sys.stderr)
            return 1
        print(f"restored {restored} file(s)")
        for item in skipped:
            print(f"  skipped: {item}")
        return 0 if restored or not skipped else 1

    print(usage, file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main())
