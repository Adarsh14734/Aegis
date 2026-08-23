"""Aegis S9 — C11: constrain the agent's whole process tree.

Every sprint since S1 has repeated the same gap. S1 gap #4: "Aegis mediates the
MCP channel; a bash tool bypasses it entirely." S1's own live session is the
evidence — three of the model's four attempts on a secret went through Bash and
Aegis blocked none of them. S8 repeated it for egress. THREAT-MODEL.md §7.6 has
said it since S0.

This module closes it by putting the agent inside an OS sandbox, so the rules
are enforced by the kernel on every process in the tree rather than by policy.py
on the frames that happen to cross one stdio pipe. A `cat` of a denied file
fails with EPERM. It is not asked about, and there is nothing to ask.

WHAT THIS DOES NOT DO: WRITE A SANDBOX

D2 is explicit — "wrap the vendor sandbox; do not rebuild it. Reimplementing
kernel isolation as a solo founder is a multi-month detour with a high chance of
producing something weaker." So this file contains no isolation logic at all. It
is a translator: policy.json in, a sandbox-runtime settings document out, plus
the plumbing to refuse when the sandbox cannot be established.

The sandbox is Anthropic's Sandbox Runtime (`srt`, `@anthropic-ai/sandbox-runtime`,
Apache-2.0), which is the implementation D2 names. It uses `sandbox-exec`
(Seatbelt) on macOS and `bubblewrap` on Linux, and routes network through its own
filtering proxies. See S9-REPORT.md §Evaluating ASRT for what was checked before
choosing it, and for the two things it does not give us.

ONE SOURCE OF TRUTH

The settings document is generated from policy.json and from nothing else, so a
path denied in policy is denied by the kernel. It is written next to the policy,
digested, and the digest goes in the audit log — a profile that does not match
the policy is a profile someone edited by hand, and the digest is how that
becomes visible.

FAIL CLOSED

Wrong OS, missing binary, unloadable policy, rejected profile: `establish()`
raises and `aegis run` refuses to launch. It never falls back to launching
unconfined. A silently-unsandboxed agent is the exact failure this control
exists to prevent, and it is worse than no sandbox at all because the operator
believes there is one.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

try:  # S7 import plumbing: package when installed, flat when run as a script
    from .audit import default_db_path
    from . import killswitch
except ImportError:  # pragma: no cover
    from audit import default_db_path
    import killswitch

# The sandbox runtime this wraps. Not a Python dependency and deliberately not
# vendored: it is a Node package with its own release cadence and its own
# security review, and pinning a copy inside a pip package would mean shipping a
# stale sandbox to people who think they have the current one.
RUNTIME_BIN = "srt"
RUNTIME_PACKAGE = "@anthropic-ai/sandbox-runtime"
RUNTIME_INSTALL_HINT = f"npm install -g {RUNTIME_PACKAGE}"

SUPPORTED_PLATFORMS = ("darwin", "linux")

PROFILE_NAME = "sandbox-profile.json"


class SandboxError(Exception):
    """The sandbox could not be established. Callers must refuse to launch."""


# ---------------------------------------------------------------------------
# policy.json -> sandbox profile
# ---------------------------------------------------------------------------


def _resolved(path) -> str:
    """An absolute, symlink-resolved path string.

    Every path in the profile goes through this. On macOS `/var` is a symlink to
    `/private/var`, so a profile that mixed the two would hand the kernel one
    spelling while the process used the other — and a rule that does not match
    is a rule that is not there. The first version of this file mixed them (the
    policy path was resolved, the data directory was not), which is how this
    helper came to exist.
    """
    return str(Path(path).expanduser().resolve())


def _deny_globs(pattern: str) -> list[str]:
    """Translate one policy `deny_paths` entry into sandbox glob(s).

    Two things have to be got right here, and getting either wrong produces a
    profile that looks correct and enforces nothing.

    **1. The pattern must be anchored at the filesystem root.** In this runtime a
    relative glob is rooted at the *process's working directory*, not at `/`.
    So `**/.env` denies `.env` only under wherever the agent happened to be
    started, and `cat ~/.ssh/id_rsa` from a workspace in /tmp sails straight
    through. Measured, not assumed — see S9-REPORT.md finding 1. Everything
    therefore becomes `/**/…`, which the runtime does treat as
    filesystem-wide.

    **2. It must cover what policy.py covers.** policy.py matches each pattern
    against *both* the full resolved path and the basename:

        fnmatch(str(p), pattern) or fnmatch(p.name, pattern)

    So a bare `.env` means "any file named .env, anywhere", and `/**/.env` is
    exactly that. If the kernel rule covered less than the MCP rule the two
    layers would disagree about what is denied, which is worse than either one
    alone because the weaker answer is the one that decides.

    A directory pattern like `**/.aws/**` covers the contents but not the
    directory itself, so the parent form is emitted too — denying the contents
    while allowing the listing is a distinction nobody wants to explain
    afterwards.
    """
    out: set[str] = set()
    if pattern.startswith("/"):
        out.add(pattern)
        if pattern.endswith("/**"):
            out.add(pattern[: -len("/**")])
        return sorted(out)

    core = pattern[3:] if pattern.startswith("**/") else pattern
    out.add(f"/**/{core}")
    if core.endswith("/**"):
        out.add(f"/**/{core[: -len('/**')]}")
    return sorted(out)


def profile_from_policy(policy, deny_all_network: bool = False) -> dict:
    """The sandbox settings document, derived from policy and nothing else.

    Filesystem, and why each entry is there:

      allowWrite   workspace_roots — the agent's job.
                   The Aegis data directory, because the MCP proxy runs *inside*
                   this sandbox (the client spawns it) and C3 requires it to
                   write audit.db before every forwarded call. A proxy that
                   cannot record is a proxy that denies everything, so a sandbox
                   that denied this would take C1..C10 down with it.
                   trash_dir, for the same reason (C9 stages copies there).

      denyWrite    policy.json and KILLSWITCH, explicitly, and denyWrite beats
                   allowWrite in this runtime. These two are the reason the data
                   directory being writable is survivable:
                     - A7: the agent cannot rewrite the policy that constrains
                       it. S1 argued this structurally ("outside every workspace
                       root"); here the kernel enforces it.
                     - C10: the agent cannot delete the kill switch. A stop
                       button an agent can remove is not a stop button.
                   Plus every deny_paths pattern.

      denyRead     every deny_paths pattern. This is the line the sprint exists
                   for: `cat ~/.ssh/id_rsa` fails with EPERM instead of
                   succeeding because it never crossed the MCP pipe.

    Read is allow-by-default in this runtime and stays that way: the agent has
    to be able to read its interpreter, its libraries and its own installation
    to run at all, and enumerating that is how a sandbox becomes a
    compatibility problem and then gets turned off (D4's reasoning, applied to
    something other than prompts).

    Network is allow-only and starts empty, so `curl` reaches nothing unless
    policy named it. `allowed_domains` is passed through so the proxy's own
    egress (S8, C4) still works from inside. What that buys and what it does
    not is in S9-REPORT.md §The network residual — briefly: the sandbox cannot
    tell the proxy's request from bash's, so bash can also reach an allowed
    domain. `deny_all_network=True` closes that at the cost of C4's egress.
    """
    allow_write = [_resolved(root) for root in policy.workspace_roots]
    allow_write.append(_resolved(default_db_path().parent))
    if policy.trash_dir is not None:
        allow_write.append(_resolved(policy.trash_dir))

    deny_read: list[str] = []
    deny_write: list[str] = [
        _resolved(policy.source_path),
        _resolved(killswitch.killswitch_path()),
    ]

    # S10: a folder the user set to Deny must be denied at the kernel too. The
    # MCP layer refuses it via folder_rules; without this the same path would
    # stay writable to a Bash tool inside the sandbox, and the two layers would
    # disagree about a rule the user set in the UI.
    #
    # `ask` deliberately does NOT deny here. An approval that a human grants has
    # to be able to proceed, and a kernel rule cannot be asked.
    for folder, effect in getattr(policy, "folder_rules", ()):
        if effect.value == "deny":
            deny_read.append(_resolved(folder))
            deny_read.append(_resolved(folder) + "/**")
            deny_write.append(_resolved(folder))
            deny_write.append(_resolved(folder) + "/**")
    for pattern in policy.deny_paths:
        deny_read.extend(_deny_globs(pattern))
        deny_write.extend(_deny_globs(pattern))

    domains = [] if deny_all_network else [str(d) for d in policy.allowed_domains]

    return {
        "filesystem": {
            "denyRead": sorted(set(deny_read)),
            "allowWrite": sorted(set(allow_write)),
            "denyWrite": sorted(set(deny_write)),
        },
        "network": {
            "allowedDomains": sorted(set(domains)),
            "deniedDomains": [],
        },
    }


def canonical(document: dict) -> str:
    """Byte-stable, for the digest. Same rule audit.py uses."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def digest_of(document: dict) -> str:
    return hashlib.sha256(canonical(document).encode("utf-8")).hexdigest()


def profile_path() -> Path:
    if override := os.environ.get("AEGIS_SANDBOX_PROFILE"):
        return Path(override).expanduser()
    return default_db_path().parent / PROFILE_NAME


def matches_policy(policy, path: Path | None = None, deny_all_network: bool = False):
    """(True, digest) if the profile on disk is the one this policy generates.

    A stale profile is the failure mode that matters: policy.json is edited,
    the kernel keeps enforcing yesterday's rules, and nothing says so. So the
    profile is regenerated from policy on every launch rather than reused, and
    this function exists so the suite can ask the question directly. Nothing in
    `aegis doctor` calls it — S9 changes no S7 onboarding — which means a stale
    profile on disk is not reported anywhere. See S9-REPORT.md known gaps.
    """
    path = path or profile_path()
    wanted = profile_from_policy(policy, deny_all_network)
    if not path.exists():
        return False, digest_of(wanted)
    try:
        found = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False, digest_of(wanted)
    return found == wanted, digest_of(wanted)


# ---------------------------------------------------------------------------
# can this machine sandbox at all?
# ---------------------------------------------------------------------------


def find_runtime() -> str | None:
    if override := os.environ.get("AEGIS_SANDBOX_RUNTIME"):
        return override if Path(override).exists() else None
    return shutil.which(RUNTIME_BIN)


def preflight() -> list[str]:
    """Every reason this machine cannot establish a sandbox. Empty means it can.

    All of them, not the first: an operator who has to fix three things wants to
    be told three things once.
    """
    problems: list[str] = []

    if sys.platform not in SUPPORTED_PLATFORMS:
        problems.append(
            f"platform {sys.platform!r} is not supported. The sandbox runtime "
            f"covers macOS (Seatbelt) and Linux (bubblewrap); on anything else "
            f"Aegis has no kernel-level boundary to offer and will not pretend "
            f"otherwise."
        )

    if find_runtime() is None:
        problems.append(
            f"the sandbox runtime {RUNTIME_BIN!r} is not on PATH. Aegis wraps "
            f"{RUNTIME_PACKAGE} rather than implementing kernel isolation "
            f"itself (THREAT-MODEL.md D2). Install it with:\n"
            f"    {RUNTIME_INSTALL_HINT}\n"
            f"or point AEGIS_SANDBOX_RUNTIME at the binary."
        )

    if sys.platform == "darwin" and not Path("/usr/bin/sandbox-exec").exists():
        problems.append(
            "/usr/bin/sandbox-exec is missing, so Seatbelt cannot be applied."
        )
    if sys.platform == "linux" and shutil.which("bwrap") is None:
        problems.append(
            "bubblewrap ('bwrap') is not on PATH, so the Linux sandbox cannot "
            "be applied. Install it with your package manager."
        )
    return problems


# ---------------------------------------------------------------------------
# establishing it
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Sandbox:
    runtime: str
    profile: Path
    digest: str
    document: dict
    platform: str

    def wrap(self, argv: list[str]) -> list[str]:
        """The argv that runs `argv` inside this sandbox."""
        return [self.runtime, "-s", str(self.profile), *argv]

    def summary(self) -> str:
        fs = self.document["filesystem"]
        net = self.document["network"]["allowedDomains"]
        return (
            f"sandbox established via {Path(self.runtime).name} on "
            f"{self.platform}; profile {self.digest[:16]}; "
            f"{len(fs['allowWrite'])} writable root(s), "
            f"{len(fs['denyRead'])} read-denied pattern(s), "
            f"{len(net)} domain(s) reachable"
        )


def write_profile(document: dict, path: Path | None = None) -> Path:
    """Write the profile at 0600, atomically.

    Same mode as the policy and the audit log: this file decides what the
    kernel enforces, so a profile anyone can edit is a sandbox anyone can widen.
    """
    path = path or profile_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp{os.getpid()}")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, (json.dumps(document, indent=2) + "\n").encode("utf-8"))
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
        raise SandboxError(f"could not write the sandbox profile to {path}: {exc}") from exc
    return path


def verify_profile_accepted(runtime: str, path: Path) -> None:
    """Prove the runtime accepts this profile, before an agent depends on it.

    A profile the runtime rejects means it refuses to run — which is safe — but
    discovering that at agent-launch time turns a configuration error into a
    confusing crash. Running a trivial command through it first is cheap and
    turns the same error into a sentence. It is also the only way to know the
    sandbox *works* rather than that its inputs looked plausible; every other
    check in this file reads a file.
    """
    try:
        done = subprocess.run(
            [runtime, "-s", str(path), "-c", "exit 0"],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SandboxError(
            f"the sandbox runtime could not be executed: {type(exc).__name__}: {exc}"
        ) from None
    if done.returncode != 0:
        detail = (done.stderr or done.stdout or "").strip().splitlines()
        raise SandboxError(
            "the sandbox runtime rejected the generated profile, so nothing was "
            "launched:\n    " + "\n    ".join(detail[-6:] or ["(no output)"])
        )


def establish(policy, deny_all_network: bool = False) -> Sandbox:
    """Generate, write and prove the profile. Raises SandboxError; never falls back."""
    problems = preflight()
    if problems:
        raise SandboxError(
            "cannot establish a sandbox on this machine:\n"
            + "\n".join(f"  - {p}" for p in problems)
        )

    runtime = find_runtime()
    document = profile_from_policy(policy, deny_all_network)
    path = write_profile(document)
    verify_profile_accepted(runtime, path)
    return Sandbox(
        runtime=runtime,
        profile=path,
        digest=digest_of(document),
        document=document,
        platform=sys.platform,
    )
