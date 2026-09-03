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


# The temp root the agent's process tree actually writes to.
#
# Every agent runtime makes a scratch directory before it does anything else, so
# a profile with no writable temp cannot launch an agent at all: Claude Code
# dies with `EPERM: operation not permitted, mkdir '/tmp/claude-501'` before it
# prints its first line. A sandbox that looks like a broken install is a sandbox
# that gets switched off, which costs C1..C11 rather than saving anything.
#
# This is /tmp and deliberately NOT $TMPDIR, which is the counter-intuitive
# part. macOS's per-user private temp is the narrower grant and would be the one
# to prefer -- except that the sandbox runtime REWRITES TMPDIR to /tmp/claude
# for everything it launches, so the scratch path an agent derives INSIDE the
# sandbox is under /tmp whatever $TMPDIR said outside it. Granting $TMPDIR
# fixes nothing and widens the boundary for free: it would hand the agent the
# user's entire per-user temp, which is exactly where tempfile.mkdtemp() puts
# the directories S9's own suite uses to prove a write outside workspace_roots
# fails. Measured inside `srt`, not assumed.
#
# A narrower glob (`/private/tmp/claude*`) was tried and does not hold: this
# runtime matches such a directory itself but still refuses the creation of
# children under it, so the agent cannot make its own subdirectories.
#
# /tmp is world-writable on macOS already (drwxrwxrwt), so this grants the tree
# nothing it could not reach unsandboxed, and it stays bounded the way the data
# directory does: denyWrite beats allowWrite, and every deny_paths pattern is
# anchored at `/**/...`, so a secret spelled `.env` is still denied at /tmp/.env.
SYSTEM_TEMP_ROOT = "/tmp"


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
                   SYSTEM_TEMP_ROOT, because an agent that cannot create
                   its scratch directory never starts.
                   sandbox_state_paths, so a wrapped client can write its own
                   state — without it the client starts and then fails every
                   request. See THE CLIENT'S STATE below.

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

    THE CLIENT'S STATE (S9f)

    A client launched through the S9c wrapper runs inside this profile, and
    until S9f the profile granted it nowhere to write but the workspace, the
    Aegis data directory and /tmp. Its own state directory was not among them,
    so on macOS Claude Code could not take its OAuth refresh lock, could not
    write a transcript, and failed every request with a 401 that looked like an
    expired login. Measured, with the paths taken from kernel denials rather
    than guessed — evidence/S9f-client-state.txt.

    `sandbox_state_paths` grants those directories and `sandbox_state_protect`
    carves the dangerous files back out of the grant. The residual is real and
    is stated in THREAT-MODEL.md §7.11: a granted state directory is writable
    by everything in the tree, including a Bash tool, not only by the client.

    THE TERMINAL (S9e)

    `allowPty` decides whether the runtime emits its pty rules: pseudo-tty
    access, plus ioctl and read/write on the terminal devices themselves,
    /dev/ptmx and /dev/ttys*. Those rules are the runtime's, and are described
    here rather than reproduced — this file states intent in a settings
    document and never spells a sandbox profile, which is the D2 property
    tests/s9.py checks by grepping this source.

    Without them every ioctl on the terminal is refused. `tcsetattr` returns
    EPERM, nothing inside can enter raw mode, and an interactive client is
    left with the tty in canonical+echo — which is why mouse reports appeared
    as literal text in the prompt and why `stty -a` printed nothing.

    Measured, not reasoned about: handing sandbox-exec a profile that refuses
    ioctl reproduces the same `stty: TIOCGETD: Operation not permitted`, and
    the failure is byte-identical under `srt` alone, so it was never anything
    `aegis run` did to the process it spawns.

    What it grants is terminal devices and nothing else: `/dev/ptmx` and
    `/dev/ttys*`. It moves no path in denyRead, denyWrite or allowWrite and no
    entry in either domain list — asserted in tests/s9.py by comparing the two
    documents directly, and by re-running every kernel-denial check with it on.
    It is a real capability all the same: a process inside can then open
    another terminal owned by the same user. An unsandboxed agent could
    already do that, so this declines to add a protection rather than removing
    one, but the distinction is worth stating rather than eliding.

    Network is allow-only and starts empty, so `curl` reaches nothing unless
    policy named it. TWO lists feed it, and they are unioned here and nowhere
    else:

      allowed_domains   the proxy's own egress allowlist (S8, C4), passed
                        through so a fetch tool that Aegis permits can also
                        leave the sandbox.
      sandbox_domains   hosts the process tree may reach that Aegis itself
                        never fetches — in practice the client's own API and
                        update endpoints. See policy.py::_load_sandbox_domains
                        for why this is a separate key rather than more entries
                        in the first one.

    What that buys and what it does not is in S9-REPORT.md §The network
    residual — briefly: the sandbox cannot tell the proxy's request from
    bash's, so bash can also reach an allowed domain. That residual is why
    sandbox_domains is kept as short as it can be and still let the client
    start. `deny_all_network=True` clears BOTH lists, at the cost of C4's
    egress and of the client being able to function.
    """
    allow_write = [_resolved(root) for root in policy.workspace_roots]
    allow_write.append(_resolved(default_db_path().parent))
    if policy.trash_dir is not None:
        allow_write.append(_resolved(policy.trash_dir))
    allow_write.append(_resolved(SYSTEM_TEMP_ROOT))
    # S9f. The client's own state directory, when policy names one. Not the
    # home directory — policy.py refuses that outright — and nothing here is
    # derived: the paths come from the policy, which `aegis init` fills in from
    # a measured table.
    for state in getattr(policy, "sandbox_state_paths", ()):
        allow_write.append(_resolved(state))

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
    # S9f. Read-only islands inside a granted state directory: the files whose
    # contents are code the client will run, or credentials. denyWrite beats
    # allowWrite in this runtime, so these survive the grant around them.
    # Deliberately NOT added to deny_read: the client has to read its own
    # settings to start, and denying that would break the thing being fixed.
    # The `/**` is appended whether the entry is a file or a directory. On a
    # file it matches nothing and costs a line; deciding by is_dir() would be
    # wrong for a path that does not exist yet, which is exactly the case for a
    # credentials file on a machine that keeps its token in the Keychain.
    for protect in getattr(policy, "sandbox_state_protect", ()):
        deny_write.append(_resolved(protect))
        deny_write.append(_resolved(protect) + "/**")

    for pattern in policy.deny_paths:
        deny_read.extend(_deny_globs(pattern))
        deny_write.extend(_deny_globs(pattern))

    # getattr for both, matching how folder_rules is read above: the suites
    # build policy stand-ins, and a missing attribute must read as "no domains"
    # rather than raising — deny-by-default survives a partial object.
    domains: list[str] = []
    if not deny_all_network:
        domains += [str(d) for d in getattr(policy, "allowed_domains", ())]
        domains += [str(d) for d in getattr(policy, "sandbox_domains", ())]

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
        # Always emitted, true or false, so the document says what it means
        # rather than meaning something by omission — and so turning it off
        # moves the digest visibly instead of silently.
        "allowPty": bool(getattr(policy, "sandbox_pty", True)),
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
        """The argv that runs `argv` inside this sandbox.

        The `--` is not decoration. The runtime's own CLI takes a `-c` flag
        ("run command string directly"), and it parses options anywhere on the
        line, so `aegis run -- bash -c 'script'` handed it without a separator
        was read as *the runtime's* `-c`: `bash` was dropped and the script was
        run by the runtime's shell instead. It worked, which is why nothing
        noticed — but the process tree was not the one the operator asked for,
        and the runtime recorded the command as `script` rather than
        `bash -c script`. Measured while building S9j's attribution, which
        needs the recorded command to be the command.
        """
        return [self.runtime, "-s", str(self.profile), "--", *argv]

    def summary(self) -> str:
        fs = self.document["filesystem"]
        net = self.document["network"]["allowedDomains"]
        return (
            f"sandbox established via {Path(self.runtime).name} on "
            f"{self.platform}; profile {self.digest[:16]}; "
            f"{len(fs['allowWrite'])} writable root(s), "
            f"{len(fs['denyRead'])} read-denied pattern(s), "
            f"{len(net)} domain(s) reachable"
            + (f": {', '.join(net)}" if net else "")
            + ("; terminal control allowed"
               if self.document.get("allowPty") else
               "; NO terminal control — an interactive client cannot enter raw mode")
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
