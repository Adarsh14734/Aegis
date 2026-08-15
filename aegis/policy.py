"""Deterministic policy engine for Aegis.

S1: controls C1 (path allow/deny per tools/call) and C2 (default-deny).
S3a: partial C4 (egress domain allowlist) and partial C5 (outbound secret
scan), delegated to egress.py and dlp.py but sequenced here.

Design constraints from THREAT-MODEL.md:
  - B1: nothing on the agent side is trusted, including tool arguments.
  - D1: decisions here are deterministic. No model judgement anywhere in this file.
  - Fail-closed: any exception raised out of this module must be treated as DENY
    by the caller. The caller is responsible for that; this module never guesses.
"""

import fnmatch
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import dlp
import egress


class Effect(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    effect: Effect
    reason: str
    rule_id: str
    tool: str
    paths: tuple[str, ...] = ()

    def is_allowed(self) -> bool:
        return self.effect is Effect.ALLOW


class PolicyError(Exception):
    """Raised for any malformed or unsafe policy. Callers must fail closed."""


# Argument keys that carry filesystem paths in the reference MCP filesystem server.
# Anything not listed here is not treated as a path. Unknown path-bearing tools are
# caught by default-deny rather than by guessing at argument names.
PATH_ARG_KEYS = ("path", "paths", "source", "destination", "src", "dst", "directory")


def safe_resolve(raw: str, cwd: Path) -> Path:
    """Resolve a path for policy evaluation without trusting it.

    Resolves symlinks on the deepest existing ancestor, then re-appends the
    non-existent tail. This prevents two escapes:
      - '../../etc/passwd' traversal
      - a symlink inside the workspace pointing outside it
    A path that does not exist yet (a file about to be created) still gets its
    parent directory resolved, so a symlinked parent cannot be used to escape.
    """
    p = Path(raw)
    if not p.is_absolute():
        p = cwd / p

    tail: list[str] = []
    probe = p
    # Walk up to the deepest component that actually exists.
    while not probe.exists():
        if probe.parent == probe:  # reached filesystem root
            break
        tail.append(probe.name)
        probe = probe.parent

    resolved = probe.resolve()
    for part in reversed(tail):
        resolved = resolved / part
    return resolved


def _within(child: Path, parent: Path) -> bool:
    try:
        return child == parent or child.is_relative_to(parent)
    except (ValueError, OSError):
        return False


class Policy:
    """Loaded, validated policy. Immutable after construction."""

    def __init__(self, doc: dict, source_path: Path):
        self.source_path = source_path

        if doc.get("version") != 1:
            raise PolicyError(f"unsupported policy version: {doc.get('version')!r}")

        roots = doc.get("workspace_roots") or []
        if not isinstance(roots, list) or not roots:
            raise PolicyError("workspace_roots must be a non-empty list")
        self.workspace_roots = tuple(Path(r).expanduser().resolve() for r in roots)

        self.deny_paths = tuple(doc.get("deny_paths") or ())
        if not isinstance(self.deny_paths, tuple):
            raise PolicyError("deny_paths must be a list")

        self.allowed_domains = self._load_allowed_domains(doc)

        rules = doc.get("tool_rules") or {}
        if not isinstance(rules, dict):
            raise PolicyError("tool_rules must be an object")
        for tool, rule in rules.items():
            if rule.get("effect") not in {e.value for e in Effect}:
                raise PolicyError(f"tool_rules[{tool}] has invalid effect")
        self.tool_rules = rules

        default = doc.get("default_effect", "deny")
        if default == Effect.ALLOW.value:
            # D1/C2: a policy file that defaults to allow is a misconfiguration
            # severe enough that we refuse to run rather than run insecurely.
            raise PolicyError("default_effect may not be 'allow'")
        self.default_effect = Effect(default)

        # S5 has not been built. Until an approval loop exists, ASK cannot be
        # resolved by a human, so it must collapse to DENY. Recorded explicitly
        # so this becomes a visible change when S5 lands.
        self.ask_behavior = Effect(doc.get("ask_behavior", "deny"))
        if self.ask_behavior is Effect.ALLOW:
            raise PolicyError("ask_behavior may not be 'allow' before S5")

        self._assert_policy_file_unreachable()

    @staticmethod
    def _load_allowed_domains(doc: dict) -> tuple[str, ...]:
        """S3a: a missing key is the empty list, and the empty list denies every
        URL. Absence must never mean permissive — the same rule as C2.

        Entries are bare hostnames. Subdomains are implied, so '*.example.com'
        is rejected rather than silently reinterpreted, and a bare '*' is
        rejected outright for the same reason `default_effect: allow` is: a
        policy that permits everything is a misconfiguration severe enough to
        refuse to start over.
        """
        raw = doc.get("allowed_domains")
        if raw is None:
            return ()
        if not isinstance(raw, list):
            raise PolicyError("allowed_domains must be a list")

        out: list[str] = []
        for entry in raw:
            if not isinstance(entry, str):
                raise PolicyError(f"allowed_domains entry {entry!r} is not a string")
            value = egress.normalize_domain(entry)
            if not value:
                raise PolicyError("allowed_domains contains an empty entry")
            if value == "*":
                raise PolicyError("allowed_domains may not contain '*' (allow-all)")
            if value.startswith("*."):
                raise PolicyError(
                    f"allowed_domains entry {entry!r}: wildcards are not supported; "
                    f"write {value[2:]!r}, which already covers its subdomains"
                )
            if "/" in value:
                raise PolicyError(
                    f"allowed_domains entry {entry!r} must be a bare host, "
                    f"without scheme or path"
                )
            head, sep, tail = value.rpartition(":")
            if sep and tail.isdigit() and egress.parse_ip_literal(value) is None:
                # ...but ':' inside a bare IPv6 literal is not a port.
                raise PolicyError(
                    f"allowed_domains entry {entry!r} must not carry a port; "
                    f"ports are not part of the host check"
                )
            out.append(value)
        return tuple(out)

    def _assert_policy_file_unreachable(self) -> None:
        """S0 decision #2: the agent must not be able to write the policy file.

        Verified structurally at load time: if the policy file sits inside any
        workspace root the agent can write to, refuse to start. A proxy that
        enforces a policy the agent can edit enforces nothing.
        """
        policy = self.source_path.resolve()
        for root in self.workspace_roots:
            if _within(policy, root):
                raise PolicyError(
                    f"policy file {policy} is inside agent-writable workspace root "
                    f"{root}; move it outside every workspace root"
                )

    @classmethod
    def load(cls, path: Path) -> "Policy":
        if not path.exists():
            raise PolicyError(f"policy file not found: {path}")
        mode = path.stat().st_mode
        if mode & 0o022:
            raise PolicyError(
                f"policy file {path} is group/world writable (mode {oct(mode & 0o777)})"
            )
        try:
            doc = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise PolicyError(f"policy file is not valid JSON: {exc}") from exc
        return cls(doc, path)

    # ---- evaluation -----------------------------------------------------

    def extract_paths(self, arguments: dict) -> list[str]:
        found: list[str] = []
        for key in PATH_ARG_KEYS:
            val = arguments.get(key)
            if isinstance(val, str):
                found.append(val)
            elif isinstance(val, list):
                found.extend(v for v in val if isinstance(v, str))
        return found

    def evaluate(self, tool: str, arguments: dict, cwd: Path) -> Decision:
        """Return a Decision. Order is fixed and deny always wins.

        deny_paths -> DLP -> egress -> tool rule -> containment -> default.

        DLP and egress sit above the tool rule for the same reason deny_paths
        does: they must be unreachable by any allow rule. A tool being allowed
        says the *operation* is permitted, never that the *content* is.
        """
        args = arguments if isinstance(arguments, dict) else {}
        raw_paths = self.extract_paths(args)
        resolved = [safe_resolve(p, cwd) for p in raw_paths]
        shown = tuple(str(p) for p in resolved)

        # 1. Explicit deny globs. Highest precedence, checked before anything else.
        for pattern in self.deny_paths:
            for p in resolved:
                if fnmatch.fnmatch(str(p), pattern) or fnmatch.fnmatch(p.name, pattern):
                    return Decision(
                        Effect.DENY,
                        f"path matches deny rule {pattern!r}",
                        "deny_paths",
                        tool,
                        shown,
                    )

        # One traversal feeds both content controls, so they cannot disagree
        # about what the arguments contained. An argument tree too large to
        # scan completely is denied rather than partially scanned.
        try:
            strings = egress.walk_strings(args)
        except egress.ScanLimitExceeded as exc:
            return Decision(
                Effect.DENY,
                f"arguments could not be scanned completely ({exc}); failing closed",
                "scan_limit",
                tool,
                shown,
            )

        # 2. Secrets in arguments (C5, partial). Pattern name only — the value
        # is never carried into the Decision, which is written to the audit db
        # and shown to the model.
        secret = dlp.scan(strings)
        if secret is not None:
            return Decision(Effect.DENY, secret.reason(), "dlp", tool, shown)

        # 3. Egress destinations (C4, partial). Deny-by-default allowlist.
        url = egress.check(strings, self.allowed_domains)
        if url is not None:
            return Decision(
                Effect.DENY,
                f"URL {url.scheme}://{url.host} in {url.where}: {url.reason}",
                "egress_domain",
                tool,
                shown,
            )

        # 4. Tool must be named in policy. Unknown tool -> default (never allow).
        rule = self.tool_rules.get(tool)
        if rule is None:
            return self._default(tool, shown, f"tool {tool!r} not present in tool_rules")

        effect = Effect(rule["effect"])
        if effect is Effect.DENY:
            return Decision(Effect.DENY, "tool is denied by policy", f"tool_rules.{tool}", tool, shown)

        # 5. Containment. Every path in the call must sit inside an allowed root.
        if resolved:
            allowed_roots = self._roots_for(rule)
            for p in resolved:
                if not any(_within(p, root) for root in allowed_roots):
                    return Decision(
                        Effect.DENY,
                        f"path {p} is outside every allowed root for this tool",
                        f"tool_rules.{tool}.within",
                        tool,
                        shown,
                    )

        if effect is Effect.ASK:
            return Decision(
                self.ask_behavior,
                "action requires human approval; approval loop is not implemented until S5",
                f"tool_rules.{tool}",
                tool,
                shown,
            )

        return Decision(Effect.ALLOW, "matched allow rule", f"tool_rules.{tool}", tool, shown)

    def _roots_for(self, rule: dict) -> tuple[Path, ...]:
        within = rule.get("within")
        if not within:
            return self.workspace_roots
        out: list[Path] = []
        for entry in within:
            if entry == "<workspace>":
                out.extend(self.workspace_roots)
            else:
                out.append(Path(entry).expanduser().resolve())
        return tuple(out)

    def _default(self, tool: str, shown: tuple[str, ...], why: str) -> Decision:
        effect = self.default_effect
        if effect is Effect.ASK:
            effect = self.ask_behavior
        return Decision(effect, why, "default_effect", tool, shown)
