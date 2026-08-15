"""Aegis S3a — outbound secret scanning of tool arguments. Partial C5.

Scans every string in a `tools/call` argument tree for high-confidence secret
patterns. A match denies the call.

THE FAILURE MODE THAT MATTERS IS THE FALSE POSITIVE. A scanner that fires on
ordinary code trains the user to disable it, and a disabled control is worth
less than no control because it is still on the slide deck. Every pattern here
is therefore anchored on a vendor-specific prefix and constrained by length and
charset, and where a pattern has no distinctive prefix — the AWS secret access
key is forty characters of base64, which is also the shape of a git SHA, a
base64 line, or half the hashes in a lockfile — it is gated on a required
context word instead. Deliberately missing a secret is preferred to flagging
normal text. This is a partial control and is described that way in
S3a-REPORT.md.

DISCLOSURE RULE: the matched value never leaves this module. Callers get a
pattern NAME and an argument path. Nothing here returns, logs, or formats the
secret itself, because the caller writes the reason string into the audit
database and into the denial frame the model reads — either would turn a
leak-prevention control into a leak. There is deliberately no debug mode that
prints the match.
"""

import re
from dataclasses import dataclass

# (name, pattern). Order matters only for which name is reported first:
# sk-ant- must be tried before the generic sk- prefix so an Anthropic key is
# not reported as an OpenAI one.
PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    # AKIA/ASIA/ABIA/ACCA + exactly 16 uppercase alphanumerics. Unambiguous.
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),

    # 40 base64 chars is far too generic on its own — a git SHA matches that
    # shape. Only flagged when an aws/secret-access-key label sits next to it.
    ("aws_secret_access_key", re.compile(
        r"(?i)(?:aws[_\-. ]{0,3})?secret[_\-. ]?access[_\-. ]?key\b[^A-Za-z0-9]{0,12}"
        r"[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
    )),

    # Classic PATs: ghp_ (personal), gho_ (oauth), ghs_ (server), ghu_, ghr_.
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b")),
    ("github_fine_grained_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,255}\b")),

    ("anthropic_api_key", re.compile(r"\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_\-]{24,}")),

    # Must not swallow sk-ant-; must not fire on short hyphenated identifiers.
    ("openai_api_key", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{32,}")),

    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),

    ("stripe_secret_key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    # Publishable by design and safe in client code; included because S3a
    # asked for it. Expect this one to be the first false-positive complaint.
    ("stripe_publishable_key", re.compile(r"\bpk_live_[A-Za-z0-9]{16,}\b")),

    ("private_key_pem", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),

    # Three base64url segments where the first two decode to '{"' — requiring
    # eyJ twice is what separates a JWT from any other dotted base64 blob.
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    )),
)


@dataclass(frozen=True)
class Finding:
    """What the caller is allowed to know: which pattern, and where. Never the
    value, never an excerpt, never an offset into a string the caller holds."""

    pattern: str
    where: str

    def reason(self) -> str:
        return (
            f"argument {self.where} contains a value matching secret pattern "
            f"{self.pattern!r}; the value is deliberately not recorded"
        )


def scan(strings) -> Finding | None:
    """First secret found in [(argument_path, text)], or None.

    Patterns are tried in order per string, so the reported name is stable for
    a given input rather than depending on match position.
    """
    for where, text in strings:
        for name, pattern in PATTERNS:
            if pattern.search(text):
                return Finding(name, where)
    return None
