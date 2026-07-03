"""Boundary profiles — safe defaults keyed to what you're protecting.

A profile expands into two tiers of glob rules over capability names: ``block``
(forbidden) and ``ask`` (risky, pause for a human). A *mode* sets how the block
tier is enforced:

  * ``observe`` — never interrupt; log what would have been blocked/asked;
  * ``ask``     — pause on risky actions; still hard-deny the catastrophic floor
                  (:data:`ALWAYS_DENY`: secrets, disk wipes, RCE, exfiltration);
  * ``enforce`` — hard-deny the block tier, pause on the ask tier.
"""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Dict, List, Optional, Tuple

# The catastrophic, usually-irreversible floor. These stay hard-denied even in
# ``ask`` mode — there is no "are you sure?" for leaking a key or wiping a disk.
ALWAYS_DENY: Tuple[str, ...] = (
    "secrets:read", "secrets:write", "secrets:*",
    "fs:destroy", "*:destroy",
    "code:exec", "remote:exfiltrate", "*:exfiltrate",
)

MODES = ("observe", "ask", "enforce")


@dataclass(frozen=True)
class Profile:
    key: str
    name: str
    tagline: str
    default_mode: str
    block_patterns: Tuple[str, ...]   # forbidden (glob over capabilities)
    ask_patterns: Tuple[str, ...]     # risky — pause for a human (glob)

    def _match(self, patterns: Tuple[str, ...], cap: str) -> bool:
        return any(fnmatch(cap, p) for p in patterns)

    def blocks(self, cap: str) -> bool:
        return self._match(self.block_patterns, cap)

    def asks(self, cap: str) -> bool:
        return self._match(self.ask_patterns, cap)

    def to_dict(self) -> Dict[str, object]:
        return {
            "key": self.key, "name": self.name, "tagline": self.tagline,
            "default_mode": self.default_mode,
            "block_patterns": list(self.block_patterns),
            "ask_patterns": list(self.ask_patterns),
        }


def always_denied(cap: str) -> bool:
    return any(fnmatch(cap, p) for p in ALWAYS_DENY)


# Building blocks, ordered from least to most locked-down; each profile layers these.
_SECRETS = ("secrets:read", "secrets:write")
_DESTRUCTIVE = ("fs:destroy", "db:destroy")
_EXFIL = ("*:exfiltrate", "remote:exfiltrate", "code:exec")
_DEPLOY = ("prod:deploy", "prod:write", "*:deploy")   # for profiles that don't block prod:*
_PUBLISH = ("package:publish",)
_PUSH = ("git:push", "git:merge")
_DELETE = ("fs:delete",)

_PROFILES: Tuple[Profile, ...] = (
    Profile(
        key="personal",
        name="Personal repo",
        tagline="Solo dev. Block secrets & destructive commands; ask before pushes, "
                "publishes and deploys.",
        default_mode="ask",
        block_patterns=_SECRETS + _DESTRUCTIVE + _EXFIL,
        ask_patterns=_PUSH + _DELETE + _PUBLISH + _DEPLOY,
    ),
    Profile(
        key="team",
        name="Startup / team repo",
        tagline="Block secrets & destructive commands; ask before deploys, migrations, "
                "auth/billing edits, CI/CD, dependency installs, and pushes.",
        default_mode="ask",
        block_patterns=_SECRETS + _DESTRUCTIVE + _EXFIL,
        # prod:* here means "ask before anything prod" (deploy or infra edit).
        ask_patterns=_PUSH + _DELETE + _PUBLISH
        + ("prod:*", "migrations:*", "auth:write", "billing:write", "ci:write", "deps:install"),
    ),
    Profile(
        key="production",
        name="Production service",
        tagline="Enforce: prod deploys and infra edits are blocked outright; secret access, "
                "DB drops and exfiltration too. Ask before migrations, auth/billing & installs.",
        default_mode="enforce",
        # prod:* is a hard block here (enforce) — no unattended deploys or infra edits.
        block_patterns=_SECRETS + _DESTRUCTIVE + _EXFIL + ("prod:*",),
        ask_patterns=_PUSH + _DELETE + _PUBLISH
        + ("migrations:*", "auth:write", "billing:write", "ci:write", "deps:install"),
    ),
    Profile(
        key="regulated",
        name="Regulated (SOC2 / HIPAA)",
        tagline="Enforce with strong receipts. Block secrets, prod changes, data/PHI export "
                "and destructive DB ops; ask before access-control, billing & installs.",
        default_mode="enforce",
        block_patterns=_SECRETS + _DESTRUCTIVE + _EXFIL
        + ("prod:*", "*:export", "phi:export", "data:export"),
        ask_patterns=_PUSH + _DELETE + _PUBLISH
        + ("migrations:*", "auth:*", "billing:*", "ci:write", "deps:install", "phi:*"),
    ),
)

PROFILES: Dict[str, Profile] = {p.key: p for p in _PROFILES}
DEFAULT_PROFILE = "team"


def get_profile(key: str) -> Optional[Profile]:
    return PROFILES.get(key)


def list_profiles() -> List[Profile]:
    return list(_PROFILES)
