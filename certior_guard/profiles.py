"""Boundary profiles — safe defaults keyed to what you're protecting.

A *profile* answers "what are you protecting?" — a personal repo, a team repo,
a production service, or a regulated one — and expands into two tiers of rules:

  * ``block`` — forbidden actions (secrets, destructive shell, prod deploys …)
  * ``ask``   — risky-but-normal actions that pause for a human (push, migrate …)

Rules are **glob patterns** over capability names (:func:`fnmatch.fnmatch`), not
literal lists, so they match any spelling a shell produces and only ever
*narrow* what the agent may do.

On top of the profile sits a **mode** — how strictly the ``block`` tier is
enforced:

  * ``observe`` — never interrupt; just log what *would* have been blocked/asked
  * ``ask``     — pause for approval on risky actions; still hard-deny the
                  catastrophic floor (:data:`ALWAYS_DENY`: secrets, disk wipes,
                  remote-code-exec, exfiltration)
  * ``enforce`` — hard-deny the ``block`` tier, pause on the ``ask`` tier

Pure stdlib, no dependencies.
"""
from __future__ import annotations

from dataclasses import dataclass, field
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


# ── The menu ─────────────────────────────────────────────────────────────────
# Ordered from least to most locked-down. Each layers onto the previous one.

_SECRETS = ("secrets:read", "secrets:write")
_DESTRUCTIVE = ("fs:destroy", "db:destroy")
_EXFIL = ("*:exfiltrate", "remote:exfiltrate", "code:exec")
_DEPLOY = ("prod:deploy", "prod:write", "*:deploy")
_PUBLISH = ("package:publish", "*:release")
_PUSH = ("git:push", "git:merge")
_DELETE = ("fs:delete",)

_PROFILES: Tuple[Profile, ...] = (
    Profile(
        key="personal",
        name="Personal repo",
        tagline="Solo dev. Block secrets & destructive commands; ask before pushes and publishes.",
        default_mode="ask",
        block_patterns=_SECRETS + _DESTRUCTIVE + _EXFIL,
        ask_patterns=_PUSH + _DELETE + _PUBLISH + _DEPLOY,
    ),
    Profile(
        key="team",
        name="Startup / team repo",
        tagline="Block secrets & destructive commands; ask before deploys, migrations, "
                "auth/billing edits, CI/CD, and pushes to protected branches.",
        default_mode="ask",
        block_patterns=_SECRETS + _DESTRUCTIVE + _EXFIL,
        ask_patterns=_PUSH + _DELETE + _PUBLISH + _DEPLOY
        + ("migrations:*", "auth:write", "billing:write", "ci:write", "prod:*"),
    ),
    Profile(
        key="production",
        name="Production service",
        tagline="Enforce: no prod deploys, IAM/Terraform/k8s changes, DB drops, or secret "
                "access without approval. Ask before migrations & dependency changes.",
        default_mode="enforce",
        block_patterns=_SECRETS + _DESTRUCTIVE + _EXFIL + ("prod:*",),
        ask_patterns=_PUSH + _DELETE + _PUBLISH + _DEPLOY
        + ("migrations:*", "auth:write", "billing:write", "ci:write", "deps:install"),
    ),
    Profile(
        key="regulated",
        name="Regulated (SOC2 / HIPAA)",
        tagline="Enforce mode with strong receipts. Block secrets, data export, and "
                "destructive DB ops; ask before access-control, infra & billing changes.",
        default_mode="enforce",
        block_patterns=_SECRETS + _DESTRUCTIVE + _EXFIL
        + ("prod:*", "*:export", "phi:export", "data:export"),
        ask_patterns=_PUSH + _DELETE + _PUBLISH + _DEPLOY
        + ("migrations:*", "auth:*", "billing:*", "ci:write", "deps:install", "phi:*"),
    ),
)

PROFILES: Dict[str, Profile] = {p.key: p for p in _PROFILES}
DEFAULT_PROFILE = "team"


def get_profile(key: str) -> Optional[Profile]:
    return PROFILES.get(key)


def list_profiles() -> List[Profile]:
    return list(_PROFILES)
