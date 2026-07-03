"""Map a Claude Code tool call to a capability, then decide it against a profile.

The decision logic is deliberately small and dependency-free:

    tool call  ──capability_for──▶  capability strings  ──decide──▶  allow / ask / deny

``capability_for`` translates a PreToolUse envelope (``Bash`` command, ``Edit``
path, ``mcp__…`` call …) into candidate capability strings. ``decide`` matches
those against the chosen :class:`~certior_guard.profiles.Profile` under the
active mode and returns a verdict with a human reason.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

from certior_guard.profiles import Profile, always_denied
from certior_guard.shell_parse import shell_capabilities

# ── Path heuristics ──────────────────────────────────────────────────────────
_SECRET_PATH = re.compile(
    r"(^|/)\.env(\.|$)|(^|/)(secrets?|credentials?)(/|\.|$)|\.pem$|\.key$|"
    r"id_rsa|/\.aws/|/\.ssh/|\.pfx$|\.p12$|\.netrc|service-account\.json|\.npmrc$|\.pypirc$",
    re.IGNORECASE,
)
_PROD_PATH = re.compile(
    r"(^|/)(prod|production|infra|terraform|k8s|kubernetes|helm)(/|$)|"
    r"(^|/)(Dockerfile|docker-compose\.ya?ml)$",
    re.IGNORECASE,
)
_MIGRATION_PATH = re.compile(r"(^|/)(migrations?)(/|$)|/migrate/", re.IGNORECASE)
_AUTH_PATH = re.compile(r"(^|/)(auth|permissions?|security|crypto)(/|$)", re.IGNORECASE)
_BILLING_PATH = re.compile(r"(^|/)(billing|payments?|stripe)(/|$)", re.IGNORECASE)
_CI_PATH = re.compile(r"(^|/)\.github/workflows/|(^|/)\.gitlab-ci\.ya?ml$|(^|/)\.circleci/", re.IGNORECASE)


def _write_caps_for_path(path: str) -> List[str]:
    """Capability candidates for a file write, most-specific first."""
    if _SECRET_PATH.search(path):
        return ["secrets:write", "files:write"]
    if _MIGRATION_PATH.search(path):
        return ["migrations:write", "files:write"]
    if _CI_PATH.search(path):
        return ["ci:write", "files:write"]
    if _AUTH_PATH.search(path):
        return ["auth:write", "files:write"]
    if _BILLING_PATH.search(path):
        return ["billing:write", "files:write"]
    if _PROD_PATH.search(path):
        return ["prod:write", "files:write"]
    return ["files:write"]


def capability_for(tool_name: str, tool_input: Dict[str, Any]) -> Tuple[List[str], str]:
    """Return ``(capability_candidates, preview)`` for a Claude Code tool call.

    Several candidates are returned so a profile glob (``secrets:*``, ``*:write``)
    can match on any of them.
    """
    ti = tool_input or {}

    if tool_name.startswith("mcp__"):
        # mcp__<server>__<tool> — no upstream schema here, so classify by verb.
        tool = tool_name.split("__", 2)[-1].lower()
        if re.search(r"delete|remove|drop|destroy", tool):
            return ["mcp:delete", "mcp:" + tool], tool_name
        if re.search(r"send|email|post|publish|transfer|pay", tool):
            return ["mcp:send", "mcp:" + tool], tool_name
        if re.search(r"write|create|update|edit|set", tool):
            return ["mcp:write", "mcp:" + tool], tool_name
        return ["mcp:read", "mcp:" + tool], tool_name

    if tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        path = str(ti.get("file_path", ""))
        content = ti.get("new_string") or ti.get("file_text") or ti.get("content") or ""
        return _write_caps_for_path(path), str(content)[:4000]

    if tool_name == "Read":
        path = str(ti.get("file_path", ""))
        return (["secrets:read"] if _SECRET_PATH.search(path) else ["files:read"]), path

    if tool_name in ("WebFetch", "WebSearch"):
        return ["network:http:read"], str(ti.get("url") or ti.get("query") or "")

    if tool_name == "Bash":
        cmd = str(ti.get("command", ""))
        caps = shell_capabilities(cmd)
        if caps:
            return caps, cmd
        if caps is not None:
            return ["shell:exec"], cmd   # parsed fine, nothing dangerous
        return ["shell:exec"], cmd       # parse failed → still allow bare exec

    return ["tool:" + tool_name.lower()], json.dumps(ti)[:2000]


# ── Decision ─────────────────────────────────────────────────────────────────

def decide(tool_name: str, tool_input: Dict[str, Any], profile: Profile, mode: str) -> Dict[str, str]:
    """Decide a tool call. Returns ``{decision, reason, capability, would}``.

    ``decision`` is what Certior tells Claude Code now (``allow``/``ask``/``deny``).
    ``would`` is what the rules say regardless of mode — so ``observe`` mode can
    report "would have blocked" without actually interrupting.
    """
    caps, _preview = capability_for(tool_name, tool_input)

    blocked = next((c for c in caps if profile.blocks(c)), None)
    asked = next((c for c in caps if profile.asks(c)), None)
    floor = next((c for c in caps if always_denied(c)), None)

    if blocked or floor:
        would, cap = "deny", (floor or blocked)
    elif asked:
        would, cap = "ask", asked
    else:
        return {"decision": "allow", "would": "allow", "capability": caps[0] if caps else "?", "reason": ""}

    pname = profile.name

    if mode == "observe":
        verb = "blocked" if would == "deny" else "held for approval"
        return {"decision": "allow", "would": would, "capability": cap,
                "reason": f"[observe] would have {verb} '{cap}' ({pname})."}

    if mode == "ask":
        # Catastrophic floor stays hard-denied; everything else just asks.
        if floor:
            return {"decision": "deny", "would": "deny", "capability": floor,
                    "reason": f"Certior · {pname}: '{floor}' is never allowed for an agent."}
        return {"decision": "ask", "would": would, "capability": cap,
                "reason": f"Certior · {pname}: '{cap}' is risky — approve before it runs."}

    # enforce
    if would == "deny":
        return {"decision": "deny", "would": "deny", "capability": cap,
                "reason": f"Certior · {pname}: '{cap}' is outside this boundary."}
    return {"decision": "ask", "would": "ask", "capability": cap,
            "reason": f"Certior · {pname}: '{cap}' is high-stakes — approve before it runs."}
