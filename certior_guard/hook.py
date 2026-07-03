"""PreToolUse hook: read a tool-call envelope on stdin, decide it against the
configured profile+mode, write a receipt, and emit the decision on stdout.

Fail-open: any error exits 0 so a Certior fault never blocks normal work.
"""
from __future__ import annotations

import json
import sys
from typing import Optional

from certior_guard.config import load_config
from certior_guard.engine import decide
from certior_guard.profiles import get_profile
from certior_guard.receipts import policy_hash, write_receipt


def run_hook(
    profile_key: Optional[str] = None,
    mode: Optional[str] = None,
    stream=sys.stdin,
    out=sys.stdout,
) -> int:
    try:
        envelope = json.load(stream)
    except Exception:
        return 0

    cfg = load_config()
    profile = get_profile(profile_key or cfg["profile"]) or get_profile(cfg["profile"])
    mode = mode or cfg["mode"]
    if profile is None:
        return 0  # unknown profile → fail open

    tool_name = envelope.get("tool_name", "")
    tool_input = envelope.get("tool_input", {}) or {}

    try:
        d = decide(tool_name, tool_input, profile, mode)
    except Exception:
        return 0  # fail-open

    try:
        target = (
            tool_input.get("command")
            or tool_input.get("file_path")
            or tool_input.get("url")
            or tool_input.get("query")
            or ""
        )
        write_receipt(
            audit_dir=cfg["audit_dir"],
            tool=tool_name,
            target=str(target),
            decision=d["decision"],
            would=d.get("would", d["decision"]),
            capability=d.get("capability", ""),
            reason=d.get("reason", ""),
            profile_key=profile.key,
            mode=mode,
            policy_hash=policy_hash(profile.to_dict(), mode),
            session_id=str(envelope.get("session_id", "")),
        )
    except Exception:
        pass

    if d["decision"] == "allow":
        # In observe mode, surface the would-be block as a non-blocking note so
        # the user still sees Certior working without being interrupted.
        if mode == "observe" and d.get("would") in ("deny", "ask") and d.get("reason"):
            sys.stderr.write("certior: " + d["reason"] + "\n")
        return 0  # silent — Claude Code's normal flow continues

    out.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": d["decision"],            # "deny" | "ask"
            "permissionDecisionReason": d["reason"],
        }
    }, ensure_ascii=False))
    out.flush()
    return 0
