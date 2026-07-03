"""Local audit receipts — every decision is logged, no cloud, no login.

One JSON object per line, appended to ``.certior/audit/YYYY-MM-DD.jsonl``: a
grep-able, diff-able, offline record of what the agent tried and what Certior did.

A ``policy_hash`` binds each receipt to the exact rule set in force, so a receipt
can later be replayed and checked against the policy that produced it.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

AUDIT_DIRNAME = os.path.join(".certior", "audit")


def policy_hash(profile_dict: Dict[str, object], mode: str) -> str:
    blob = json.dumps({"profile": profile_dict, "mode": mode}, sort_keys=True)
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()[:16]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_receipt(
    *,
    audit_dir: str,
    tool: str,
    target: str,
    decision: str,
    would: str,
    capability: str,
    reason: str,
    profile_key: str,
    mode: str,
    policy_hash: str,
    session_id: str = "",
) -> Optional[str]:
    """Append one receipt line. Best-effort — never raises into the hook."""
    try:
        os.makedirs(audit_dir, exist_ok=True)
        ts = _now()
        receipt = {
            "actor": "claude-code",
            "tool": tool,
            "target": target[:500],
            "decision": decision,
            "would": would,
            "capability": capability,
            "reason": reason,
            "profile": profile_key,
            "mode": mode,
            "policy_hash": policy_hash,
            "session_id": session_id,
            "timestamp": ts,
            "verifier": "certior-guard",
        }
        day = ts[:10]
        path = os.path.join(audit_dir, f"{day}.jsonl")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(receipt, ensure_ascii=False) + "\n")
        return path
    except Exception:
        return None


def read_recent(audit_dir: str, limit: int = 20) -> List[Dict[str, object]]:
    """Most recent receipts across all day-files, newest last."""
    rows: List[Dict[str, object]] = []
    try:
        files = sorted(
            os.path.join(audit_dir, f) for f in os.listdir(audit_dir) if f.endswith(".jsonl")
        )
    except FileNotFoundError:
        return []
    for path in files:
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        rows.append(json.loads(line))
        except Exception:
            continue
    return rows[-limit:]
