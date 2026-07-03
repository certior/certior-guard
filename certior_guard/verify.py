"""Verify the audit log two independent ways.

Integrity — recompute each receipt hash and confirm every ``prev`` links to the
prior receipt; any altered, inserted, or deleted line breaks the chain at a named
seq. Faithfulness — re-run each decision through the engine under its recorded
profile+mode; a mismatch means the receipt no longer matches the policy. Both are
pure and offline.
"""
from __future__ import annotations

from typing import Any, Dict, List

from certior_guard.engine import decide
from certior_guard.profiles import get_profile
from certior_guard.receipts import GENESIS, read_all, receipt_hash


def _reconstruct_input(tool: str, target: str) -> Dict[str, Any]:
    """Rebuild the decision-relevant tool input from (tool, target).

    Decisions depend only on the command / path / url / MCP name, all preserved
    in ``target``, so this replay is faithful without storing tool content.
    """
    if tool == "Bash":
        return {"command": target}
    if tool in ("Read", "Edit", "Write", "MultiEdit", "NotebookEdit"):
        return {"file_path": target}
    if tool in ("WebFetch", "WebSearch"):
        return {"url": target}
    return {}  # mcp__… and others classify off the tool name alone


def verify(audit_dir: str, replay: bool = True) -> Dict[str, Any]:
    """Return a structured verification report over the whole audit log."""
    rows = read_all(audit_dir)
    chained = [r for r in rows if "hash" in r]

    report: Dict[str, Any] = {
        "total": len(rows),
        "chained": len(chained),
        "integrity_ok": True,
        "break_at": None,
        "break_reason": None,
        "replayed": 0,
        "drift": [],  # receipts whose decision no longer matches the engine
    }

    prev_hash = GENESIS
    for r in chained:
        recomputed = receipt_hash(r)
        if recomputed != r.get("hash"):
            report.update(integrity_ok=False, break_at=r.get("seq"),
                          break_reason="content hash mismatch (receipt altered)")
            break
        if r.get("prev") != prev_hash:
            report.update(integrity_ok=False, break_at=r.get("seq"),
                          break_reason="broken link (a prior receipt was changed or removed)")
            break
        prev_hash = r.get("hash")

    if replay:
        drift: List[Dict[str, Any]] = []
        for r in chained:
            prof = get_profile(str(r.get("profile", "")))
            if prof is None:
                continue
            ti = _reconstruct_input(str(r.get("tool", "")), str(r.get("target", "")))
            got = decide(str(r.get("tool", "")), ti, prof, str(r.get("mode", "")))
            report["replayed"] += 1
            if got["decision"] != r.get("decision"):
                drift.append({"seq": r.get("seq"), "tool": r.get("tool"),
                              "target": r.get("target"), "recorded": r.get("decision"),
                              "now": got["decision"]})
        report["drift"] = drift

    report["ok"] = report["integrity_ok"] and not report["drift"]
    return report
