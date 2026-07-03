"""Local, tamper-evident audit receipts — one JSON object per line in
``.certior/audit/YYYY-MM-DD.jsonl``.

The log is a hash chain: each receipt carries ``seq``, ``prev`` (the previous
receipt's hash), and ``hash`` (SHA-256 over its own content). Altering or deleting
any receipt breaks every later link, so ``certior-guard verify`` can prove the log
is intact. Writes take a best-effort directory lock so concurrent sessions extend
one chain. Best-effort throughout: never raises into the hook.
"""
from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional, Tuple

AUDIT_DIRNAME = os.path.join(".certior", "audit")
GENESIS = "sha256:genesis"

# Fields that are not part of the signed content (the hash itself).
_UNSIGNED = ("hash",)


def policy_hash(profile_dict: Dict[str, object], mode: str) -> str:
    blob = json.dumps({"profile": profile_dict, "mode": mode}, sort_keys=True)
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()[:16]


def receipt_hash(receipt: Dict[str, object]) -> str:
    """SHA-256 over a receipt's canonical content (every field except ``hash``)."""
    content = {k: v for k, v in receipt.items() if k not in _UNSIGNED}
    blob = json.dumps(content, sort_keys=True, ensure_ascii=False)
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _day_files(audit_dir: str) -> List[str]:
    try:
        return sorted(os.path.join(audit_dir, f)
                      for f in os.listdir(audit_dir) if f.endswith(".jsonl"))
    except FileNotFoundError:
        return []


@contextmanager
def _lock(audit_dir: str) -> Iterator[None]:
    """Exclusive directory lock, best-effort. No-op where flock is unavailable."""
    lockpath = os.path.join(audit_dir, ".lock")
    try:
        import fcntl
    except Exception:
        yield
        return
    fd = os.open(lockpath, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _tail(audit_dir: str) -> Tuple[int, str]:
    """``(seq, hash)`` of the last receipt in the chain, or ``(0, GENESIS)``."""
    for path in reversed(_day_files(audit_dir)):
        last = None
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        last = line
        except OSError:
            continue
        if last:
            try:
                rec = json.loads(last)
                return int(rec.get("seq", 0)), str(rec.get("hash", GENESIS))
            except (ValueError, TypeError):
                return 0, GENESIS
    return 0, GENESIS


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
    """Append one hash-chained receipt line. Best-effort — never raises."""
    try:
        os.makedirs(audit_dir, exist_ok=True)
        with _lock(audit_dir):
            prev_seq, prev_hash = _tail(audit_dir)
            ts = _now()
            receipt: Dict[str, object] = {
                "seq": prev_seq + 1,
                "prev": prev_hash,
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
            receipt["hash"] = receipt_hash(receipt)
            path = os.path.join(audit_dir, f"{ts[:10]}.jsonl")
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(receipt, ensure_ascii=False) + "\n")
            return path
    except Exception:
        return None


def read_all(audit_dir: str) -> List[Dict[str, object]]:
    """Every receipt across all day-files, in chain order (oldest first)."""
    rows: List[Dict[str, object]] = []
    for path in _day_files(audit_dir):
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        rows.append(json.loads(line))
        except (OSError, ValueError):
            continue
    return rows


def read_recent(audit_dir: str, limit: int = 20) -> List[Dict[str, object]]:
    """Most recent receipts, newest last."""
    return read_all(audit_dir)[-limit:]
