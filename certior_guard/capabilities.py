"""The capability vocabulary — the closed set of actions the guard reasons about.

Every tool call is reduced to one or more of these strings
(:mod:`certior_guard.engine`, :mod:`certior_guard.shell_parse`), and every profile
rule is a glob over them. Centralising the vocabulary here turns an implicit pile
of strings into an explicit model, which is what lets ``certior-guard check``
reason over a *closed world*: a profile rule that matches nothing here is dead,
and the always-deny floor can be shown to dominate by exhaustive enumeration.

``source`` records where a capability is classified:

  ``file``      a file path (Read / Edit / Write)
  ``net``       WebFetch / WebSearch
  ``shell``     parsed from a Bash command
  ``mcp``       an MCP tool call
  ``reserved``  part of the model but classified by a later layer (content / MCP
                inspection), not by the current shell/path heuristics
"""
from __future__ import annotations

from fnmatch import fnmatch
from typing import Dict, List

# capability → (source, one-line meaning)
KNOWN_CAPABILITIES: Dict[str, tuple] = {
    "files:read":        ("file", "read a normal file"),
    "files:write":       ("file", "write a normal file"),
    "secrets:read":      ("file", "read a secret file (.env, keys, credentials)"),
    "secrets:write":     ("file", "write a secret file"),
    "prod:write":        ("file", "edit prod/infra/Docker files"),
    "migrations:write":  ("file", "edit a database migration"),
    "ci:write":          ("file", "edit CI/CD workflows"),
    "auth:write":        ("file", "edit auth/permissions/crypto code"),
    "billing:write":     ("file", "edit billing/payments code"),
    "network:http:read": ("net", "fetch a URL / web search"),
    "shell:exec":        ("shell", "run an ordinary shell command"),
    "code:exec":         ("shell", "fetch-and-run remote code (curl | sh)"),
    "remote:exfiltrate": ("shell", "send data to a remote host"),
    "data:exfiltrate":   ("shell", "upload/transfer data off the machine"),
    "fs:destroy":        ("shell", "wipe a disk/device (dd, mkfs, shred)"),
    "fs:delete":         ("shell", "recursive/forced delete (rm -rf)"),
    "db:destroy":        ("shell", "drop/truncate a database"),
    "git:push":          ("shell", "push commits"),
    "git:merge":         ("shell", "merge branches"),
    "prod:deploy":       ("shell", "deploy (terraform/kubectl/vercel …)"),
    "package:publish":   ("shell", "publish a package/release"),
    "deps:install":      ("shell", "install a dependency (supply-chain surface)"),
    "mcp:read":          ("mcp", "read via an MCP tool"),
    "mcp:write":         ("mcp", "write via an MCP tool"),
    "mcp:send":          ("mcp", "send/publish via an MCP tool"),
    "mcp:delete":        ("mcp", "delete via an MCP tool"),
    "phi:read":          ("reserved", "read protected health information"),
    "phi:export":        ("reserved", "export protected health information"),
    "data:export":       ("reserved", "export customer/regulated data"),
}

# Dynamic families the engine may emit with an open-ended suffix (mcp:<tool>,
# tool:<name>). They are recognised so `check` does not flag rules against them.
CAPABILITY_FAMILIES = ("mcp:", "tool:")


def is_known(cap: str) -> bool:
    return cap in KNOWN_CAPABILITIES or any(cap.startswith(f) for f in CAPABILITY_FAMILIES)


def known_matching(pattern: str) -> List[str]:
    """Concrete known capabilities a glob pattern matches (families excluded)."""
    return [c for c in KNOWN_CAPABILITIES if fnmatch(c, pattern)]
