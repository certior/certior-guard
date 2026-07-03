"""Read/write ``certior.yml`` — the one file that holds the user's choice.

Format is intentionally tiny::

    profile: team          # personal | team | production | regulated
    mode: ask              # observe | ask | enforce
    audit:
      dir: .certior/audit

We parse this minimal YAML with the stdlib only (no PyYAML dependency) so
``certior-guard`` stays zero-dependency. Anything fancier than the shape above
falls back to sane defaults rather than erroring.
"""
from __future__ import annotations

import os
import re
from typing import Dict

from certior_guard.profiles import DEFAULT_PROFILE, PROFILES, get_profile

CONFIG_NAME = "certior.yml"
DEFAULT_AUDIT_DIR = os.path.join(".certior", "audit")


def default_config() -> Dict[str, str]:
    prof = PROFILES[DEFAULT_PROFILE]
    return {"profile": prof.key, "mode": prof.default_mode, "audit_dir": DEFAULT_AUDIT_DIR}


def _find_config(start: str = ".") -> str:
    """Walk up from ``start`` to the filesystem root looking for certior.yml."""
    cur = os.path.abspath(start)
    while True:
        candidate = os.path.join(cur, CONFIG_NAME)
        if os.path.exists(candidate):
            return candidate
        parent = os.path.dirname(cur)
        if parent == cur:
            return ""
        cur = parent


def load_config(start: str = ".") -> Dict[str, str]:
    """Load config from the nearest certior.yml, filling defaults for anything absent."""
    cfg = default_config()
    path = _find_config(start)
    if not path:
        return cfg
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except Exception:
        return cfg

    in_audit = False
    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indented = line[0] in " \t"
        stripped = line.strip()
        if stripped.rstrip(":") == "audit" and stripped.endswith(":"):
            in_audit = True
            continue
        if not indented:
            in_audit = False
        if ":" not in stripped:
            continue
        key, _, val = stripped.partition(":")
        # Strip an inline "# comment" (only when set off by whitespace, so a
        # value like a URL fragment isn't truncated), then surrounding quotes.
        val = re.split(r"\s+#", val, maxsplit=1)[0]
        key, val = key.strip(), val.strip().strip('"').strip("'")
        if not val:
            continue
        if key == "profile" and get_profile(val):
            cfg["profile"] = val
        elif key == "mode" and val in ("observe", "ask", "enforce"):
            cfg["mode"] = val
        elif key == "dir" and in_audit:
            cfg["audit_dir"] = val
    # Anchor a relative audit dir to the config's directory, not the CWD.
    if not os.path.isabs(cfg["audit_dir"]):
        cfg["audit_dir"] = os.path.join(os.path.dirname(path), cfg["audit_dir"])
    return cfg


def write_config(profile: str, mode: str, audit_dir: str = DEFAULT_AUDIT_DIR, path: str = CONFIG_NAME) -> str:
    prof = get_profile(profile)
    tagline = prof.tagline if prof else ""
    text = (
        "# Certior Guard — safe defaults for Claude Code in this repo.\n"
        "# Edit and save; changes take effect on the next tool call (no restart).\n"
        f"# {tagline}\n\n"
        f"profile: {profile}    # personal | team | production | regulated\n"
        f"mode: {mode}          # observe (log only) | ask (approve risky) | enforce (block)\n"
        "audit:\n"
        f"  dir: {audit_dir}\n"
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path
