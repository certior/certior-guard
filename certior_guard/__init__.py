"""Certior Guard — safe defaults for Claude Code in real repositories.

Block secrets and dangerous commands, ask before deploys/migrations, and log
every decision. A single PreToolUse hook, zero dependencies, install in two
minutes.

    certior-guard init

The public surface:

    from certior_guard.engine import capability_for, decide, resolve
    from certior_guard.profiles import get_profile, list_profiles
    from certior_guard.check import check      # policy soundness
    from certior_guard.verify import verify    # audit-log integrity + replay
"""
from __future__ import annotations

__version__ = "0.1.0"

from certior_guard.check import check
from certior_guard.engine import capability_for, decide, resolve
from certior_guard.profiles import get_profile, list_profiles
from certior_guard.verify import verify

__all__ = ["capability_for", "decide", "resolve", "get_profile", "list_profiles",
           "check", "verify", "__version__"]
