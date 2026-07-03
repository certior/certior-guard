"""Certior Guard — safe defaults for Claude Code in real repositories.

Block secrets and dangerous commands, ask before deploys/migrations, and log
every decision. A single PreToolUse hook, zero dependencies, install in two
minutes.

    certior-guard init

The public surface:

    from certior_guard.engine import capability_for, decide
    from certior_guard.profiles import get_profile, list_profiles
"""
from __future__ import annotations

__version__ = "0.1.0"

from certior_guard.engine import capability_for, decide
from certior_guard.profiles import get_profile, list_profiles

__all__ = ["capability_for", "decide", "get_profile", "list_profiles", "__version__"]
