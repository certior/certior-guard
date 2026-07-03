#!/usr/bin/env python3
"""Self-contained PreToolUse hook entry for the Certior Guard plugin.

Claude Code runs this on every matched tool call. It does *not* install plugin
dependencies, and the ``certior-guard`` pip package may not be present — so this
entry puts the plugin's own bundled copy of the engine on ``sys.path`` and calls
it directly. Pure stdlib, zero third-party deps.

``${CLAUDE_PLUGIN_ROOT}`` is the plugin's install directory (set by Claude Code);
we fall back to this file's repo root for local runs (``claude --plugin-dir .``).
"""
import os
import sys

_root = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)
if _root not in sys.path:
    sys.path.insert(0, _root)

from certior_guard.hook import run_hook  # noqa: E402

if __name__ == "__main__":
    sys.exit(run_hook())
