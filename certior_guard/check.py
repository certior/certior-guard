"""Policy analysis over the closed capability vocabulary.

The capability set is finite and rules are globs over it, so these are decided by
exhaustive enumeration, no solver:
  - floor domination — every always-deny capability resolves to ``deny`` under
    every profile and enforcing mode (the safety invariant);
  - dead rules — a pattern matching no known capability;
  - shadowed asks — an ``ask`` pattern whose matches are all already blocked.
A finite-model check, not an SMT proof, but complete over this vocabulary.
"""
from __future__ import annotations

from typing import Any, Dict, List

from certior_guard.capabilities import KNOWN_CAPABILITIES, known_matching
from certior_guard.engine import resolve
from certior_guard.profiles import ALWAYS_DENY, always_denied, list_profiles

ENFORCING_MODES = ("ask", "enforce")


def check() -> Dict[str, Any]:
    """Run every check across all built-in profiles; return a structured report."""
    caps = list(KNOWN_CAPABILITIES)
    floor = [c for c in caps if always_denied(c)]

    # Floor domination: exhaustive over floor caps × profiles × enforcing modes.
    violations: List[Dict[str, str]] = []
    checks = 0
    for prof in list_profiles():
        for mode in ENFORCING_MODES:
            for cap in floor:
                checks += 1
                if resolve([cap], prof, mode)["decision"] != "deny":
                    violations.append({"profile": prof.key, "mode": mode, "capability": cap})

    profiles: List[Dict[str, Any]] = []
    for prof in list_profiles():
        dead: List[str] = []
        for pat in prof.block_patterns + prof.ask_patterns:
            if not known_matching(pat):
                dead.append(pat)
        shadowed = [pat for pat in prof.ask_patterns
                    if known_matching(pat)
                    and all(prof.blocks(c) for c in known_matching(pat))]
        profiles.append({"profile": prof.key, "dead_rules": dead, "shadowed_asks": shadowed})

    return {
        "floor_size": len(floor),
        "floor_patterns": list(ALWAYS_DENY),
        "checks": checks,
        "floor_ok": not violations,
        "violations": violations,
        "profiles": profiles,
    }
