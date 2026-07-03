"""Static policy analysis over the closed capability vocabulary.

Because the capability set is finite and known (:mod:`certior_guard.capabilities`)
and rules are globs over it, useful properties can be decided by exhaustive
enumeration — no solver required:

**Floor domination** (the safety invariant) — for every known capability on the
always-deny floor, and every profile in every enforcing mode (``ask``/``enforce``),
the resolved decision is ``deny``. This proves no profile or mode can open a hole
in the floor: secrets, disk wipes, remote-code-exec and exfiltration stay blocked.

**Dead rules** — a profile pattern that matches no known capability (a typo or an
aspirational rule with no emitter yet).

**Shadowed asks** — an ``ask`` pattern whose every matching capability is already
blocked, so it can never actually prompt.

This is an honest finite-model check, not a general SMT proof — but over this
vocabulary it is complete for the properties above.
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
