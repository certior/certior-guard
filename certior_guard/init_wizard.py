"""``certior-guard init`` — the two-minute setup.

Scans the repo, recommends a profile, asks at most two questions, then writes:

    certior.yml                 the choice (profile + mode)
    .claude/settings.json       the PreToolUse hook wiring (merged, idempotent)
    .certior/audit/             where receipts land

Non-interactive (``--yes`` or no TTY) takes the recommended defaults so it works
in CI and scripted installs.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Optional

from certior_guard.config import DEFAULT_AUDIT_DIR, write_config
from certior_guard.detect import detect
from certior_guard.profiles import PROFILES, get_profile

HOOK_MATCHER = "Bash|Edit|Write|MultiEdit|NotebookEdit|Read|WebFetch|WebSearch|mcp__.*"
HOOK_COMMAND = "certior-guard hook"


def _prompt(question: str, options, default_key: str) -> str:
    """Numbered menu; empty input takes the default. Options: [(key, label)]."""
    print("\n" + question)
    for i, (key, label) in enumerate(options, 1):
        marker = " (recommended)" if key == default_key else ""
        print(f"  {i}. {label}{marker}")
    default_idx = next((i for i, (k, _) in enumerate(options, 1) if k == default_key), 1)
    try:
        raw = input(f"Choose [1-{len(options)}] ({default_idx}): ").strip()
    except EOFError:
        raw = ""
    if not raw:
        return default_key
    if raw.isdigit() and 1 <= int(raw) <= len(options):
        return options[int(raw) - 1][0]
    # allow typing the key directly
    for key, _ in options:
        if raw.lower() == key:
            return key
    return default_key


def _wire_hook(scope: str) -> str:
    scope_dir = os.path.expanduser("~/.claude") if scope == "user" else ".claude"
    os.makedirs(scope_dir, exist_ok=True)
    path = os.path.join(scope_dir, "settings.json")
    settings = {}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                settings = json.load(fh)
        except Exception:
            settings = {}
    hooks = settings.setdefault("hooks", {})
    pre = hooks.get("PreToolUse", [])
    # Drop any prior Certior entry so re-running init is idempotent.
    pre = [h for h in pre if HOOK_COMMAND not in json.dumps(h)]
    pre.append({
        "matcher": HOOK_MATCHER,
        "hooks": [{"type": "command", "command": HOOK_COMMAND, "timeout": 15}],
    })
    hooks["PreToolUse"] = pre
    settings["hooks"] = hooks
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(settings, fh, indent=2)
    return path


def run_init(
    profile: Optional[str] = None,
    mode: Optional[str] = None,
    scope: str = "project",
    yes: bool = False,
    root: str = ".",
) -> int:
    info = detect(root)
    interactive = sys.stdin.isatty() and not yes

    print("Certior Guard — safe defaults for Claude Code\n" + "─" * 44)
    if info["detected"]:
        print("Scanned this repo, detected:")
        for label in info["detected"]:
            print(f"  • {label}")
    else:
        print("Scanned this repo (no notable frameworks detected).")

    # 1) What are you protecting?
    chosen_profile = profile
    if chosen_profile is None:
        default_p = str(info["recommended"])
        if interactive:
            chosen_profile = _prompt(
                "What are you protecting?",
                [(p.key, f"{p.name} — {p.tagline.split('.')[0]}") for p in PROFILES.values()],
                default_p,
            )
        else:
            chosen_profile = default_p
    prof = get_profile(chosen_profile)
    if prof is None:
        print(f"Unknown profile '{chosen_profile}'. Choose from: {', '.join(PROFILES)}")
        return 2

    # 2) Mode
    chosen_mode = mode
    if chosen_mode is None:
        default_m = prof.default_mode
        if interactive:
            chosen_mode = _prompt(
                "How strict should it be?",
                [("observe", "Observe — log what would be blocked, never interrupt"),
                 ("ask", "Ask — approve risky actions in the terminal"),
                 ("enforce", "Enforce — block forbidden actions outright")],
                default_m,
            )
        else:
            chosen_mode = default_m

    # Write everything.
    cfg_path = write_config(prof.key, chosen_mode, DEFAULT_AUDIT_DIR)
    os.makedirs(DEFAULT_AUDIT_DIR, exist_ok=True)
    settings_path = _wire_hook(scope)

    print("\n" + "─" * 44)
    print(f"✓ Certior Guard installed — protecting a {prof.name.lower()} in {chosen_mode} mode.")
    print(f"  wrote {cfg_path}")
    print(f"  wrote {settings_path}")
    print(f"  receipts → {DEFAULT_AUDIT_DIR}/")
    print("\nProtected now:")
    print("  • secrets (.env, keys, credentials)   • destructive shell (rm -rf, dd, curl|bash)")
    if info["has_deploy"]:
        print("  • production deploys (terraform/kubectl/vercel …) require approval")
    if info["has_migrations"]:
        print("  • database migrations require approval")
    print("\nRun Claude Code as usual. Try it:")
    print('  ask Claude to "show me the .env file" → Certior blocks it, receipt saved.')
    print("  see decisions:  certior-guard log")
    print("  change rules:   edit certior.yml   ·   remove:  certior-guard uninstall")
    return 0
