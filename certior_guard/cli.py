"""``certior-guard`` — safe defaults for Claude Code.

    certior-guard init          scan the repo, pick a profile, wire the hook
    certior-guard hook          PreToolUse entrypoint (wired by init)
    certior-guard log           show recent decisions
    certior-guard status        show the active profile/mode
    certior-guard uninstall     remove the hook wiring
    certior-guard test          dry-run a tool call against the active policy
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List

from certior_guard.config import load_config
from certior_guard.profiles import PROFILES, get_profile


def _cmd_init(args) -> int:
    from certior_guard.init_wizard import run_init
    return run_init(profile=args.profile, mode=args.mode, scope=args.scope, yes=args.yes)


def _cmd_hook(args) -> int:
    from certior_guard.hook import run_hook
    return run_hook(profile_key=args.profile, mode=args.mode)


def _cmd_status(_args) -> int:
    cfg = load_config()
    prof = get_profile(cfg["profile"])
    print(f"profile:   {cfg['profile']}  ({prof.name if prof else '?'})")
    print(f"mode:      {cfg['mode']}")
    print(f"audit dir: {cfg['audit_dir']}")
    if prof:
        print(f"\n{prof.tagline}")
    return 0


def _cmd_log(args) -> int:
    from certior_guard.receipts import read_recent
    cfg = load_config()
    rows = read_recent(cfg["audit_dir"], limit=args.n)
    if not rows:
        print(f"No receipts yet in {cfg['audit_dir']}/ — run Claude Code to generate some.")
        return 0
    icon = {"deny": "⛔", "ask": "✋", "allow": "✓"}
    for r in rows:
        d = str(r.get("decision", "?"))
        tgt = str(r.get("target", ""))[:60]
        print(f"{icon.get(d, '·')} {r.get('timestamp','')}  {d:5} {r.get('tool',''):10} "
              f"{r.get('capability',''):18} {tgt}")
    return 0


def _cmd_uninstall(args) -> int:
    path = os.path.join(os.path.expanduser("~/.claude") if args.scope == "user" else ".claude",
                        "settings.json")
    if not os.path.exists(path):
        print("Nothing to remove.")
        return 0
    with open(path, encoding="utf-8") as fh:
        settings = json.load(fh)
    pre = settings.get("hooks", {}).get("PreToolUse", [])
    settings.setdefault("hooks", {})["PreToolUse"] = [
        h for h in pre if "certior-guard hook" not in json.dumps(h)
    ]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(settings, fh, indent=2)
    print(f"✓ Certior hook removed from {path}. (certior.yml and receipts left in place.)")
    return 0


def _cmd_test(args) -> int:
    """Dry-run a tool call against the active policy — no Claude Code needed."""
    from certior_guard.engine import decide
    cfg = load_config()
    prof = get_profile(cfg["profile"])
    if prof is None:
        print("No valid profile configured.")
        return 2
    tool_input = {}
    if args.tool == "Bash":
        tool_input = {"command": args.arg}
    elif args.tool in ("Read", "Edit", "Write"):
        tool_input = {"file_path": args.arg}
    elif args.tool in ("WebFetch", "WebSearch"):
        tool_input = {"url": args.arg}
    else:
        tool_input = {"command": args.arg, "file_path": args.arg, "url": args.arg}
    d = decide(args.tool, tool_input, prof, cfg["mode"])
    icon = {"deny": "⛔ DENY", "ask": "✋ ASK", "allow": "✓ ALLOW"}
    print(f"{icon.get(d['decision'], d['decision'])}   [{cfg['profile']} · {cfg['mode']}]")
    print(f"  capability: {d.get('capability','')}")
    if d.get("reason"):
        print(f"  reason:     {d['reason']}")
    return 0


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="certior-guard",
        description="Safe defaults for Claude Code: block secrets & dangerous commands, "
                    "ask before deploys/migrations, log every decision.",
    )
    sub = p.add_subparsers(dest="command")

    p_init = sub.add_parser("init", help="Scan the repo, pick a profile, wire the Claude Code hook.")
    p_init.add_argument("--profile", choices=list(PROFILES), help="skip the question")
    p_init.add_argument("--mode", choices=["observe", "ask", "enforce"], help="skip the question")
    p_init.add_argument("--scope", choices=["project", "user"], default="project",
                        help="wire into ./.claude (project) or ~/.claude (all repos)")
    p_init.add_argument("--yes", "-y", action="store_true", help="accept recommended defaults")
    p_init.set_defaults(func=_cmd_init)

    p_hook = sub.add_parser("hook", help="PreToolUse entrypoint (wired by init).")
    p_hook.add_argument("--profile", default=None, help="override certior.yml")
    p_hook.add_argument("--mode", default=None, choices=["observe", "ask", "enforce"])
    p_hook.set_defaults(func=_cmd_hook)

    sub.add_parser("status", help="Show the active profile and mode.").set_defaults(func=_cmd_status)

    p_log = sub.add_parser("log", help="Show recent decisions (receipts).")
    p_log.add_argument("-n", type=int, default=20, help="how many to show")
    p_log.set_defaults(func=_cmd_log)

    p_un = sub.add_parser("uninstall", help="Remove the Claude Code hook wiring.")
    p_un.add_argument("--scope", choices=["project", "user"], default="project")
    p_un.set_defaults(func=_cmd_uninstall)

    p_test = sub.add_parser("test", help="Dry-run a tool call against the active policy.")
    p_test.add_argument("tool", help="Bash | Read | Edit | Write | WebFetch")
    p_test.add_argument("arg", help="the command / file path / url")
    p_test.set_defaults(func=_cmd_test)

    args = p.parse_args(argv)
    if not getattr(args, "command", None):
        p.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
