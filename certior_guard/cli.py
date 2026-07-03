"""``certior-guard`` — safe defaults for Claude Code.

    certior-guard init          scan the repo, pick a profile, wire the hook
    certior-guard hook          PreToolUse entrypoint (wired by init)
    certior-guard demo          show the block moments (no setup needed)
    certior-guard log           show recent decisions
    certior-guard verify        prove the audit log is intact and faithful
    certior-guard check         analyse the policy (floor invariant, dead rules)
    certior-guard status        show the active profile/mode
    certior-guard test          dry-run a tool call against the active policy
    certior-guard uninstall     remove the hook wiring
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
    from certior_guard.receipts import read_all, read_recent
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
    # Totals across the whole log, not just the shown page.
    allrows = read_all(cfg["audit_dir"])
    n = {"deny": 0, "ask": 0, "allow": 0}
    for r in allrows:
        n[str(r.get("decision"))] = n.get(str(r.get("decision")), 0) + 1
    print(f"\n{len(allrows)} decisions logged · "
          f"⛔ {n['deny']} blocked · ✋ {n['ask']} held · ✓ {n['allow']} allowed")
    return 0


def _cmd_demo(args) -> int:
    from certior_guard.demo import run_demo
    return run_demo(profile_key=args.profile, mode=args.mode)


def _cmd_verify(args) -> int:
    from certior_guard.verify import verify
    cfg = load_config()
    rep = verify(cfg["audit_dir"])
    if rep["total"] == 0:
        print(f"No receipts to verify in {cfg['audit_dir']}/.")
        return 0
    if rep["integrity_ok"]:
        print(f"✓ integrity: {rep['chained']} receipts, hash chain intact (no edits or deletions)")
    else:
        print(f"⛔ integrity: chain BROKEN at seq {rep['break_at']} — {rep['break_reason']}")
    if rep["drift"]:
        print(f"⚠ faithfulness: {len(rep['drift'])}/{rep['replayed']} decisions differ from the current policy:")
        for dft in rep["drift"][:10]:
            print(f"    seq {dft['seq']}  {dft['tool']} {str(dft['target'])[:40]}  "
                  f"{dft['recorded']} → {dft['now']}")
    else:
        print(f"✓ faithfulness: {rep['replayed']} decisions replay identically under the current policy")
    return 0 if rep["ok"] else 1


def _cmd_check(args) -> int:
    from certior_guard.check import check
    rep = check()
    if rep["floor_ok"]:
        print(f"✓ always-deny floor holds: {rep['checks']} checks "
              f"({rep['floor_size']} capabilities × profiles × modes) — no override path")
    else:
        print(f"⛔ FLOOR VIOLATION — {len(rep['violations'])} case(s) where a floor capability is not denied:")
        for v in rep["violations"][:10]:
            print(f"    {v['profile']} · {v['mode']} · {v['capability']}")
    for p in rep["profiles"]:
        notes = []
        if p["dead_rules"]:
            notes.append("dead rules: " + ", ".join(p["dead_rules"]))
        if p["shadowed_asks"]:
            notes.append("shadowed asks: " + ", ".join(p["shadowed_asks"]))
        if notes:
            print(f"  {p['profile']}: " + " · ".join(notes))
    return 0 if rep["floor_ok"] else 1


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

    p_demo = sub.add_parser("demo", help="Show the block moments (no setup needed).")
    p_demo.add_argument("--profile", default="team", choices=list(PROFILES))
    p_demo.add_argument("--mode", default="enforce", choices=["observe", "ask", "enforce"])
    p_demo.set_defaults(func=_cmd_demo)

    p_log = sub.add_parser("log", help="Show recent decisions (receipts).")
    p_log.add_argument("-n", type=int, default=20, help="how many to show")
    p_log.set_defaults(func=_cmd_log)

    sub.add_parser(
        "verify", help="Prove the audit log is intact (hash chain) and faithful (replay)."
    ).set_defaults(func=_cmd_verify)

    sub.add_parser(
        "check", help="Analyse the policy: floor invariant, dead & shadowed rules."
    ).set_defaults(func=_cmd_check)

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
