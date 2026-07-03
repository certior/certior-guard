# Certior Guard — Claude Code plugin

Safe defaults for Claude Code, installed from inside Claude Code. Every
`Bash` / `Edit` / `Read` / `WebFetch` / MCP call is checked before it runs —
secrets and dangerous commands are blocked, risky ones wait for approval, and
every decision is logged. Fails open.

## Install

```bash
pip install certior-guard                        # the hook calls the certior-guard CLI
```

Then, inside Claude Code:

```
/plugin marketplace add certior/certior-guard
/plugin install certior-guard@certior
```

Configure what you're protecting (once, at your repo root):

```bash
certior-guard init          # scans the repo, picks a profile, writes certior.yml
```

That's it. `/plugin list` to confirm, `/plugin disable certior-guard` to pause.

## Local testing (before publishing)

```bash
claude --plugin-dir ./plugin
```

## What it enforces

Set by `certior.yml` (`personal` / `team` / `production` / `regulated`, in
`observe` / `ask` / `enforce` mode). See the [main README](../README.md) for the
full table. Change rules any time by editing `certior.yml` — no restart.
