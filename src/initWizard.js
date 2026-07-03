'use strict';
// `certior-guard init` — the two-minute setup. Scans the repo, recommends a
// profile, asks at most two questions, then writes certior.yml, the PreToolUse
// hook wiring in .claude/settings.json (merged, idempotent), and .certior/audit/.
// Non-interactive (--yes or no TTY) takes the recommended defaults.
const fs = require('fs');
const path = require('path');
const os = require('os');
const readline = require('readline/promises');
const { DEFAULT_AUDIT_DIR, writeConfig } = require('./config');
const { detect } = require('./detect');
const { PROFILE_LIST, getProfile } = require('./profiles');

const HOOK_MATCHER = 'Bash|Edit|Write|MultiEdit|NotebookEdit|Read|WebFetch|WebSearch|mcp__.*';
const HOOK_COMMAND = 'certior-guard hook';

async function prompt(question, options, defaultKey) {
  process.stdout.write('\n' + question + '\n');
  options.forEach(([key, label], i) => {
    const mark = key === defaultKey ? ' (recommended)' : '';
    process.stdout.write(`  ${i + 1}. ${label}${mark}\n`);
  });
  const defaultIdx = options.findIndex(([k]) => k === defaultKey) + 1 || 1;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  let raw = '';
  try { raw = (await rl.question(`Choose [1-${options.length}] (${defaultIdx}): `)).trim(); } catch { /* EOF */ } finally { rl.close(); }
  if (!raw) return defaultKey;
  const num = Number(raw);
  if (Number.isInteger(num) && num >= 1 && num <= options.length) return options[num - 1][0];
  const byKey = options.find(([k]) => k === raw.toLowerCase());
  return byKey ? byKey[0] : defaultKey;
}

function wireHook(scope) {
  const scopeDir = scope === 'user' ? path.join(os.homedir(), '.claude') : '.claude';
  fs.mkdirSync(scopeDir, { recursive: true });
  const p = path.join(scopeDir, 'settings.json');
  let settings = {};
  if (fs.existsSync(p)) { try { settings = JSON.parse(fs.readFileSync(p, 'utf8')); } catch { settings = {}; } }
  const hooks = settings.hooks || (settings.hooks = {});
  let pre = hooks.PreToolUse || [];
  pre = pre.filter((h) => !JSON.stringify(h).includes(HOOK_COMMAND)); // idempotent re-init
  pre.push({ matcher: HOOK_MATCHER, hooks: [{ type: 'command', command: HOOK_COMMAND, timeout: 15 }] });
  hooks.PreToolUse = pre;
  fs.writeFileSync(p, JSON.stringify(settings, null, 2));
  return p;
}

async function runInit({ profile = null, mode = null, scope = 'project', yes = false, root = '.' } = {}) {
  const info = detect(root);
  const interactive = process.stdin.isTTY && !yes;

  console.log('Certior Guard — safe defaults for Claude Code\n' + '─'.repeat(44));
  if (info.detected.length) {
    console.log('Scanned this repo, detected:');
    for (const label of info.detected) console.log(`  • ${label}`);
  } else {
    console.log('Scanned this repo (no notable frameworks detected).');
  }

  let chosenProfile = profile;
  if (!chosenProfile) {
    chosenProfile = interactive
      ? await prompt('What are you protecting?',
        PROFILE_LIST.map((p) => [p.key, `${p.name} — ${p.tagline.split('.')[0]}`]), info.recommended)
      : info.recommended;
  }
  const prof = getProfile(chosenProfile);
  if (!prof) { console.log(`Unknown profile '${chosenProfile}'.`); return 2; }

  let chosenMode = mode;
  if (!chosenMode) {
    chosenMode = interactive
      ? await prompt('How strict should it be?', [
        ['observe', 'Observe — log what would be blocked, never interrupt'],
        ['ask', 'Ask — approve risky actions in the terminal'],
        ['enforce', 'Enforce — block forbidden actions outright'],
      ], prof.defaultMode)
      : prof.defaultMode;
  }

  const cfgPath = writeConfig(prof.key, chosenMode, DEFAULT_AUDIT_DIR);
  fs.mkdirSync(DEFAULT_AUDIT_DIR, { recursive: true });
  const settingsPath = wireHook(scope);

  console.log('\n' + '─'.repeat(44));
  console.log(`✓ Certior Guard installed — protecting a ${prof.name.toLowerCase()} in ${chosenMode} mode.`);
  console.log(`  wrote ${cfgPath}`);
  console.log(`  wrote ${settingsPath}`);
  console.log(`  receipts → ${DEFAULT_AUDIT_DIR}/`);
  console.log('\nProtected now:');
  console.log('  • secrets (.env, keys, credentials)   • destructive shell (rm -rf, dd, curl|bash)');
  if (info.hasDeploy) console.log('  • production deploys (terraform/kubectl/vercel …) require approval');
  if (info.hasMigrations) console.log('  • database migrations require approval');
  console.log('\nRun Claude Code as usual. Try it:');
  console.log('  ask Claude to "show me the .env file" → Certior blocks it, receipt saved.');
  console.log('  see decisions:  certior-guard log');
  console.log('  change rules:   edit certior.yml   ·   remove:  certior-guard uninstall');
  return 0;
}

module.exports = { runInit, HOOK_MATCHER, HOOK_COMMAND };
