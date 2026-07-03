'use strict';
// certior-guard — safe defaults for Claude Code.
//   init | hook | demo | log | verify | check | status | test | uninstall
const fs = require('fs');
const path = require('path');
const os = require('os');
const { loadConfig } = require('./config');
const { getProfile, PROFILES } = require('./profiles');
const { red, green, yellow, cyan, dim, bold } = require('./colors');

function parseFlags(args) {
  const flags = {};
  const pos = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--yes' || a === '-y') flags.yes = true;
    else if (a.startsWith('--')) {
      const key = a.slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) { flags[key] = args[++i]; } else flags[key] = true;
    } else pos.push(a);
  }
  return { flags, pos };
}

function cmdStatus() {
  const cfg = loadConfig();
  const prof = getProfile(cfg.profile);
  console.log(`profile:   ${cfg.profile}  (${prof ? prof.name : '?'})`);
  console.log(`mode:      ${cfg.mode}`);
  console.log(`audit dir: ${cfg.auditDir}`);
  if (prof) console.log(`\n${prof.tagline}`);
  return 0;
}

function cmdLog(flags) {
  const { readAll, readRecent } = require('./receipts');
  const cfg = loadConfig();
  const n = Number(flags.n) || 20;
  const rows = readRecent(cfg.auditDir, n);
  if (!rows.length) { console.log(`No receipts yet in ${cfg.auditDir}/ — run Claude Code to generate some.`); return 0; }
  const icon = { deny: red('deny '), ask: yellow('ask  '), allow: green('allow') };
  for (const r of rows) {
    const d = String(r.decision || '?');
    const tgt = String(r.target || '').slice(0, 60);
    console.log(`${icon[d] || d}  ${r.timestamp || ''}  ${String(r.tool || '').padEnd(10)} ${String(r.capability || '').padEnd(18)} ${tgt}`);
  }
  const all = readAll(cfg.auditDir);
  const c = { deny: 0, ask: 0, allow: 0 };
  for (const r of all) c[r.decision] = (c[r.decision] || 0) + 1;
  console.log(`\n${all.length} decisions logged · ${red(c.deny + ' blocked')} · ${yellow(c.ask + ' held')} · ${green(c.allow + ' allowed')}`);
  return 0;
}

function cmdUninstall(flags) {
  const p = path.join(flags.scope === 'user' ? path.join(os.homedir(), '.claude') : '.claude', 'settings.json');
  if (!fs.existsSync(p)) { console.log('Nothing to remove.'); return 0; }
  const settings = JSON.parse(fs.readFileSync(p, 'utf8'));
  const pre = (settings.hooks && settings.hooks.PreToolUse) || [];
  settings.hooks = settings.hooks || {};
  settings.hooks.PreToolUse = pre.filter((h) => !JSON.stringify(h).includes('certior-guard hook'));
  fs.writeFileSync(p, JSON.stringify(settings, null, 2));
  console.log(`✓ Certior hook removed from ${p}. (certior.yml and receipts left in place.)`);
  return 0;
}

function cmdTest(pos) {
  const { decide } = require('./engine');
  const cfg = loadConfig();
  const prof = getProfile(cfg.profile);
  if (!prof) { console.log('No valid profile configured.'); return 2; }
  const [tool, arg] = [pos[0], pos.slice(1).join(' ')];
  let ti;
  if (tool === 'Bash') ti = { command: arg };
  else if (['Read', 'Edit', 'Write'].includes(tool)) ti = { file_path: arg };
  else if (['WebFetch', 'WebSearch'].includes(tool)) ti = { url: arg };
  else ti = { command: arg, file_path: arg, url: arg };
  const d = decide(tool, ti, prof, cfg.mode);
  const label = { deny: red(bold('⛔ DENY')), ask: yellow(bold('✋ ASK')), allow: green(bold('✓ ALLOW')) };
  console.log(`${label[d.decision] || d.decision}   [${cfg.profile} · ${cfg.mode}]`);
  console.log(`  capability: ${d.capability || ''}`);
  if (d.reason) console.log(`  reason:     ${d.reason}`);
  return 0;
}

function cmdVerify() {
  const { verify } = require('./verify');
  const cfg = loadConfig();
  const rep = verify(cfg.auditDir);
  if (rep.total === 0) { console.log(`No receipts to verify in ${cfg.auditDir}/.`); return 0; }
  if (rep.integrityOk) console.log(green('✓') + ` integrity: ${rep.chained} receipts, hash chain intact (no edits or deletions)`);
  else console.log(red('⛔') + ` integrity: chain BROKEN at seq ${rep.breakAt} — ${rep.breakReason}`);
  if (rep.drift.length) {
    console.log(yellow('⚠') + ` faithfulness: ${rep.drift.length}/${rep.replayed} decisions differ from the current policy:`);
    for (const d of rep.drift.slice(0, 10)) console.log(`    seq ${d.seq}  ${d.tool} ${String(d.target).slice(0, 40)}  ${d.recorded} → ${d.now}`);
  } else {
    console.log(green('✓') + ` faithfulness: ${rep.replayed} decisions replay identically under the current policy`);
  }
  return rep.ok ? 0 : 1;
}

function cmdCheck() {
  const { check } = require('./check');
  const rep = check();
  if (rep.floorOk) {
    console.log(green('✓') + ` always-deny floor holds: ${rep.checks} checks (${rep.floorSize} capabilities × profiles × modes) — no override path`);
  } else {
    console.log(red('⛔') + ` FLOOR VIOLATION — ${rep.violations.length} case(s) where a floor capability is not denied:`);
    for (const v of rep.violations.slice(0, 10)) console.log(`    ${v.profile} · ${v.mode} · ${v.capability}`);
  }
  for (const p of rep.profiles) {
    const notes = [];
    if (p.deadRules.length) notes.push('dead rules: ' + p.deadRules.join(', '));
    if (p.shadowedAsks.length) notes.push('shadowed asks: ' + p.shadowedAsks.join(', '));
    if (notes.length) console.log(`  ${p.profile}: ` + notes.join(' · '));
  }
  return rep.floorOk ? 0 : 1;
}

function help() {
  console.log(`certior-guard — safe defaults for Claude Code

  ${bold('certior-guard init')}          scan the repo, pick a profile, wire the hook
  ${bold('certior-guard demo')}          show the block moments (no setup needed)
  ${bold('certior-guard status')}        show the active profile/mode
  ${bold('certior-guard log')}           recent decisions + totals
  ${bold('certior-guard verify')}        prove the audit log is intact & faithful
  ${bold('certior-guard check')}         analyse the policy (floor invariant, dead rules)
  ${bold('certior-guard test')} <tool> <arg>   dry-run a call against the policy
  ${bold('certior-guard hook')}          PreToolUse entrypoint (wired by init)
  ${bold('certior-guard uninstall')}     remove the hook wiring`);
}

async function main(argv) {
  const [command, ...rest] = argv;
  const { flags, pos } = parseFlags(rest);
  switch (command) {
    case 'init': {
      const { runInit } = require('./initWizard');
      return runInit({ profile: flags.profile, mode: flags.mode, scope: flags.scope || 'project', yes: !!flags.yes });
    }
    case 'hook': {
      const { runHook } = require('./hook');
      return runHook(flags.profile || null, flags.mode || null);
    }
    case 'demo': {
      const { runDemo } = require('./demo');
      return runDemo(flags.profile || 'team', flags.mode || 'enforce');
    }
    case 'status': return cmdStatus();
    case 'log': return cmdLog(flags);
    case 'verify': return cmdVerify();
    case 'check': return cmdCheck();
    case 'test': return cmdTest(pos);
    case 'uninstall': return cmdUninstall(flags);
    case undefined: case '-h': case '--help': case 'help': help(); return 0;
    default: console.error(`unknown command '${command}'. Try: certior-guard --help`); return 2;
  }
}

module.exports = { main, PROFILES };
