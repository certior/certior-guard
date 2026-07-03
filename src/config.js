'use strict';
// Read/write certior.yml — the one file that holds the user's choice. Parsed
// with a tiny hand-rolled reader (no YAML dependency); anything outside the
// expected shape falls back to defaults rather than erroring.
const fs = require('fs');
const path = require('path');
const { DEFAULT_PROFILE, PROFILES, getProfile } = require('./profiles');

const CONFIG_NAME = 'certior.yml';
const DEFAULT_AUDIT_DIR = path.join('.certior', 'audit');

function defaultConfig() {
  const prof = PROFILES[DEFAULT_PROFILE];
  return { profile: prof.key, mode: prof.defaultMode, auditDir: DEFAULT_AUDIT_DIR };
}

function findConfig(start = '.') {
  let cur = path.resolve(start);
  for (;;) {
    const candidate = path.join(cur, CONFIG_NAME);
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(cur);
    if (parent === cur) return '';
    cur = parent;
  }
}

function loadConfig(start = '.') {
  const cfg = defaultConfig();
  const cfgPath = findConfig(start);
  if (!cfgPath) return cfg;
  let lines;
  try { lines = fs.readFileSync(cfgPath, 'utf8').split('\n'); } catch { return cfg; }

  let inAudit = false;
  for (const raw of lines) {
    const line = raw.replace(/\r$/, '');
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const indented = line[0] === ' ' || line[0] === '\t';
    const stripped = line.trim();
    if (stripped === 'audit:' || stripped.replace(/:$/, '') === 'audit') { inAudit = true; continue; }
    if (!indented) inAudit = false;
    const idx = stripped.indexOf(':');
    if (idx === -1) continue;
    const key = stripped.slice(0, idx).trim();
    // strip an inline "# comment" set off by whitespace, then surrounding quotes
    let val = stripped.slice(idx + 1).split(/\s+#/)[0].trim().replace(/^["']|["']$/g, '');
    if (!val) continue;
    if (key === 'profile' && getProfile(val)) cfg.profile = val;
    else if (key === 'mode' && ['observe', 'ask', 'enforce'].includes(val)) cfg.mode = val;
    else if (key === 'dir' && inAudit) cfg.auditDir = val;
  }
  if (!path.isAbsolute(cfg.auditDir)) cfg.auditDir = path.join(path.dirname(cfgPath), cfg.auditDir);
  return cfg;
}

function writeConfig(profile, mode, auditDir = DEFAULT_AUDIT_DIR, outPath = CONFIG_NAME) {
  const prof = getProfile(profile);
  const tagline = prof ? prof.tagline : '';
  const text = ''
    + '# Certior Guard — safe defaults for Claude Code in this repo.\n'
    + '# Edit and save; changes take effect on the next tool call (no restart).\n'
    + `# ${tagline}\n\n`
    + `profile: ${profile}    # personal | team | production | regulated\n`
    + `mode: ${mode}          # observe (log only) | ask (approve risky) | enforce (block)\n`
    + 'audit:\n'
    + `  dir: ${auditDir}\n`;
  fs.writeFileSync(outPath, text);
  return outPath;
}

module.exports = { CONFIG_NAME, DEFAULT_AUDIT_DIR, defaultConfig, findConfig, loadConfig, writeConfig };
