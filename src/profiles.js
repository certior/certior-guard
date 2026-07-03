'use strict';
// Boundary profiles — safe defaults keyed to what you're protecting. A profile
// expands into two tiers of glob rules over capability names: `block` (forbidden)
// and `ask` (risky, pause for a human). A mode sets how the block tier is
// enforced: observe (log only) / ask (pause; still hard-deny the floor) / enforce
// (hard-deny the block tier, pause on ask).
const { fnmatch } = require('./glob');

// The catastrophic, usually-irreversible floor: hard-denied even in ask mode.
const ALWAYS_DENY = [
  'secrets:read', 'secrets:write', 'secrets:*',
  'fs:destroy', '*:destroy',
  'code:exec', 'remote:exfiltrate', '*:exfiltrate',
];

const MODES = ['observe', 'ask', 'enforce'];

class Profile {
  constructor({ key, name, tagline, defaultMode, block, ask }) {
    this.key = key;
    this.name = name;
    this.tagline = tagline;
    this.defaultMode = defaultMode;
    this.blockPatterns = block;
    this.askPatterns = ask;
  }

  blocks(cap) { return this.blockPatterns.some((p) => fnmatch(cap, p)); }

  asks(cap) { return this.askPatterns.some((p) => fnmatch(cap, p)); }

  toDict() {
    return {
      key: this.key, name: this.name, tagline: this.tagline,
      default_mode: this.defaultMode,
      block_patterns: this.blockPatterns, ask_patterns: this.askPatterns,
    };
  }
}

function alwaysDenied(cap) {
  return ALWAYS_DENY.some((p) => fnmatch(cap, p));
}

// Building blocks, ordered least→most locked-down; each profile layers these.
const SECRETS = ['secrets:read', 'secrets:write'];
const DESTRUCTIVE = ['fs:destroy', 'db:destroy'];
const EXFIL = ['*:exfiltrate', 'remote:exfiltrate', 'code:exec'];
const DEPLOY = ['prod:deploy', 'prod:write', '*:deploy']; // for profiles that don't block prod:*
const PUBLISH = ['package:publish'];
const PUSH = ['git:push', 'git:merge'];
const DEL = ['fs:delete'];

const PROFILE_LIST = [
  new Profile({
    key: 'personal',
    name: 'Personal repo',
    tagline: 'Solo dev. Block secrets & destructive commands; ask before pushes, publishes and deploys.',
    defaultMode: 'ask',
    block: [...SECRETS, ...DESTRUCTIVE, ...EXFIL],
    ask: [...PUSH, ...DEL, ...PUBLISH, ...DEPLOY],
  }),
  new Profile({
    key: 'team',
    name: 'Startup / team repo',
    tagline: 'Block secrets & destructive commands; ask before deploys, migrations, '
      + 'auth/billing edits, CI/CD, dependency installs, and pushes.',
    defaultMode: 'ask',
    block: [...SECRETS, ...DESTRUCTIVE, ...EXFIL],
    ask: [...PUSH, ...DEL, ...PUBLISH,
      'prod:*', 'migrations:*', 'auth:write', 'billing:write', 'ci:write', 'deps:install'],
  }),
  new Profile({
    key: 'production',
    name: 'Production service',
    tagline: 'Enforce: prod deploys and infra edits are blocked outright; secret access, '
      + 'DB drops and exfiltration too. Ask before migrations, auth/billing & installs.',
    defaultMode: 'enforce',
    block: [...SECRETS, ...DESTRUCTIVE, ...EXFIL, 'prod:*'],
    ask: [...PUSH, ...DEL, ...PUBLISH,
      'migrations:*', 'auth:write', 'billing:write', 'ci:write', 'deps:install'],
  }),
  new Profile({
    key: 'regulated',
    name: 'Regulated (SOC2 / HIPAA)',
    tagline: 'Enforce with strong receipts. Block secrets, prod changes, data/PHI export '
      + 'and destructive DB ops; ask before access-control, billing & installs.',
    defaultMode: 'enforce',
    block: [...SECRETS, ...DESTRUCTIVE, ...EXFIL, 'prod:*', '*:export', 'phi:export', 'data:export'],
    ask: [...PUSH, ...DEL, ...PUBLISH,
      'migrations:*', 'auth:*', 'billing:*', 'ci:write', 'deps:install', 'phi:*'],
  }),
];

const PROFILES = Object.fromEntries(PROFILE_LIST.map((p) => [p.key, p]));
const DEFAULT_PROFILE = 'team';

function getProfile(key) { return PROFILES[key] || null; }
function listProfiles() { return PROFILE_LIST.slice(); }

module.exports = {
  Profile, ALWAYS_DENY, MODES, alwaysDenied,
  PROFILES, PROFILE_LIST, DEFAULT_PROFILE, getProfile, listProfiles,
};
