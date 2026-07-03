'use strict';
// The closed capability vocabulary the guard reasons over. Every tool call
// reduces to one or more of these strings and every profile rule is a glob over
// them, so `check` can treat the set as a closed world: a rule matching nothing
// here is dead, and the always-deny floor can be shown to dominate by
// enumeration. The tag records where each is classified — file / net / shell /
// mcp / reserved (a later content/MCP layer, not the current heuristics).
const { fnmatch } = require('./glob');

const KNOWN_CAPABILITIES = {
  'files:read': ['file', 'read a normal file'],
  'files:write': ['file', 'write a normal file'],
  'secrets:read': ['file', 'read a secret file (.env, keys, credentials)'],
  'secrets:write': ['file', 'write a secret file'],
  'prod:write': ['file', 'edit prod/infra/Docker files'],
  'migrations:write': ['file', 'edit a database migration'],
  'ci:write': ['file', 'edit CI/CD workflows'],
  'auth:write': ['file', 'edit auth/permissions/crypto code'],
  'billing:write': ['file', 'edit billing/payments code'],
  'network:http:read': ['net', 'fetch a URL / web search'],
  'shell:exec': ['shell', 'run an ordinary shell command'],
  'code:exec': ['shell', 'fetch-and-run remote code (curl | sh)'],
  'remote:exfiltrate': ['shell', 'send data to a remote host'],
  'data:exfiltrate': ['shell', 'upload/transfer data off the machine'],
  'fs:destroy': ['shell', 'wipe a disk/device (dd, mkfs, shred)'],
  'fs:delete': ['shell', 'recursive/forced delete (rm -rf)'],
  'db:destroy': ['shell', 'drop/truncate a database'],
  'git:push': ['shell', 'push commits'],
  'git:merge': ['shell', 'merge branches'],
  'prod:deploy': ['shell', 'deploy (terraform/kubectl/vercel …)'],
  'package:publish': ['shell', 'publish a package/release'],
  'deps:install': ['shell', 'install a dependency (supply-chain surface)'],
  'mcp:read': ['mcp', 'read via an MCP tool'],
  'mcp:write': ['mcp', 'write via an MCP tool'],
  'mcp:send': ['mcp', 'send/publish via an MCP tool'],
  'mcp:delete': ['mcp', 'delete via an MCP tool'],
  'phi:read': ['reserved', 'read protected health information'],
  'phi:export': ['reserved', 'export protected health information'],
  'data:export': ['reserved', 'export customer/regulated data'],
};

// Open-ended families the engine may emit with a variable suffix.
const CAPABILITY_FAMILIES = ['mcp:', 'tool:'];

function isKnown(cap) {
  return cap in KNOWN_CAPABILITIES || CAPABILITY_FAMILIES.some((f) => cap.startsWith(f));
}

function knownMatching(pattern) {
  return Object.keys(KNOWN_CAPABILITIES).filter((c) => fnmatch(c, pattern));
}

module.exports = { KNOWN_CAPABILITIES, CAPABILITY_FAMILIES, isKnown, knownMatching };
