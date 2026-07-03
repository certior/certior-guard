'use strict';
// Map a Claude Code tool call to capabilities, then decide against a profile.
// capabilityFor turns a PreToolUse envelope into candidate capability strings;
// resolve matches them against a profile under the active mode, returning
// allow / ask / deny with a reason.
const { SECRET_PATH } = require('./patterns');
const { alwaysDenied } = require('./profiles');
const { shellCapabilities } = require('./shellParse');

const PROD_PATH = /(^|\/)(prod|production|infra|terraform|k8s|kubernetes|helm)(\/|$)|(^|\/)(Dockerfile|docker-compose\.ya?ml)$/i;
const MIGRATION_PATH = /(^|\/)(migrations?)(\/|$)|\/migrate\//i;
const AUTH_PATH = /(^|\/)(auth|permissions?|security|crypto)(\/|$)/i;
const BILLING_PATH = /(^|\/)(billing|payments?|stripe)(\/|$)/i;
const CI_PATH = /(^|\/)\.github\/workflows\/|(^|\/)\.gitlab-ci\.ya?ml$|(^|\/)\.circleci\//i;

function writeCapsForPath(path) {
  if (SECRET_PATH.test(path)) return ['secrets:write', 'files:write'];
  if (MIGRATION_PATH.test(path)) return ['migrations:write', 'files:write'];
  if (CI_PATH.test(path)) return ['ci:write', 'files:write'];
  if (AUTH_PATH.test(path)) return ['auth:write', 'files:write'];
  if (BILLING_PATH.test(path)) return ['billing:write', 'files:write'];
  if (PROD_PATH.test(path)) return ['prod:write', 'files:write'];
  return ['files:write'];
}

// Returns [capabilityCandidates, preview].
function capabilityFor(toolName, toolInput) {
  const ti = toolInput || {};

  if (toolName.startsWith('mcp__')) {
    const tool = toolName.split('__').slice(2).join('__').toLowerCase() || toolName.toLowerCase();
    if (/delete|remove|drop|destroy/.test(tool)) return [['mcp:delete', `mcp:${tool}`], toolName];
    if (/send|email|post|publish|transfer|pay/.test(tool)) return [['mcp:send', `mcp:${tool}`], toolName];
    if (/write|create|update|edit|set/.test(tool)) return [['mcp:write', `mcp:${tool}`], toolName];
    return [['mcp:read', `mcp:${tool}`], toolName];
  }

  if (['Edit', 'Write', 'MultiEdit', 'NotebookEdit'].includes(toolName)) {
    const path = String(ti.file_path || '');
    const content = ti.new_string || ti.file_text || ti.content || '';
    return [writeCapsForPath(path), String(content).slice(0, 4000)];
  }

  if (toolName === 'Read') {
    const path = String(ti.file_path || '');
    return [SECRET_PATH.test(path) ? ['secrets:read'] : ['files:read'], path];
  }

  if (toolName === 'WebFetch' || toolName === 'WebSearch') {
    return [['network:http:read'], String(ti.url || ti.query || '')];
  }

  if (toolName === 'Bash') {
    const cmd = String(ti.command || '');
    const caps = shellCapabilities(cmd);
    if (caps && caps.length) return [caps, cmd];
    return [['shell:exec'], cmd]; // parsed clean OR unparseable → opaque exec
  }

  return [[`tool:${toolName.toLowerCase()}`], JSON.stringify(ti).slice(0, 2000)];
}

function decide(toolName, toolInput, profile, mode) {
  const [caps] = capabilityFor(toolName, toolInput);
  return resolve(caps, profile, mode);
}

// Resolve capability candidates against a profile+mode → {decision, reason,
// capability, would}. `would` is the mode-independent verdict, so observe can
// report a would-be block. Shared by the hook and check.
function resolve(caps, profile, mode) {
  const blocked = caps.find((c) => profile.blocks(c));
  const asked = caps.find((c) => profile.asks(c));
  const floor = caps.find((c) => alwaysDenied(c));

  let would;
  let cap;
  if (blocked || floor) { would = 'deny'; cap = floor || blocked; } else if (asked) { would = 'ask'; cap = asked; } else {
    return { decision: 'allow', would: 'allow', capability: caps[0] || '?', reason: '' };
  }

  const pname = profile.name;

  if (mode === 'observe') {
    const verb = would === 'deny' ? 'blocked' : 'held for approval';
    return { decision: 'allow', would, capability: cap, reason: `[observe] would have ${verb} '${cap}' (${pname}).` };
  }

  if (mode === 'ask') {
    if (floor) {
      return { decision: 'deny', would: 'deny', capability: floor, reason: `Certior · ${pname}: '${floor}' is never allowed for an agent.` };
    }
    return { decision: 'ask', would, capability: cap, reason: `Certior · ${pname}: '${cap}' is risky — approve before it runs.` };
  }

  if (would === 'deny') {
    return { decision: 'deny', would: 'deny', capability: cap, reason: `Certior · ${pname}: '${cap}' is outside this boundary.` };
  }
  return { decision: 'ask', would: 'ask', capability: cap, reason: `Certior · ${pname}: '${cap}' is high-stakes — approve before it runs.` };
}

module.exports = { capabilityFor, decide, resolve };
