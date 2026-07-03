'use strict';
// PreToolUse hook: read a tool-call envelope on stdin, decide it against the
// configured profile+mode, write a receipt, and emit the decision on stdout.
// Fail-open: any error exits 0 so a Certior fault never blocks normal work.
const fs = require('fs');
const { loadConfig } = require('./config');
const { decide } = require('./engine');
const { getProfile } = require('./profiles');
const { policyHash, writeReceipt } = require('./receipts');

function readStdin() {
  try { return fs.readFileSync(0, 'utf8'); } catch { return ''; }
}

function runHook(profileKey = null, mode = null, input = null) {
  let envelope;
  try { envelope = JSON.parse(input != null ? input : readStdin()); } catch { return 0; }

  const cfg = loadConfig();
  const profile = getProfile(profileKey || cfg.profile) || getProfile(cfg.profile);
  const activeMode = mode || cfg.mode;
  if (!profile) return 0;

  const toolName = envelope.tool_name || '';
  const toolInput = envelope.tool_input || {};

  let d;
  try { d = decide(toolName, toolInput, profile, activeMode); } catch { return 0; }

  try {
    const target = toolInput.command || toolInput.file_path || toolInput.url || toolInput.query || '';
    writeReceipt({
      auditDir: cfg.auditDir,
      tool: toolName,
      target: String(target),
      decision: d.decision,
      would: d.would || d.decision,
      capability: d.capability || '',
      reason: d.reason || '',
      profileKey: profile.key,
      mode: activeMode,
      policyHash: policyHash(profile.toDict(), activeMode),
      sessionId: String(envelope.session_id || ''),
    });
  } catch { /* best-effort */ }

  if (d.decision === 'allow') {
    if (activeMode === 'observe' && (d.would === 'deny' || d.would === 'ask') && d.reason) {
      process.stderr.write('certior: ' + d.reason + '\n');
    }
    return 0;
  }

  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: d.decision, // "deny" | "ask"
      permissionDecisionReason: d.reason,
    },
  }));
  return 0;
}

module.exports = { runHook };
