'use strict';
// Local, tamper-evident audit receipts — one JSON object per line in
// .certior/audit/YYYY-MM-DD.jsonl. The log is a hash chain: each receipt carries
// seq, prev (the previous receipt's hash), and hash (SHA-256 over its own
// content). Altering or deleting any receipt breaks every later link, so
// `certior-guard verify` can prove the log is intact. Best-effort throughout:
// never throws into the hook.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const AUDIT_DIRNAME = path.join('.certior', 'audit');
const GENESIS = 'sha256:genesis';

// Deterministic JSON with recursively sorted keys, for stable hashing.
function stableStringify(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(stableStringify).join(',')}]`;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
}

function policyHash(profileDict, mode) {
  const blob = stableStringify({ profile: profileDict, mode });
  return 'sha256:' + crypto.createHash('sha256').update(blob).digest('hex').slice(0, 16);
}

// SHA-256 over a receipt's canonical content (every field except `hash`).
function receiptHash(receipt) {
  const content = { ...receipt };
  delete content.hash;
  return 'sha256:' + crypto.createHash('sha256').update(stableStringify(content)).digest('hex');
}

function nowIso() {
  return new Date().toISOString().replace(/\.\d+Z$/, 'Z');
}

function dayFiles(auditDir) {
  let entries;
  try { entries = fs.readdirSync(auditDir); } catch { return []; }
  return entries.filter((f) => f.endsWith('.jsonl')).sort().map((f) => path.join(auditDir, f));
}

// Best-effort exclusive lock via an O_EXCL lockfile; spins briefly, then proceeds.
function withLock(auditDir, fn) {
  const lockpath = path.join(auditDir, '.lock');
  let fd = -1;
  for (let attempt = 0; attempt < 50; attempt++) {
    try { fd = fs.openSync(lockpath, 'wx'); break; } catch { /* held — retry */ }
    const until = Date.now() + 5;
    while (Date.now() < until) { /* tiny spin */ }
  }
  try { return fn(); } finally {
    if (fd !== -1) { try { fs.closeSync(fd); } catch {} }
    try { fs.unlinkSync(lockpath); } catch {}
  }
}

// [seq, hash] of the last receipt in the chain, or [0, GENESIS].
function tail(auditDir) {
  const files = dayFiles(auditDir);
  for (let i = files.length - 1; i >= 0; i--) {
    let last = null;
    try {
      for (const line of fs.readFileSync(files[i], 'utf8').split('\n')) if (line.trim()) last = line;
    } catch { continue; }
    if (last) {
      try { const rec = JSON.parse(last); return [Number(rec.seq || 0), String(rec.hash || GENESIS)]; } catch { return [0, GENESIS]; }
    }
  }
  return [0, GENESIS];
}

function writeReceipt(opts) {
  try {
    const { auditDir } = opts;
    fs.mkdirSync(auditDir, { recursive: true });
    return withLock(auditDir, () => {
      const [prevSeq, prevHash] = tail(auditDir);
      const ts = nowIso();
      const receipt = {
        seq: prevSeq + 1,
        prev: prevHash,
        actor: 'claude-code',
        tool: opts.tool,
        target: String(opts.target || '').slice(0, 500),
        decision: opts.decision,
        would: opts.would,
        capability: opts.capability,
        reason: opts.reason,
        profile: opts.profileKey,
        mode: opts.mode,
        policy_hash: opts.policyHash,
        session_id: opts.sessionId || '',
        timestamp: ts,
        verifier: 'certior-guard',
      };
      receipt.hash = receiptHash(receipt);
      const file = path.join(auditDir, `${ts.slice(0, 10)}.jsonl`);
      fs.appendFileSync(file, JSON.stringify(receipt) + '\n');
      return file;
    });
  } catch { return null; }
}

function readAll(auditDir) {
  const rows = [];
  for (const file of dayFiles(auditDir)) {
    try {
      for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
        const t = line.trim();
        if (t) rows.push(JSON.parse(t));
      }
    } catch { /* skip unreadable/partial */ }
  }
  return rows;
}

function readRecent(auditDir, limit = 20) { return readAll(auditDir).slice(-limit); }

module.exports = {
  AUDIT_DIRNAME, GENESIS, stableStringify, policyHash, receiptHash,
  writeReceipt, readAll, readRecent,
};
