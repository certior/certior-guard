'use strict';
// Verify the audit log two independent ways. Integrity — recompute each receipt
// hash and confirm every `prev` links to the prior receipt; any altered,
// inserted, or deleted line breaks the chain at a named seq. Faithfulness —
// re-run each decision through the engine under its recorded profile+mode; a
// mismatch means the receipt no longer matches the policy.
const { decide } = require('./engine');
const { getProfile } = require('./profiles');
const { GENESIS, readAll, receiptHash } = require('./receipts');

function reconstructInput(tool, target) {
  if (tool === 'Bash') return { command: target };
  if (['Read', 'Edit', 'Write', 'MultiEdit', 'NotebookEdit'].includes(tool)) return { file_path: target };
  if (tool === 'WebFetch' || tool === 'WebSearch') return { url: target };
  return {};
}

function verify(auditDir, replay = true) {
  const rows = readAll(auditDir);
  const chained = rows.filter((r) => 'hash' in r);

  const report = {
    total: rows.length,
    chained: chained.length,
    integrityOk: true,
    breakAt: null,
    breakReason: null,
    replayed: 0,
    drift: [],
  };

  let prevHash = GENESIS;
  for (const r of chained) {
    if (receiptHash(r) !== r.hash) {
      report.integrityOk = false;
      report.breakAt = r.seq;
      report.breakReason = 'content hash mismatch (receipt altered)';
      break;
    }
    if (r.prev !== prevHash) {
      report.integrityOk = false;
      report.breakAt = r.seq;
      report.breakReason = 'broken link (a prior receipt was changed or removed)';
      break;
    }
    prevHash = r.hash;
  }

  if (replay) {
    for (const r of chained) {
      const prof = getProfile(String(r.profile || ''));
      if (!prof) continue;
      const ti = reconstructInput(String(r.tool || ''), String(r.target || ''));
      const got = decide(String(r.tool || ''), ti, prof, String(r.mode || ''));
      report.replayed += 1;
      if (got.decision !== r.decision) {
        report.drift.push({ seq: r.seq, tool: r.tool, target: r.target, recorded: r.decision, now: got.decision });
      }
    }
  }

  report.ok = report.integrityOk && report.drift.length === 0;
  return report;
}

module.exports = { verify };
