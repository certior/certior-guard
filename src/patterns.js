'use strict';
// Security-critical path patterns — the single source of truth shared by the
// Read-tool path (engine) and the Bash path (shellParse). Committed env
// *templates* (.env.example/.sample/.template/.dist/.md) are intentionally
// excluded: reading or copying a checked-in template is normal.

// `.env` and real variants (.env.local, .env.production) but NOT the templates.
const ENV = String.raw`(^|/)\.env(?!\.(?:example|sample|template|dist|md)\b)(\.|$)`;

const SECRET_PATH = new RegExp(
  ENV +
  String.raw`|(^|/)(secrets?|credentials?)(/|\.|$)|\.pem$|\.key$|` +
  String.raw`id_rsa|/\.aws/|/\.ssh/|\.pfx$|\.p12$|\.netrc|service-account\.json|\.npmrc$|\.pypirc$`,
  'i',
);

const SECRET_INLINE = new RegExp(
  String.raw`\.env(?!\.(?:example|sample|template|dist|md)\b)\b` +
  String.raw`|\.pem\b|\.key\b|id_rsa|/\.ssh/|/\.aws/|\.netrc\b|\.npmrc\b|\.pypirc\b|` +
  String.raw`\.p12\b|\.pfx\b|service-account\.json`,
  'i',
);

module.exports = { SECRET_PATH, SECRET_INLINE };
