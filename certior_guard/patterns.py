"""Security-critical path patterns — the single source of truth.

Both the Read-tool path (:mod:`certior_guard.engine`) and the Bash path
(:mod:`certior_guard.shell_parse`) match secret files against these. Keeping one
copy here is deliberate: an earlier bug came from two regexes drifting apart, so
one file with no dependencies is the fix.

``SECRET_PATH``   — a bare filesystem path that names a credential file.
``SECRET_INLINE`` — the same, but embedded in a string/expression (e.g. code
                    passed to ``python -c`` or ``node -e``), where the filename
                    is wrapped in quotes/parens rather than sitting as its own
                    argument.

Conventional *non-secret* env templates — ``.env.example``, ``.env.sample``,
``.env.template``, ``.env.dist`` — are intentionally excluded: reading or copying
a checked-in template is normal and should not trip the guard.
"""
from __future__ import annotations

import re

# ``.env`` and real variants (``.env.local``, ``.env.production``) but NOT the
# committed templates. The negative lookahead handles the template suffixes.
_ENV = r"(^|/)\.env(?!\.(?:example|sample|template|dist|md)\b)(\.|$)"

SECRET_PATH = re.compile(
    _ENV
    + r"|(^|/)(secrets?|credentials?)(/|\.|$)|\.pem$|\.key$|"
    r"id_rsa|/\.aws/|/\.ssh/|\.pfx$|\.p12$|\.netrc|service-account\.json|\.npmrc$|\.pypirc$",
    re.IGNORECASE,
)

SECRET_INLINE = re.compile(
    r"\.env(?!\.(?:example|sample|template|dist|md)\b)\b"
    r"|\.pem\b|\.key\b|id_rsa|/\.ssh/|/\.aws/|\.netrc\b|\.npmrc\b|\.pypirc\b|"
    r"\.p12\b|\.pfx\b|service-account\.json",
    re.IGNORECASE,
)
