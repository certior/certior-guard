'use strict';
// Policy analysis over the closed capability vocabulary. The capability set is
// finite and rules are globs over it, so these are decided by exhaustive
// enumeration, no solver:
//   - floor domination — every always-deny capability resolves to `deny` under
//     every profile and enforcing mode (the safety invariant);
//   - dead rules — a pattern matching no known capability;
//   - shadowed asks — an `ask` pattern whose matches are all already blocked.
const { KNOWN_CAPABILITIES, knownMatching } = require('./capabilities');
const { resolve } = require('./engine');
const { ALWAYS_DENY, alwaysDenied, listProfiles } = require('./profiles');

const ENFORCING_MODES = ['ask', 'enforce'];

function check() {
  const caps = Object.keys(KNOWN_CAPABILITIES);
  const floor = caps.filter((c) => alwaysDenied(c));

  const violations = [];
  let checks = 0;
  for (const prof of listProfiles()) {
    for (const mode of ENFORCING_MODES) {
      for (const cap of floor) {
        checks += 1;
        if (resolve([cap], prof, mode).decision !== 'deny') {
          violations.push({ profile: prof.key, mode, capability: cap });
        }
      }
    }
  }

  const profiles = [];
  for (const prof of listProfiles()) {
    const dead = [];
    for (const pat of [...prof.blockPatterns, ...prof.askPatterns]) {
      if (knownMatching(pat).length === 0) dead.push(pat);
    }
    const shadowed = prof.askPatterns.filter((pat) => {
      const m = knownMatching(pat);
      return m.length > 0 && m.every((c) => prof.blocks(c));
    });
    profiles.push({ profile: prof.key, deadRules: dead, shadowedAsks: shadowed });
  }

  return {
    floorSize: floor.length,
    floorPatterns: ALWAYS_DENY.slice(),
    checks,
    floorOk: violations.length === 0,
    violations,
    profiles,
  };
}

module.exports = { check };
