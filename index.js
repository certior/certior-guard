'use strict';
// Public API. The CLI is `certior-guard`; programmatic entry points:
const { capabilityFor, decide, resolve } = require('./src/engine');
const { getProfile, listProfiles } = require('./src/profiles');
const { check } = require('./src/check');
const { verify } = require('./src/verify');

module.exports = {
  version: require('./package.json').version,
  capabilityFor, decide, resolve, getProfile, listProfiles, check, verify,
};
