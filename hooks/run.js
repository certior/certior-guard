#!/usr/bin/env node
'use strict';
// Self-contained PreToolUse hook entry for the Certior Guard plugin. Claude Code
// runs this on every matched tool call: `node "${CLAUDE_PLUGIN_ROOT}/hooks/run.js"`.
// It needs no npm install and no build — just Node, which every Claude Code user
// already has. Zero third-party dependencies.
const { runHook } = require('../src/hook');

process.exit(runHook());
