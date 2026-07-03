'use strict';
// Map a shell command to capabilities against a shell-normalised form. A raw
// `\bcurl\b` regex is trivially evaded — c""url, FOO=1 curl, /usr/bin/curl,
// sudo curl, C=curl; $C all run curl while dodging the match. So the command is
// tokenised like a shell would (quote/escape removal), split into simple
// commands, stripped of env-assignment prefixes and wrappers (sudo/env/timeout),
// and VAR=val indirection is resolved; rules run against that normal form.
//
// Not a sandbox: a parse failure returns null so the caller treats the command
// as an opaque exec, and dynamic constructs ($(…), eval, base64 -d) are flagged
// for conservative handling.
const { SECRET_PATH, SECRET_INLINE } = require('./patterns');

const WRAPPERS = new Set([
  'sudo', 'doas', 'command', 'env', 'nohup', 'nice', 'ionice', 'stdbuf',
  'setsid', 'time', 'timeout', 'watch', 'xargs', 'exec', 'builtin',
  'caffeinate', 'chrt',
]);
const OPERATORS = new Set(['|', '||', '&&', ';', '&', '|&', '(', ')']);
const PIPES = new Set(['|', '|&']);
const PUNCT = new Set([';', '&', '|', '<', '>', '(', ')']);

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'fish', 'csh', 'tcsh', 'busybox']);
const DOWNLOADERS = new Set(['curl', 'wget', 'fetch', 'aria2c', 'lynx', 'w3m', 'httpie', 'http']);

const ASSIGN = /^[A-Za-z_]\w*=/;
const VARREF = /^\$\{?([A-Za-z_]\w*)\}?$/;
const DYNAMIC = /\$\(|`|\beval\b|\bsource\b|base64\s+-{0,2}d|\bxxd\b\s+-r|\bopenssl\b.*\benc\b.*-d/;

function basename(token) { return token.slice(token.lastIndexOf('/') + 1); }

// Tokenise like a POSIX shell with punctuation split out. Returns null on a
// parse error (unbalanced quotes) so the caller falls back to opaque exec.
function tokenize(command) {
  command = command.replace(/\n/g, ' ; ').replace(/\r/g, ' ');
  const tokens = [];
  let i = 0;
  const n = command.length;
  while (i < n) {
    const c = command[i];
    if (c === ' ' || c === '\t') { i++; continue; }
    if (PUNCT.has(c)) {
      let j = i;
      while (j < n && PUNCT.has(command[j])) j++;
      tokens.push(command.slice(i, j));
      i = j;
      continue;
    }
    let word = '';
    while (i < n) {
      const ch = command[i];
      if (ch === ' ' || ch === '\t' || PUNCT.has(ch)) break;
      if (ch === '\\') { if (i + 1 < n) { word += command[i + 1]; i += 2; } else { i++; } continue; }
      if (ch === "'") {
        const end = command.indexOf("'", i + 1);
        if (end === -1) return null;
        word += command.slice(i + 1, end);
        i = end + 1;
        continue;
      }
      if (ch === '"') {
        let k = i + 1;
        let buf = '';
        let closed = false;
        while (k < n) {
          if (command[k] === '\\' && k + 1 < n && (command[k + 1] === '"' || command[k + 1] === '\\')) {
            buf += command[k + 1]; k += 2; continue;
          }
          if (command[k] === '"') { closed = true; break; }
          buf += command[k]; k++;
        }
        if (!closed) return null;
        word += buf;
        i = k + 1;
        continue;
      }
      word += ch; i++;
    }
    tokens.push(word);
  }
  return tokens;
}

// Resolve simple VAR=val … $VAR indirection within one command line.
function substituteVars(tokens) {
  const varmap = {};
  for (const t of tokens) {
    if (ASSIGN.test(t)) { const idx = t.indexOf('='); varmap[t.slice(0, idx)] = t.slice(idx + 1); }
  }
  if (Object.keys(varmap).length === 0) return tokens;
  return tokens.map((t) => {
    const m = VARREF.exec(t);
    return (m && m[1] in varmap) ? varmap[m[1]] : t;
  });
}

// Drop leading assignments and wrapper commands; return {exe, args} or null.
function peel(tokens) {
  let i = 0;
  const n = tokens.length;
  while (i < n) {
    const t = tokens[i];
    if (ASSIGN.test(t)) { i++; continue; }
    const base = basename(t);
    if (WRAPPERS.has(base.toLowerCase())) {
      i++;
      while (i < n && (tokens[i].startsWith('-') || /^\d+$/.test(tokens[i]))) i++;
      continue;
    }
    return { executable: base, exe: base.toLowerCase(), args: tokens.slice(i + 1) };
  }
  return null;
}

function analyze(command) {
  if (!command || !command.trim()) return { commands: [], piped: false, hasDynamic: false, redirects: [] };
  let tokens = tokenize(command);
  if (tokens === null) return null;
  tokens = substituteVars(tokens);

  const piped = tokens.some((t) => PIPES.has(t));
  const redirects = [];
  const commands = [];
  let segment = [];
  let expectTarget = false;
  for (const t of tokens) {
    if (expectTarget) { redirects.push(t); expectTarget = false; continue; }
    if (t === '>' || t === '>>' || t === '<' || t === '>|') { expectTarget = true; continue; }
    if (OPERATORS.has(t)) {
      if (segment.length) { const c = peel(segment); if (c) commands.push(c); segment = []; }
      continue;
    }
    segment.push(t);
  }
  if (segment.length) { const c = peel(segment); if (c) commands.push(c); }

  return { commands, piped, hasDynamic: DYNAMIC.test(command), redirects };
}

const READERS = new Set(['cat', 'less', 'more', 'head', 'tail', 'grep', 'egrep', 'strings',
  'xxd', 'od', 'base64', 'bat', 'nl', 'tac', 'awk', 'sed', 'cut']);
const INTERPRETERS = new Set(['python', 'python2', 'python3', 'node', 'nodejs', 'deno', 'bun',
  'ruby', 'perl', 'php', 'rscript']);
const COPIERS = new Set(['cp', 'mv', 'install', 'ln']);
const DESTROYERS = new Set(['dd', 'shred', 'wipefs', 'blkdiscard']);
const DEPLOYERS = new Set(['kubectl', 'terraform', 'helm', 'serverless', 'vercel', 'netlify',
  'fly', 'flyctl', 'pulumi', 'ansible-playbook', 'aws']);
const DEPLOY_VERBS = new Set(['apply', 'deploy', 'destroy', 'delete', 'up', 'provision']);
const INSTALLERS = new Set(['npm', 'pnpm', 'yarn', 'pip', 'pip3', 'pipx', 'uv', 'poetry',
  'gem', 'bundle', 'cargo', 'go', 'apt', 'apt-get', 'brew', 'apk']);
const INSTALL_VERBS = new Set(['install', 'add']);
const DB_DANGER = /\bdrop\b|\btruncate\b|\bdelete\s+from\b/i;

function isInstall(exe, args) {
  if (!INSTALLERS.has(exe)) return false;
  if (args.some((a) => INSTALL_VERBS.has(a))) return true;
  return (exe === 'npm' && args[0] === 'i') || (exe === 'go' && args.includes('get'));
}

// Returns a (possibly empty) array of capabilities, or null if unparseable.
function shellCapabilities(command) {
  const parsed = analyze(command);
  if (parsed === null) return null;

  const caps = [];
  const add = (...cs) => { for (const c of cs) if (!caps.includes(c)) caps.push(c); };

  const hasDownloader = parsed.commands.some((c) => DOWNLOADERS.has(c.exe));
  const hasShell = parsed.commands.some((c) => SHELLS.has(c.exe));

  if (hasDownloader && hasShell && parsed.piped) add('code:exec', 'remote:exfiltrate');
  if (parsed.hasDynamic && (hasShell || parsed.commands.some((c) => c.exe === 'eval'))) {
    if (hasDownloader || /curl|wget/i.test(command)) add('code:exec', 'remote:exfiltrate');
  }

  for (const c of parsed.commands) {
    const { exe, args } = c;
    if (DESTROYERS.has(exe) || exe.startsWith('mkfs')) add('fs:destroy');
    else if (exe === 'rm' && args.some((f) => f.startsWith('-') && (f.includes('r') || f.includes('f')))) add('fs:delete');
    else if (exe === 'git' && args[0] === 'push') add('git:push');
    else if (exe === 'git' && args[0] === 'merge') add('git:merge');
    else if (DEPLOYERS.has(exe) && args.some((a) => DEPLOY_VERBS.has(a))) add('prod:deploy');
    else if (exe === 'docker' && args.includes('push')) add('prod:deploy');
    else if (['npm', 'pnpm', 'yarn'].includes(exe) && args.includes('publish')) add('package:publish');
    else if (exe === 'twine' && args.includes('upload')) add('package:publish');
    else if (exe === 'cargo' && args.includes('publish')) add('package:publish');
    else if (exe === 'gh' && args.includes('release')) add('package:publish');
    else if (['psql', 'mysql', 'mongo', 'mongosh'].includes(exe) && DB_DANGER.test(args.join(' '))) add('db:destroy');
    else if (isInstall(exe, args)) add('deps:install');
    else if (READERS.has(exe) && args.some((a) => SECRET_PATH.test(a))) add('secrets:read');
    else if (INTERPRETERS.has(exe) && args.some((a) => SECRET_INLINE.test(a))) add('secrets:read');
    else if ((exe === 'source' || exe === '.') && args.some((a) => SECRET_PATH.test(a))) add('secrets:read');
    else if (COPIERS.has(exe)
      && args.slice(0, -1).some((a) => !a.startsWith('-') && SECRET_PATH.test(a))) add('secrets:read');
    else if (['scp', 'rsync'].includes(exe) && args.some((a) => a.includes('@'))) add('data:exfiltrate');
    else if (DOWNLOADERS.has(exe)
      && args.some((a) => ['-F', '-d', '--data', '--data-binary', '-T', '--upload-file'].includes(a))
      && args.some((a) => /^https?:\/\/(?!localhost|127\.)/.test(a))) add('data:exfiltrate');
  }

  if (parsed.redirects.some((t) => /^\/dev\/(sd|nvme|mmcblk|vd|hd)/.test(t))) add('fs:destroy');

  return caps;
}

module.exports = { analyze, shellCapabilities, tokenize };
