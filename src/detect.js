'use strict';
// Scan a repo and recommend a profile. Cheap, offline signal-gathering: which
// frameworks, deploy targets, and sensitive surfaces are present.
const fs = require('fs');
const path = require('path');

const MARKERS = [
  [['prisma/schema.prisma', 'prisma'], 'Prisma'],
  [['supabase'], 'Supabase'],
  [['db/migrations', 'migrations', 'alembic'], 'DB migrations'],
  [['terraform', 'main.tf'], 'Terraform'],
  [['k8s', 'kubernetes', 'helm'], 'Kubernetes / Helm'],
  [['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'], 'Docker'],
  [['vercel.json', '.vercel'], 'Vercel deploy'],
  [['fly.toml'], 'Fly.io deploy'],
  [['netlify.toml'], 'Netlify deploy'],
  [['serverless.yml'], 'Serverless'],
  [['.github/workflows'], 'GitHub Actions'],
  [['auth', 'middleware.ts'], 'Auth code'],
];

const ENV_FILES = ['.env', '.env.local', '.env.production'];
const DEP_HINTS = {
  stripe: 'Stripe (billing)', '@stripe': 'Stripe (billing)', next: 'Next.js',
  django: 'Django', fastapi: 'FastAPI', rails: 'Rails', express: 'Express',
};

function exists(root, rel) { return fs.existsSync(path.join(root, rel)); }

function scanDeps(root) {
  const found = [];
  for (const fname of ['package.json', 'pyproject.toml', 'requirements.txt', 'Gemfile']) {
    const p = path.join(root, fname);
    if (!fs.existsSync(p)) continue;
    let text;
    try { text = fs.readFileSync(p, 'utf8').toLowerCase(); } catch { continue; }
    for (const [needle, label] of Object.entries(DEP_HINTS)) {
      const re = new RegExp('\\b' + needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
      if (re.test(text) && !found.includes(label)) found.push(label);
    }
  }
  return found;
}

function detect(root = '.') {
  const detected = [];
  for (const [markers, label] of MARKERS) {
    if (markers.some((m) => exists(root, m)) && !detected.includes(label)) detected.push(label);
  }

  const hasEnv = ENV_FILES.some((f) => exists(root, f));
  if (hasEnv) detected.unshift('.env files');

  for (const d of scanDeps(root)) if (!detected.includes(d)) detected.push(d);

  const deployLabels = new Set(['Terraform', 'Kubernetes / Helm', 'Vercel deploy', 'Fly.io deploy',
    'Netlify deploy', 'Serverless', 'Docker']);
  const hasDeploy = detected.some((d) => deployLabels.has(d));
  const hasMigrations = detected.some((d) => ['Prisma', 'Supabase', 'DB migrations'].includes(d));

  let recommended;
  if (hasDeploy && (hasMigrations || detected.includes('Stripe (billing)'))) recommended = 'production';
  else if (hasDeploy || detected.includes('GitHub Actions') || hasMigrations) recommended = 'team';
  else recommended = 'personal';

  return { detected, hasEnv, hasDeploy, hasMigrations, recommended };
}

module.exports = { detect };
