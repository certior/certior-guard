"""Scan a repo and recommend a profile — so the user doesn't have to think.

Cheap, offline signal-gathering: which frameworks, deploy targets, and
sensitive surfaces are present. This drives the "Detected: … / Recommended
profile: team" screen and lets ``init`` pick good defaults without questions.
"""
from __future__ import annotations

import os
import re
from typing import Dict, List

# marker → human label. Files/dirs whose presence implies a risk surface.
_MARKERS = [
    (["prisma/schema.prisma", "prisma"], "Prisma"),
    (["supabase"], "Supabase"),
    (["db/migrations", "migrations", "alembic"], "DB migrations"),
    (["terraform", "main.tf"], "Terraform"),
    (["k8s", "kubernetes", "helm"], "Kubernetes / Helm"),
    (["Dockerfile", "docker-compose.yml", "docker-compose.yaml"], "Docker"),
    (["vercel.json", ".vercel"], "Vercel deploy"),
    (["fly.toml"], "Fly.io deploy"),
    (["netlify.toml"], "Netlify deploy"),
    (["serverless.yml"], "Serverless"),
    ([".github/workflows"], "GitHub Actions"),
    (["auth", "middleware.ts"], "Auth code"),
]

_ENV_FILES = [".env", ".env.local", ".env.production"]
_DEP_HINTS = {
    "stripe": "Stripe (billing)",
    "@stripe": "Stripe (billing)",
    "next": "Next.js",
    "django": "Django",
    "fastapi": "FastAPI",
    "rails": "Rails",
    "express": "Express",
}


def _exists(root: str, rel: str) -> bool:
    return os.path.exists(os.path.join(root, rel))


def _scan_deps(root: str) -> List[str]:
    found: List[str] = []
    for fname in ("package.json", "pyproject.toml", "requirements.txt", "Gemfile"):
        p = os.path.join(root, fname)
        if not os.path.exists(p):
            continue
        try:
            with open(p, encoding="utf-8", errors="ignore") as fh:
                text = fh.read().lower()
        except Exception:
            continue
        for needle, label in _DEP_HINTS.items():
            if re.search(r"\b" + re.escape(needle), text) and label not in found:
                found.append(label)
    return found


def detect(root: str = ".") -> Dict[str, object]:
    """Return ``{detected: [labels], has_env, has_deploy, has_migrations, recommended}``."""
    detected: List[str] = []
    for markers, label in _MARKERS:
        if any(_exists(root, m) for m in markers) and label not in detected:
            detected.append(label)

    has_env = any(_exists(root, f) for f in _ENV_FILES)
    if has_env:
        detected.insert(0, ".env files")

    detected.extend(d for d in _scan_deps(root) if d not in detected)

    deploy_labels = {"Terraform", "Kubernetes / Helm", "Vercel deploy", "Fly.io deploy",
                     "Netlify deploy", "Serverless", "Docker"}
    has_deploy = any(d in deploy_labels for d in detected)
    has_migrations = any(d in ("Prisma", "Supabase", "DB migrations") for d in detected)

    # Recommendation: a deployable service with migrations/billing → production;
    # anything with a deploy target or CI → team; otherwise personal.
    if has_deploy and (has_migrations or "Stripe (billing)" in detected):
        recommended = "production"
    elif has_deploy or "GitHub Actions" in detected or has_migrations:
        recommended = "team"
    else:
        recommended = "personal"

    return {
        "detected": detected,
        "has_env": has_env,
        "has_deploy": has_deploy,
        "has_migrations": has_migrations,
        "recommended": recommended,
    }
