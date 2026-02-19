"""
git_scanner.py – Tjekker at .gitignore korrekt dækker sensitive filer,
og scanner om secrets allerede er committed til git-historik.
"""

import os
import re
import subprocess
from pathlib import Path

# Safevibe's egen rodmappe – ekskluderes fra scanning så vi ikke scanner os selv
SAFEVIBE_ROOT = Path(__file__).resolve().parent.parent.parent


MUST_IGNORE = [
    ".env",
    ".env.local",
    ".env.*.local",
    ".env.production",
    ".env.development",
    ".env.staging",
    ".env.test",
    ".env.vault",
    ".env.keys",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    ".DS_Store",
    "node_modules",
    "docker-compose.override.yml",
    ".npmrc",
]

# Mønstre der matches i commit-log output
SECRET_COMMIT_PATTERNS = [
    # Kodeord / passwords
    (r"(?i)(password|passwd)\s*=\s*['\"]?.{4,}", "password/passwd i commit"),
    # API-nøgler generisk
    (r"(?i)(api_key|apikey)\s*=\s*['\"]?.{8,}", "API-nøgle i commit"),
    # Secrets generisk
    (r"(?i)(secret|private_key)\s*=\s*['\"]?.{8,}", "secret/private_key i commit"),
    # JWT tokens
    (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "JWT token i commit"),
    # OpenAI
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI API-nøgle i commit"),
    # Anthropic
    (r"sk-ant-[A-Za-z0-9\-_]{40,}", "Anthropic API-nøgle i commit"),
    # GitHub
    (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT i commit"),
    (r"github_pat_[A-Za-z0-9_]{82}", "GitHub fine-grained PAT i commit"),
    # AWS
    (r"AKIA[A-Z0-9]{16}", "AWS Access Key ID i commit"),
    # Stripe
    (r"sk_live_[A-Za-z0-9]{24,}", "Stripe LIVE Secret Key i commit"),
    (r"whsec_[A-Za-z0-9]{32,}", "Stripe Webhook Secret i commit"),
    # Slack
    (r"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+", "Slack Bot Token i commit"),
    # SendGrid
    (r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}", "SendGrid API-nøgle i commit"),
    # Firebase
    (r"AIza[0-9A-Za-z\-_]{35}", "Google/Firebase API-nøgle i commit"),
    # HuggingFace
    (r"hf_[A-Za-z0-9]{34,}", "HuggingFace token i commit"),
    # NPM
    (r"npm_[A-Za-z0-9]{36}", "NPM token i commit"),
    # Database URLs med creds
    (r"(postgres|mysql|mongodb)://[^:]+:[^@]+@", "Database URL med credentials i commit"),
    # Private keys
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Privat nøgle i commit"),
]

# Filtyper der scannes i commit-log
COMMIT_SCAN_GLOBS = [
    "*.env*", "*.js", "*.ts", "*.tsx", "*.jsx",
    "*.json", "*.yaml", "*.yml", "*.toml", "*.py",
    "*.php", "*.rb", "*.go", "*.sh", "*.bash",
    "*.config", "*.ini", ".npmrc",
]


def check_gitignore(project_path: str) -> list[dict]:
    """Verificér at .gitignore dækker kritiske filer."""
    findings = []
    gitignore_path = Path(project_path) / ".gitignore"

    if not gitignore_path.exists():
        findings.append({
            "severity": "critical",
            "description": ".gitignore fil mangler helt",
            "detail": "Opret en .gitignore fil omgående – alle .env-filer er i fare",
        })
        return findings

    content = gitignore_path.read_text(encoding="utf-8", errors="ignore")
    lines = [l.strip() for l in content.splitlines()]
    non_comment_lines = [l for l in lines if l and not l.startswith("#")]

    for pattern in MUST_IGNORE:
        covered = any(
            pattern == line or
            pattern in line or
            line in pattern or
            # Fuzzy: begge starter med .env – håndtér både .env* og .env.*
            (pattern.startswith(".env") and line.startswith(".env") and
             (line in (".env*", ".env", ".env.*") or pattern.startswith(line.rstrip("*.")))) or
            # Wildcard i gitignore (både .env* og .env.*)
            (line.endswith("*") and pattern.startswith(line[:-1])) or
            (line.endswith(".*") and pattern.startswith(line[:-2]))
            for line in non_comment_lines
        )
        if not covered:
            sev = "critical" if pattern in (".env", ".env.keys", ".env.vault", "*.pem", "*.key") else "warning"
            findings.append({
                "severity": sev,
                "description": f"'{pattern}' er ikke dækket af .gitignore",
                "detail": f"Tilføj '{pattern}' til .gitignore for at beskytte sensitive filer",
            })

    return findings


def check_secrets_in_git(project_path: str) -> list[dict]:
    """Scan git-historik for hardcodede secrets (seneste 50 commits)."""
    findings = []
    git_dir = Path(project_path) / ".git"

    if not git_dir.exists():
        return []

    # Byg --glob argumenter for filtyper
    glob_args = ["--"]
    for g in COMMIT_SCAN_GLOBS:
        glob_args.append(g)

    try:
        result = subprocess.run(
            ["git", "-C", project_path, "log",
             "--oneline", "-50", "--all", "-p"] + glob_args,
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="ignore",
        )
        log_output = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []

    if not log_output:
        return []

    seen_patterns = set()
    for pattern_re, description in SECRET_COMMIT_PATTERNS:
        if pattern_re in seen_patterns:
            continue
        try:
            matches = re.findall(pattern_re, log_output)
        except re.error:
            continue

        if matches:
            seen_patterns.add(pattern_re)
            # Find commit-hash context
            commit_hash = ""
            for line in log_output.splitlines():
                if line.startswith("commit ") and len(line) > 10:
                    commit_hash = line.split()[1][:8]
                if re.search(pattern_re, line):
                    break

            findings.append({
                "severity": "critical",
                "description": f"Secret fundet i git-historik: {description}",
                "detail": (
                    f"Mønster matchede i commit ~{commit_hash}. "
                    "Brug 'git filter-repo' eller BFG Repo-Cleaner til at fjerne det."
                ),
            })

    # Tjek om .env filer er tracked af git
    try:
        tracked = subprocess.run(
            ["git", "-C", project_path, "ls-files", "*.env*", ".env", ".env.*"],
            capture_output=True, text=True, timeout=5,
            encoding="utf-8", errors="ignore",
        )
        if tracked.stdout.strip():
            for tracked_file in tracked.stdout.strip().splitlines():
                findings.append({
                    "severity": "critical",
                    "description": f"'{tracked_file}' er tracked af git",
                    "detail": (
                        f"Kør: git rm --cached {tracked_file} && "
                        f"echo '{tracked_file}' >> .gitignore"
                    ),
                    "file": tracked_file,
                })
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return findings
