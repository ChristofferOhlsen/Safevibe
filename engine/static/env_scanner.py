"""
env_scanner.py – Scanner .env-filer for eksponerede secrets og API-nøgler.
Dækker 40+ kendte secret-formater på tværs af cloud-udbydere, AI, betalinger osv.
"""

import os
import re
from pathlib import Path

# Safevibe's egen rodmappe – ekskluderes fra scanning så vi ikke scanner os selv
SAFEVIBE_ROOT = Path(__file__).resolve().parent.parent.parent

# ─── MØNSTER-KATEGORI: FORMAT-BASEREDE (matcher VALUE-format) ────────────────
# (regex, beskrivelse, severity)
FORMAT_PATTERNS = [
    # JWT / Supabase
    (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}",
     "JWT/Supabase token hardcodet", "critical"),

    # OpenAI
    (r"sk-[A-Za-z0-9]{20,}",
     "OpenAI API-nøgle (sk-)", "critical"),

    # Anthropic / Claude
    (r"sk-ant-[A-Za-z0-9\-_]{50,}",
     "Anthropic/Claude API-nøgle", "critical"),

    # AWS Access Key
    (r"AKIA[A-Z0-9]{16}",
     "AWS Access Key ID (AKIA...)", "critical"),

    # AWS Secret Key – matches typisk 40-char base64
    (r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])",
     "Mulig AWS Secret Access Key (40-char)", "warning"),

    # GitHub
    (r"ghp_[A-Za-z0-9]{36}",
     "GitHub Personal Access Token (ghp_)", "critical"),
    (r"github_pat_[A-Za-z0-9_]{82}",
     "GitHub Fine-grained PAT", "critical"),
    (r"ghs_[A-Za-z0-9]{36}",
     "GitHub App Installation Token", "critical"),

    # Stripe
    (r"sk_live_[A-Za-z0-9]{24,}",
     "Stripe LIVE Secret Key", "critical"),
    (r"sk_test_[A-Za-z0-9]{24,}",
     "Stripe TEST Secret Key", "warning"),
    (r"rk_live_[A-Za-z0-9]{24,}",
     "Stripe LIVE Restricted Key", "critical"),
    (r"whsec_[A-Za-z0-9]{32,}",
     "Stripe Webhook Secret (whsec_)", "critical"),

    # Slack
    (r"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+",
     "Slack Bot Token (xoxb-)", "critical"),
    (r"xoxp-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]+",
     "Slack User Token (xoxp-)", "critical"),
    (r"xoxa-[0-9]+-[0-9]+-[0-9]+-[A-Za-z0-9]+",
     "Slack App Token", "critical"),
    (r"xoxr-[A-Za-z0-9]+",
     "Slack Refresh Token", "critical"),

    # Twilio
    (r"SK[A-Za-z0-9]{32}",
     "Twilio API Key SID", "critical"),
    (r"AC[a-z0-9]{32}",
     "Twilio Account SID", "warning"),

    # SendGrid
    (r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
     "SendGrid API-nøgle (SG.)", "critical"),

    # Mailgun
    (r"key-[A-Za-z0-9]{32}",
     "Mailgun API-nøgle (key-)", "critical"),

    # HuggingFace
    (r"hf_[A-Za-z0-9]{34,}",
     "HuggingFace Token (hf_)", "critical"),

    # Replicate
    (r"r8_[A-Za-z0-9]{40}",
     "Replicate API Token (r8_)", "critical"),

    # Firebase / Google
    (r"AIza[0-9A-Za-z\-_]{35}",
     "Google/Firebase API-nøgle (AIza)", "critical"),

    # Cloudflare (fjernet – for bredt mønster der giver false positives)
    # CF tokens skal matches via nøglenavn i stedet

    # NPM tokens
    (r"npm_[A-Za-z0-9]{36}",
     "NPM Automation/Publish Token", "critical"),

    # Vercel
    (r"vercel_[A-Za-z0-9_]{24,}",
     "Vercel Token", "critical"),

    # Clerk
    (r"sk_live_[A-Za-z0-9]{40,}",
     "Clerk LIVE Secret Key", "critical"),
    (r"sk_test_[A-Za-z0-9]{40,}",
     "Clerk TEST Secret Key", "warning"),

    # Pusher
    (r"[A-Za-z0-9]{8}:[A-Za-z0-9]{40}",
     "Mulig Pusher App Secret", "warning"),

    # Azure Storage connection string
    (r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
     "Azure Storage Connection String", "critical"),

    # Azure SAS token
    (r"sig=[A-Za-z0-9%]+&",
     "Azure SAS Token", "critical"),

    # Supabase service_role
    (r"(?i)service_role",
     "Supabase service_role nøgle – ALDRIG i frontend", "critical"),

    # Database URL med embedded credentials
    (r"(postgres|mysql|mongodb|redis)(\+srv)?://[^:]+:[^@]+@",
     "Database URL med embedded brugernavn/kodeord", "critical"),

    # Private key (PEM)
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
     "Privat nøgle (PEM format) fundet", "critical"),
]

# ─── MØNSTER-KATEGORI: NØGLE-NAVN baserede (matcher KEY=VALUE linjer) ────────
# (key_regex, beskrivelse, severity)
KEY_PATTERNS = [
    # Kodeord / adgangskoder
    (r"(?i)^[A-Z0-9_]*?(password|passwd|pwd|passcode)[A-Z0-9_]*\s*=\s*.{4,}",
     "Adgangskode i .env", "critical"),

    # Secrets og private nøgler
    (r"(?i)^[A-Z0-9_]*?(secret|private_key|private[-_]key)[A-Z0-9_]*\s*=\s*.{4,}",
     "Hemmeligt token / privat nøgle", "critical"),

    # API nøgler (generisk)
    (r"(?i)^[A-Z0-9_]*?(api_key|apikey|api[-_]key)[A-Z0-9_]*\s*=\s*.{8,}",
     "API-nøgle fundet", "warning"),

    # Auth hemmeligheder
    (r"(?i)^[A-Z0-9_]*?(jwt_secret|auth_secret|nextauth_secret|auth[-_]key)[A-Z0-9_]*\s*=\s*.{8,}",
     "Auth-hemmelighed i .env", "critical"),

    # Auth tokens
    (r"(?i)^[A-Z0-9_]*?(auth_token|access_token|refresh_token)[A-Z0-9_]*\s*=\s*.{8,}",
     "Auth/Access token hardcodet", "critical"),

    # Database URL / DSN
    (r"(?i)^[A-Z0-9_]*?(database_url|db_url|connection_string|database_uri|db_uri|dsn)[A-Z0-9_]*\s*=\s*.{10,}",
     "Database forbindelses-URL", "warning"),

    # AWS
    (r"(?i)^[A-Z0-9_]*?aws_secret[A-Z0-9_]*\s*=\s*.{20,}",
     "AWS Secret Access Key", "critical"),
    (r"(?i)^[A-Z0-9_]*?aws_access_key[A-Z0-9_]*\s*=\s*.{16,}",
     "AWS Access Key ID", "critical"),

    # Twilio
    (r"(?i)^[A-Z0-9_]*?twilio[A-Z0-9_]*?(token|secret|sid)[A-Z0-9_]*\s*=\s*.{10,}",
     "Twilio credential", "critical"),

    # SendGrid
    (r"(?i)^[A-Z0-9_]*?sendgrid[A-Z0-9_]*?(key|token)[A-Z0-9_]*\s*=\s*.{10,}",
     "SendGrid API-nøgle", "critical"),

    # Mailgun
    (r"(?i)^[A-Z0-9_]*?mailgun[A-Z0-9_]*?(key|token|secret)[A-Z0-9_]*\s*=\s*.{10,}",
     "Mailgun API-nøgle", "critical"),

    # Clerk
    (r"(?i)^[A-Z0-9_]*?clerk[A-Z0-9_]*?(secret|key|token)[A-Z0-9_]*\s*=\s*.{10,}",
     "Clerk API credential", "critical"),

    # Upstash
    (r"(?i)^[A-Z0-9_]*?upstash[A-Z0-9_]*?(token|password|rest_token)[A-Z0-9_]*\s*=\s*.{10,}",
     "Upstash token/password", "critical"),

    # Turso
    (r"(?i)^[A-Z0-9_]*?turso[A-Z0-9_]*?(token|auth)[A-Z0-9_]*\s*=\s*.{10,}",
     "Turso auth token", "critical"),

    # PlanetScale
    (r"(?i)^[A-Z0-9_]*?planetscale[A-Z0-9_]*?(password|token)[A-Z0-9_]*\s*=\s*.{10,}",
     "PlanetScale credential", "critical"),

    # Resend
    (r"(?i)^[A-Z0-9_]*?resend[A-Z0-9_]*?(key|token|api)[A-Z0-9_]*\s*=\s*.{10,}",
     "Resend API-nøgle", "critical"),

    # Stripe
    (r"(?i)^[A-Z0-9_]*?stripe[A-Z0-9_]*?(secret|key|webhook)[A-Z0-9_]*\s*=\s*.{10,}",
     "Stripe API credential", "critical"),

    # GitHub
    (r"(?i)^[A-Z0-9_]*?github[A-Z0-9_]*?(token|secret|key|pat)[A-Z0-9_]*\s*=\s*.{10,}",
     "GitHub credential", "critical"),

    # Slack
    (r"(?i)^[A-Z0-9_]*?slack[A-Z0-9_]*?(token|secret|webhook|bot)[A-Z0-9_]*\s*=\s*.{10,}",
     "Slack credential", "critical"),

    # Cloudflare
    (r"(?i)^[A-Z0-9_]*?(cloudflare|cf)[A-Z0-9_]*?(token|key|secret)[A-Z0-9_]*\s*=\s*.{20,}",
     "Cloudflare API token", "critical"),

    # HuggingFace
    (r"(?i)^[A-Z0-9_]*?(huggingface|hf)[A-Z0-9_]*?(token|key)[A-Z0-9_]*\s*=\s*.{10,}",
     "HuggingFace token", "critical"),

    # Azure
    (r"(?i)^[A-Z0-9_]*?azure[A-Z0-9_]*?(key|secret|connection|token|sas)[A-Z0-9_]*\s*=\s*.{10,}",
     "Azure credential", "critical"),

    # Firebase
    (r"(?i)^[A-Z0-9_]*?firebase[A-Z0-9_]*?(key|secret|token|admin)[A-Z0-9_]*\s*=\s*.{10,}",
     "Firebase credential", "critical"),

    # Supabase service_role
    (r"(?i)^[A-Z0-9_]*?supabase[A-Z0-9_]*?service[A-Z0-9_]*\s*=\s*.{10,}",
     "Supabase service_role nøgle", "critical"),
]

ENV_FILE_GLOBS = [
    "**/.env", "**/.env.*", "**/env.local", "**/.env.local",
    "**/.env.development", "**/.env.production", "**/.env.staging",
    "**/.env.test", "**/.env.preview", "**/.env.vault", "**/.envrc",
]

# Værdier der sandsynligvis er placeholders
PLACEHOLDER_VALUES = {
    "", "your_key", "your_api_key", "xxx", "yyy", "change_me",
    "replace_me", "todo", "your_secret", "your_token",
    "placeholder", "example", "your_password", "your_url",
    "<your_key>", "<secret>", "CHANGE_ME", "REPLACE_ME",
}


def _is_safevibe_file(file_path: Path) -> bool:
    """Returner True hvis filen er en del af Safevibe's egne filer."""
    try:
        file_path.resolve().relative_to(SAFEVIBE_ROOT)
        return True
    except ValueError:
        return False


def _is_placeholder(value: str) -> bool:
    """Returner True hvis værdien ser ud som en placeholder."""
    v = value.strip().strip('"').strip("'").strip()
    if not v or len(v) < 3:
        return True
    if v.lower() in {p.lower() for p in PLACEHOLDER_VALUES}:
        return True
    if v.startswith("${") and v.endswith("}"):  # Shell variable
        return True
    if v.startswith("%(") and v.endswith(")s"):  # Python format
        return True
    return False


def scan_env_files(project_path: str) -> list[dict]:
    """Find og scan alle .env-filer i projektet for secrets."""
    findings = []
    base = Path(project_path)
    seen = set()  # Undgå duplikater

    env_files = []
    for pattern in ENV_FILE_GLOBS:
        env_files.extend(base.glob(pattern))

    env_files = [
        f for f in env_files
        if "node_modules" not in f.parts
        and ".git" not in f.parts
        and f.is_file()
        # Ekskluder Safevibe's egne filer (self-scan prevention)
        and not _is_safevibe_file(f)
    ]

    for env_file in env_files:
        rel_path = str(env_file.relative_to(base))
        try:
            content = env_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for line_num, line in enumerate(content.splitlines(), 1):
            raw_line = line
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Udtræk value til placeholder-check
            if "=" in line:
                _, _, raw_value = line.partition("=")
                if _is_placeholder(raw_value):
                    continue

            # ─── Tjek 1: Format-baserede mønstre (på hele linjen) ───────────
            for pattern, description, severity in FORMAT_PATTERNS:
                if re.search(pattern, line):
                    key_part = line.split("=")[0].strip() if "=" in line else line[:30]
                    dedup_key = (rel_path, line_num, description)
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        findings.append({
                            "file": rel_path,
                            "line": line_num,
                            "description": description,
                            "severity": severity,
                            "detail": f"{key_part}=***",
                        })
                    break  # Første match vinder

            # ─── Tjek 2: Nøgle-navn baserede mønstre ────────────────────────
            for pattern, description, severity in KEY_PATTERNS:
                if re.search(pattern, line):
                    key_part = line.split("=")[0].strip() if "=" in line else line[:30]
                    dedup_key = (rel_path, line_num, description)
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        findings.append({
                            "file": rel_path,
                            "line": line_num,
                            "description": description,
                            "severity": severity,
                            "detail": f"{key_part}=***",
                        })
                    break

    # ─── Post-process findings: ret beskrivelser til at afspejle .env-kontekst ─
    # Secrets i .env er BEREGNET til at være der. Det er kun farligt hvis:
    #   1. .env er committed til git (tjekkes separat af git_scanner)
    #   2. En nøgle har NEXT_PUBLIC_ prefix (eksponeres i klientbundlet)
    #   3. En service_role nøgle er eksponeret via NEXT_PUBLIC_
    for f in findings:
        f["env_file"] = True  # Marker at det er et .env-fund (ikke kode-fund)

        detail = f.get("detail", "")
        key_name = detail.split("=")[0].strip().upper()
        desc = f["description"]

        # Ret vildledende sprog fra mønstre skrevet til kildekode-kontekst:
        # "hardcodet" => antyder kildekode-eksponering, ikke .env
        # "ALDRIG i frontend" => antyder funnet direkt i frontend, ikke .env
        desc = desc.replace("hardcodet", "fundet i .env")
        desc = desc.replace(" – ALDRIG i frontend", "")

        if key_name.startswith("NEXT_PUBLIC_"):
            # NEXT_PUBLIC_ variabler bundtes ind i klientside-JavaScript.
            # Secrets med dette prefix er REELT eksponerede i browseren.
            is_service_role = (
                "service_role" in key_name.lower()
                or "service_role" in desc.lower()
            )
            if is_service_role:
                # Kritisk: admin-nøgle eksponeret i klientbundlet
                f["severity"] = "critical"
                f["description"] = (
                    "service_role nøgle med NEXT_PUBLIC_ prefix i .env – "
                    "eksponeres i klientbundlet og giver admin-adgang til databasen"
                )
            else:
                # Advarsel: enhver secret med NEXT_PUBLIC_ er synlig i browser
                f["severity"] = "warning"
                f["description"] = (
                    desc
                    + " – ADVARSEL: NEXT_PUBLIC_ variabler eksponeres i klientbundlet"
                )
        else:
            # Normal .env secret – det er det rigtige sted at opbevare nøgler.
            # Sæt severity til "info" og tilføj standard-note om gitignore.
            f["severity"] = "info"
            if "gitignored" not in desc:
                desc += " – sørg for at .env er gitignored"
            f["description"] = desc

    return findings


def check_env_example_exists(project_path: str) -> dict:
    """Tjek om der findes en .env.example som best practice."""
    base = Path(project_path)
    example_files = [".env.example", ".env.sample", ".env.template"]
    for name in example_files:
        if (base / name).exists():
            return {"exists": True, "file": name}
    return {"exists": False}


def check_env_vault(project_path: str) -> list[dict]:
    """Tjek om projektet bruger .env.vault (Dotenv Vault) korrekt."""
    findings = []
    base = Path(project_path)

    vault_file = base / ".env.vault"
    keys_file = base / ".env.keys"

    if vault_file.exists():
        findings.append({
            "severity": "info",
            "description": ".env.vault fundet – projekt bruger Dotenv Vault kryptering",
            "detail": "Husk at .env.keys ALDRIG må commites til git",
        })

    if keys_file.exists():
        # .env.keys indeholder master-dekrypteringsnøgler – MEGET kritisk
        findings.append({
            "severity": "critical",
            "description": ".env.keys fil fundet – indeholder master-krypteringsnøgler",
            "detail": "Tilføj .env.keys til .gitignore OMGÅENDE",
            "file": ".env.keys",
        })

    return findings
