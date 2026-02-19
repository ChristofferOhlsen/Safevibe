"""
db_detector.py – Benhård 3-lags hybrid database-detektion.

Lag 1: Nøgle-navne (env var NAVNE matcher DB-teknologi-navne)
Lag 2: Værdier / connection-string formater (regex på VÆRDIER)
Lag 3: Prisma schema.prisma / Drizzle config parsing
Lag 4: Header/HTML-scanning af live server
"""

import re
import base64
import json
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

# Safevibe's egen rodmappe – ekskluderes fra scanning så vi ikke scanner os selv
SAFEVIBE_ROOT = Path(__file__).resolve().parent.parent.parent

# JWT regex – matcher payload-segmentet (starter også med eyJ, og er 50+ tegn)
# Vigtigt: brug .search() ikke .match() – header-segmentet er kun ~33 tegn
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{10,}")

# Minimumslængde for at en .env-værdi betragtes som en potentiel nøgle/hemmelighed
_MIN_KEY_LEN = 20

# Placeholder-værdier der ignoreres
_PLACEHOLDER_VALUES = {
    "", "your_key", "your_api_key", "xxx", "yyy", "change_me",
    "replace_me", "todo", "your_secret", "your_token", "placeholder",
    "example", "your_password", "your_url", "<your_key>", "<secret>",
    "CHANGE_ME", "REPLACE_ME",
}

ENV_GLOBS = [
    "**/.env", "**/.env.*", "**/env.local", "**/.env.local",
    "**/.env.development", "**/.env.production", "**/.env.staging",
    "**/.env.test", "**/.env.preview",
]


def _infer_role_from_name(var_name: str) -> str:
    """
    Gæt rolle fra variabelnavnet som fallback hvis JWT-decode ikke virker.
    Eksempel: SUPABASE_ANON_KEY → 'anon', SERVICE_ROLE_KEY → 'service_role'
    """
    upper = var_name.upper()
    if "SERVICE" in upper:
        return "service_role"
    if "ANON" in upper:
        return "anon"
    return "unknown"


def _decode_jwt_role(token: str) -> str | None:
    """
    Decode JWT payload (base64url) og returner 'role' feltet.
    Returnerer 'anon', 'service_role', eller anden rolle-streng.
    Returnerer None hvis token ikke kan parses.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload_b64 = parts[1]
    # Tilføj padding så base64 decode virker
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    try:
        decoded = base64.urlsafe_b64decode(payload_b64)
        data = json.loads(decoded)
        return data.get("role")
    except Exception:
        return None


def _is_placeholder_value(value: str) -> bool:
    """Returner True hvis værdien ser ud som en placeholder."""
    v = value.strip().strip('"').strip("'").strip()
    if not v or len(v) < 4:
        return True
    if v.lower() in {p.lower() for p in _PLACEHOLDER_VALUES}:
        return True
    if v.startswith("${") and v.endswith("}"):
        return True
    return False


def extract_all_env_values(project_path: str) -> dict:
    """
    Udtræk ALLE interessante værdier fra .env filer.

    Filosofi:
    - Enhver værdi med ≥ 20 tegn er en potentiel nøgle/hemmelighed (all_keys)
    - JWTs identificeres ved payload-decode med .search() (ikke .match())
    - Rolle gættes fra variabelnavn hvis JWT-decode ikke giver svar
    - Alle værdier ≥ 8 tegn gemmes til browser-probe dynamisk matching (all_values)

    Returnerer:
    {
        "anon_key": str | None,          # Bedste bud på anon-nøgle
        "anon_key_var": str | None,
        "service_role_key": str | None,  # Bedste bud på service_role-nøgle
        "service_role_var": str | None,
        "url": str | None,               # Database/Supabase URL
        "url_var": str | None,
        "all_keys": [                    # ALLE lange værdier (≥20 tegn) til RLS-probe
            {
                "var": "BESTEMORHANNE",
                "token": "7862378...",
                "role": "unknown",       # "anon" / "service_role" / "unknown"
                "is_jwt": False,
                "source": ".env"
            }
        ],
        "all_jwts": [...],               # Subset af all_keys: kun JWTs (bagudkompatibilitet)
        "all_values": {                  # Alle værdier ≥ 8 tegn til browser-probe
            "VAR_NAME": {"value": "...", "source": ".env"}
        }
    }
    """
    base = Path(project_path).resolve()
    result = {
        "anon_key": None, "anon_key_var": None,
        "service_role_key": None, "service_role_var": None,
        "url": None, "url_var": None,
        "all_keys": [],
        "all_jwts": [],   # bagudkompatibilitet
        "all_values": {},
    }

    env_files = []
    for pattern in ENV_GLOBS:
        env_files.extend(base.glob(pattern))

    env_files = [
        f for f in env_files
        if "node_modules" not in f.parts
        and ".git" not in f.parts
        and f.is_file()
        and not _is_safevibe_path(f)
    ]

    for env_file in env_files:
        rel = str(env_file.relative_to(base))
        try:
            content = env_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, _, raw_value = line.partition("=")
            key = key.strip()
            value = raw_value.strip().strip('"').strip("'").strip()

            if not value or _is_placeholder_value(value):
                continue

            # ── Browser-probe values (≥ 8 tegn) ──────────────────────────
            if len(value) >= 8:
                result["all_values"][key] = {"value": value, "source": rel}

            # ── URL detection ─────────────────────────────────────────────
            if re.match(r"https?://|mongodb|postgres|mysql|redis|libsql", value, re.I):
                if not result["url"]:
                    result["url"] = value[:120]
                    result["url_var"] = key

            # ── Potentielle nøgler: enhver værdi ≥ 20 tegn ───────────────
            if len(value) < _MIN_KEY_LEN:
                continue

            # Er det en JWT? Brug .search() så vi finder match i payload-segmentet
            # (header-segmentet er kun ~33 tegn – for kort for den gamle .match())
            is_jwt = bool(_JWT_RE.search(value))
            role = None

            if is_jwt:
                role = _decode_jwt_role(value)

            # Fallback: gæt rolle fra variabelnavnet
            if not role or role == "unknown":
                role = _infer_role_from_name(key)

            key_entry = {
                "var": key,
                "token": value,
                "role": role,
                "is_jwt": is_jwt,
                "source": rel,
            }
            result["all_keys"].append(key_entry)

            # Bagudkompatibilitet: all_jwts = subset af JWTs
            if is_jwt:
                result["all_jwts"].append(key_entry)

            # Klassificér til anon_key / service_role_key
            if role == "service_role" and not result["service_role_key"]:
                result["service_role_key"] = value
                result["service_role_var"] = key
            elif role == "anon" and not result["anon_key"]:
                result["anon_key"] = value
                result["anon_key_var"] = key
            elif role == "unknown" and not result["anon_key"]:
                # Ukendt rolle – gem som anon-fallback
                result["anon_key"] = value
                result["anon_key_var"] = key

    return result


def _is_safevibe_path(file_path: Path) -> bool:
    """Returner True hvis filen er en del af Safevibe's egne filer."""
    try:
        file_path.resolve().relative_to(SAFEVIBE_ROOT)
        return True
    except ValueError:
        return False

# ─── LAG 1: Env-var NAVNE der indikerer en database ─────────────────────────
# Matcher uanset prefix (NEXT_PUBLIC_, VITE_, REACT_APP_, PUBLIC_, custom osv.)
# Nøgle-navne genkendes på indhold af variabelnavnet
ENV_KEY_DB_PATTERNS = [
    # Supabase
    (re.compile(r"(?i)supabase.*(url|host|endpoint|anon|key|token|jwt|service)", re.I), "Supabase"),
    (re.compile(r"(?i)(url|host|endpoint|anon|key|token|jwt|service).*supabase", re.I), "Supabase"),
    # Neon
    (re.compile(r"(?i)neon.*(url|host|dsn|connection)", re.I), "Neon"),
    (re.compile(r"(?i)(url|dsn|connection).*neon", re.I), "Neon"),
    # PlanetScale
    (re.compile(r"(?i)planetscale.*(url|host|password|token)", re.I), "PlanetScale"),
    (re.compile(r"(?i)pscale.*(url|host|password|token)", re.I), "PlanetScale"),
    # Turso
    (re.compile(r"(?i)turso.*(url|token|auth|db)", re.I), "Turso"),
    (re.compile(r"(?i)(url|token|auth).*turso", re.I), "Turso"),
    # Upstash
    (re.compile(r"(?i)upstash.*(url|token|redis|rest|key)", re.I), "Upstash"),
    (re.compile(r"(?i)(url|token|redis|rest).*upstash", re.I), "Upstash"),
    # CockroachDB
    (re.compile(r"(?i)cockroach.*(url|dsn|connection|host)", re.I), "CockroachDB"),
    (re.compile(r"(?i)crdb.*(url|dsn)", re.I), "CockroachDB"),
    # Xata
    (re.compile(r"(?i)xata.*(url|token|key|branch|api)", re.I), "Xata"),
    # Convex
    (re.compile(r"(?i)convex.*(url|deploy|key|token)", re.I), "Convex"),
    # Hasura
    (re.compile(r"(?i)hasura.*(url|secret|key|admin|endpoint)", re.I), "Hasura"),
    # Appwrite
    (re.compile(r"(?i)appwrite.*(url|endpoint|key|project|secret)", re.I), "Appwrite"),
    # PocketBase
    (re.compile(r"(?i)pocketbase.*(url|host|admin|token)", re.I), "PocketBase"),
    # Fauna
    (re.compile(r"(?i)fauna.*(key|secret|token|url)", re.I), "Fauna"),
    # Firebase
    (re.compile(r"(?i)firebase.*(url|key|project|api|token|storage|auth)", re.I), "Firebase"),
    (re.compile(r"(?i)(url|key|project).*firebase", re.I), "Firebase"),
    # MongoDB / Atlas
    (re.compile(r"(?i)(mongo|mongodb).*(uri|url|dsn|connection|host|string)", re.I), "MongoDB"),
    (re.compile(r"(?i)(uri|url|dsn|host).*mongo", re.I), "MongoDB"),
    # PostgreSQL
    (re.compile(r"(?i)(postgres|postgresql).*(url|uri|dsn|connection|host|string)", re.I), "PostgreSQL"),
    (re.compile(r"(?i)(database_url|db_url|connection_string|dsn)", re.I), "Database URL"),
    # MySQL
    (re.compile(r"(?i)(mysql|mariadb).*(url|uri|dsn|host|connection)", re.I), "MySQL"),
    # Redis
    (re.compile(r"(?i)(redis).*(url|uri|host|connection|token|tls)", re.I), "Redis"),
    # MS SQL Server
    (re.compile(r"(?i)(mssql|sqlserver|sql_server).*(url|connection|host|dsn)", re.I), "MSSQL"),
    # SQLite
    (re.compile(r"(?i)(sqlite).*(path|file|db|url)", re.I), "SQLite"),
    # Generic database
    (re.compile(r"(?i)^(db|database)[_\-]?(url|uri|host|name|pass|password|user|string|dsn|port)$", re.I), "Database"),
    (re.compile(r"(?i)^(db|database)[_\-]?(url|uri|connection)$", re.I), "Database"),
]

# ─── LAG 2: Env-var VÆRDIER der matcher connection-string formater ───────────
ENV_VALUE_PATTERNS = [
    (re.compile(r"https://[a-z0-9]{8,}\.supabase\.co", re.I), "Supabase (cloud)", "url"),
    (re.compile(r"https?://[a-z0-9\-\.]+\.[a-z]{2,}.*supabase", re.I), "Supabase (self-hosted)", "url"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{10,}"), "Supabase/JWT key", "anon_key"),
    (re.compile(r"https?://[a-z0-9\-]+\.[a-z]{2,}\.neon\.tech", re.I), "Neon (serverless Postgres)", "url"),
    (re.compile(r"postgresql?://[^\s\"']+@[^\s\"']*\.neon\.tech", re.I), "Neon connection string", "url"),
    (re.compile(r"mysql://[^\s\"']+@[^\s\"']*\.psdb\.cloud", re.I), "PlanetScale", "url"),
    (re.compile(r"pscale://[^\s\"']+", re.I), "PlanetScale", "url"),
    (re.compile(r"libsql://[^\s\"']+\.turso\.io", re.I), "Turso", "url"),
    (re.compile(r"https?://[^\s\"']+\.turso\.io", re.I), "Turso", "url"),
    (re.compile(r"rediss?://[^\s\"']*\.upstash\.io", re.I), "Upstash Redis", "url"),
    (re.compile(r"https?://[^\s\"']+\.upstash\.io", re.I), "Upstash REST", "url"),
    (re.compile(r"postgresql?://[^\s\"']+\.cockroachlabs\.cloud", re.I), "CockroachDB", "url"),
    (re.compile(r"https?://[^\s\"']+\.xata\.sh", re.I), "Xata", "url"),
    (re.compile(r"https?://[^\s\"']+\.convex\.cloud", re.I), "Convex", "url"),
    (re.compile(r"https?://[^\s\"']+\.(hasura\.app|hasura\.io)", re.I), "Hasura", "url"),
    (re.compile(r"https?://[^\s\"']+\.appwrite\.io", re.I), "Appwrite", "url"),
    (re.compile(r"https?://[^\s\"']+\.(firebaseio|firebase\.google)\.com", re.I), "Firebase", "url"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Firebase API Key", "firebase_api_key"),
    (re.compile(r"mongodb(\+srv)?://[^\s\"']+", re.I), "MongoDB", "mongodb_url"),
    (re.compile(r"postgresql?://[^\s\"']+", re.I), "PostgreSQL", "postgres_url"),
    (re.compile(r"mysql://[^\s\"']+", re.I), "MySQL", "mysql_url"),
    (re.compile(r"mariadb://[^\s\"']+", re.I), "MariaDB", "mariadb_url"),
    (re.compile(r"rediss?://[^\s\"']+", re.I), "Redis", "redis_url"),
    (re.compile(r"sqlserver://[^\s\"']+", re.I), "MS SQL Server", "mssql_url"),
    (re.compile(r"mssql://[^\s\"']+", re.I), "MS SQL Server", "mssql_url"),
    (re.compile(r"https?://fauna\.com|fnAETA[A-Za-z0-9_\-]+", re.I), "Fauna", "url"),
]

# ─── LAG 3: Prisma provider-mapping ─────────────────────────────────────────
PRISMA_PROVIDER_MAP = {
    "postgresql": "PostgreSQL (Prisma)",
    "postgres": "PostgreSQL (Prisma)",
    "mysql": "MySQL (Prisma)",
    "sqlite": "SQLite (Prisma)",
    "sqlserver": "MS SQL Server (Prisma)",
    "mongodb": "MongoDB (Prisma)",
    "cockroachdb": "CockroachDB (Prisma)",
}

# ─── LAG 4: HTML/Header-scanning mønstre ────────────────────────────────────
SUPABASE_URL_RE = re.compile(r"https://[a-z0-9]{4,}\.supabase\.co", re.IGNORECASE)
SUPABASE_KEY_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{10,}")
FIREBASE_RE     = re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com", re.IGNORECASE)
FIREBASE_KEY_RE = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
NEON_RE         = re.compile(r"https?://[a-z0-9\-]+\.[a-z]+\.neon\.tech", re.IGNORECASE)
CONVEX_RE       = re.compile(r"https?://[a-z0-9\-]+\.convex\.cloud", re.IGNORECASE)
TURSO_RE        = re.compile(r"libsql://[a-z0-9\-]+\.turso\.io", re.IGNORECASE)
UPSTASH_RE      = re.compile(r"https?://[a-z0-9\-]+\.upstash\.io", re.IGNORECASE)
HASURA_RE       = re.compile(r"https?://[a-z0-9\-]+\.(hasura\.app|hasura\.io)", re.IGNORECASE)
MONGO_RE        = re.compile(r"mongodb(\+srv)?://[^\s\"'<>]+", re.IGNORECASE)
POSTGRES_RE     = re.compile(r"postgresql?://[^\s\"'<>]+", re.IGNORECASE)

SCAN_EXTENSIONS = {
    ".env", ".local", ".js", ".jsx", ".ts", ".tsx",
    ".mjs", ".cjs", ".json", ".toml", ".yaml", ".yml",
    ".config", ".ini", ".cfg",
}
SCAN_FILENAMES = {
    ".env", ".env.local", ".env.development", ".env.production",
    ".env.staging", ".env.test", ".env.preview", ".env.vault",
    ".envrc", "wrangler.toml", "netlify.toml", "vercel.json",
    "railway.toml", "fly.toml", "docker-compose.yml",
    "docker-compose.yaml", ".npmrc",
}
EXCLUDE_DIRS = {"node_modules", ".git", ".next", "dist", "build", ".turbo", "out", ".svelte-kit"}


def _read_file_safe(file_path: Path) -> str:
    try:
        return file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _detect_from_prisma(project_path: str) -> dict | None:
    """Lag 3: Parse prisma/schema.prisma for database provider."""
    base = Path(project_path)

    # Find alle schema.prisma filer
    for schema_path in base.rglob("schema.prisma"):
        if any(excl in schema_path.parts for excl in EXCLUDE_DIRS):
            continue
        content = _read_file_safe(schema_path)
        if not content:
            continue

        provider_match = re.search(r'provider\s*=\s*["\']([a-zA-Z]+)["\']', content)
        if provider_match:
            provider = provider_match.group(1).lower()
            db_name = PRISMA_PROVIDER_MAP.get(provider, f"Database (Prisma/{provider})")

            # Udtræk DATABASE_URL
            url_env_match = re.search(r'url\s*=\s*env\(["\']([^"\']+)["\']\)', content)
            direct_url_match = re.search(r'url\s*=\s*["\']([^"\']+)["\']', content)

            result = {
                "type": db_name,
                "prisma": True,
                "schema_file": str(schema_path.relative_to(base)),
                "provider": provider,
            }
            if url_env_match:
                result["url_env_var"] = url_env_match.group(1)
            if direct_url_match:
                url_val = direct_url_match.group(1)
                if not url_val.startswith("env("):
                    result["url"] = url_val[:80]

            return result

    # Drizzle config
    for drizzle_path in list(base.rglob("drizzle.config.*")) + list(base.rglob("drizzle.config")):
        if any(excl in drizzle_path.parts for excl in EXCLUDE_DIRS):
            continue
        content = _read_file_safe(drizzle_path)
        if "drizzle" in content.lower() or "dialect" in content.lower():
            dialect_match = re.search(r'dialect\s*[:=]\s*["\']([a-zA-Z]+)["\']', content)
            db_type = f"Database (Drizzle/{dialect_match.group(1)})" if dialect_match else "Database (Drizzle ORM)"
            return {
                "type": db_type,
                "drizzle": True,
                "schema_file": str(drizzle_path.relative_to(base)),
            }

    return None


def _detect_from_env_keys(project_path: str) -> dict | None:
    """Lag 1: Match env var NAVNE mod kendte DB-teknologi-navne."""
    base = Path(project_path).resolve()
    result = {}

    for file_path in base.rglob("*"):
        # Self-scan prevention
        try:
            file_path.resolve().relative_to(SAFEVIBE_ROOT)
            continue
        except ValueError:
            pass

        if any(excl in file_path.parts for excl in EXCLUDE_DIRS):
            continue
        if file_path.name not in SCAN_FILENAMES and not file_path.name.startswith(".env"):
            continue
        if not file_path.is_file():
            continue

        content = _read_file_safe(file_path)
        rel = str(file_path.relative_to(base))

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if not value or value.startswith("your_") or value == "xxx":
                continue

            for pattern, db_tech in ENV_KEY_DB_PATTERNS:
                if pattern.search(key):
                    if not result.get("type"):
                        result["type"] = db_tech
                        result["key_env_var"] = key
                        result["key_source"] = rel

                    # Gem værdien hvis det ligner en URL
                    if re.match(r"https?://|mongodb|postgres|mysql|redis|libsql|pscale|mssql", value, re.I):
                        if not result.get("url"):
                            result["url"] = value[:80]

                    # Udtræk JWT-value som anon_key (LAG 1 kan nu finde nøglen)
                    if _JWT_RE.search(value) and not result.get("anon_key"):
                        result["anon_key"] = value
                        result.setdefault("type", db_tech)

                    break

    return result if result else None


def _detect_from_env_values(project_path: str) -> dict | None:
    """Lag 2: Match env var VÆRDIER mod kendte connection-string formater."""
    base = Path(project_path).resolve()
    result = {}

    for file_path in base.rglob("*"):
        # Self-scan prevention
        try:
            file_path.resolve().relative_to(SAFEVIBE_ROOT)
            continue
        except ValueError:
            pass

        if any(excl in file_path.parts for excl in EXCLUDE_DIRS):
            continue

        is_scannable = (
            file_path.suffix.lower() in SCAN_EXTENSIONS or
            file_path.name in SCAN_FILENAMES or
            file_path.name.startswith(".env")
        )
        if not is_scannable or not file_path.is_file():
            continue

        content = _read_file_safe(file_path)
        rel = str(file_path.relative_to(base))

        for val_pattern, db_tech, field in ENV_VALUE_PATTERNS:
            m = val_pattern.search(content)
            if m:
                if not result.get("type"):
                    result["type"] = db_tech
                if field == "anon_key" and not result.get("anon_key"):
                    result["anon_key"] = m.group(0)
                    result["key_source"] = rel
                elif field == "firebase_api_key" and not result.get("firebase_api_key"):
                    result["firebase_api_key"] = m.group(0)
                    result["key_source"] = rel
                elif not result.get("url") and field not in ("anon_key", "firebase_api_key"):
                    result["url"] = m.group(0)[:80]
                    result["url_source"] = rel

        # INGEN break her – scan ALLE filer for ALLE felter
        # URL kan sidde i vercel.json og anon_key i .env

    return result if result else None


def _detect_from_headers(base_url: str) -> dict | None:
    """Lag 4: Analyser live HTTP response headers + HTML body."""
    if requests is None or not base_url:
        return None

    try:
        resp = requests.get(base_url, timeout=5)
        body = resp.text
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception:
        return None

    result = {}

    # Supabase cloud
    m = SUPABASE_URL_RE.search(body)
    if m:
        result["type"] = "Supabase"
        result["url"] = m.group(0)
        result["source"] = "html-body"

    m = SUPABASE_KEY_RE.search(body)
    if m:
        result.setdefault("type", "Supabase")
        result["anon_key"] = m.group(0)
        result["source"] = "html-body"

    # Firebase
    if not result.get("type"):
        m = FIREBASE_RE.search(body)
        if m:
            result["type"] = "Firebase"
            result["url"] = m.group(0)
    m = FIREBASE_KEY_RE.search(body)
    if m:
        result.setdefault("type", "Firebase")
        result["firebase_api_key"] = m.group(0)

    # Neon
    if not result.get("type"):
        m = NEON_RE.search(body)
        if m:
            result["type"] = "Neon"
            result["url"] = m.group(0)

    # Convex
    if not result.get("type"):
        m = CONVEX_RE.search(body)
        if m:
            result["type"] = "Convex"
            result["url"] = m.group(0)

    # Turso
    if not result.get("type"):
        m = TURSO_RE.search(body)
        if m:
            result["type"] = "Turso"
            result["url"] = m.group(0)

    # Upstash
    if not result.get("type"):
        m = UPSTASH_RE.search(body)
        if m:
            result["type"] = "Upstash"
            result["url"] = m.group(0)

    # Hasura
    if not result.get("type"):
        m = HASURA_RE.search(body)
        if m:
            result["type"] = "Hasura"
            result["url"] = m.group(0)

    # MongoDB i HTML (sjældent, men muligt i fejlbeskeder)
    if not result.get("type"):
        m = MONGO_RE.search(body)
        if m:
            result["type"] = "MongoDB"
            result["mongodb_url"] = m.group(0)[:60] + "..."

    # Supabase headers
    for h in ["x-client-info", "sb-gateway-version", "x-supabase"]:
        if h in headers:
            result.setdefault("type", "Supabase")
            result["header_detected"] = h

    # Firebase headers
    for h in ["x-firebase-appcheck", "x-firebase-locale"]:
        if h in headers:
            result.setdefault("type", "Firebase")
            result["header_detected"] = h

    return result if result else None


def detect_database(project_path: str, base_url: str = None) -> dict | None:
    """
    Komplet 4-lags database-detektion:
    1. Live HTML/header scanning (hurtigst + mest nøjagtigt)
    2. Prisma schema / Drizzle config
    3. Env var NAVNE-baseret detektion
    4. Env var VÆRDIER / connection-string matching

    Returnerer kombineret resultat fra alle lag.
    """
    combined = {}

    # Lag 4: Live header/HTML (primær – mest troværdig)
    if base_url:
        header_result = _detect_from_headers(base_url)
        if header_result:
            header_result["method"] = "header-first"
            combined.update(header_result)

    # Lag 3: Prisma/Drizzle schema
    prisma_result = _detect_from_prisma(project_path)
    if prisma_result:
        if not combined.get("type"):
            combined.update(prisma_result)
        else:
            # Berig eksisterende resultat med Prisma-info
            combined["prisma"] = prisma_result.get("prisma", False)
            combined["schema_file"] = prisma_result.get("schema_file")
            combined["provider"] = prisma_result.get("provider")
        if not combined.get("method"):
            combined["method"] = "prisma-schema"

    # Lag 1: Env var NAVNE
    if not combined.get("type"):
        key_result = _detect_from_env_keys(project_path)
        if key_result:
            combined.update(key_result)
            combined.setdefault("method", "env-key-name")

    # Lag 2: Env var VÆRDIER / connection strings
    value_result = _detect_from_env_values(project_path)
    if value_result:
        if not combined.get("type"):
            combined.update(value_result)
        else:
            # Berig med ekstra info fra værdier
            for k in ("url", "anon_key", "firebase_api_key", "mongodb_url", "postgres_url"):
                if value_result.get(k) and not combined.get(k):
                    combined[k] = value_result[k]
        combined.setdefault("method", "env-value-scan")

    # Lag 5: Dynamisk JWT extraction via base64 decode (mest præcist)
    env_extracted = extract_all_env_values(project_path)
    if env_extracted:
        # Sæt URL hvis ikke allerede fundet
        if env_extracted.get("url") and not combined.get("url"):
            combined["url"] = env_extracted["url"]
            combined["url_var"] = env_extracted.get("url_var")
        # Sæt anon_key med korrekt role-verificering
        if env_extracted.get("anon_key") and not combined.get("anon_key"):
            combined["anon_key"] = env_extracted["anon_key"]
            combined["anon_key_var"] = env_extracted.get("anon_key_var")
        # Sæt service_role_key (kritisk!)
        if env_extracted.get("service_role_key"):
            combined["service_role_key"] = env_extracted["service_role_key"]
            combined["service_role_var"] = env_extracted.get("service_role_var")
        # Gem alle fundne nøgler til RLS-probe brug
        if env_extracted.get("all_keys"):
            combined["all_keys"] = env_extracted["all_keys"]
        if env_extracted.get("all_jwts"):
            combined["all_jwts"] = env_extracted["all_jwts"]
        # Sæt type hvis stadig ikke fundet
        if not combined.get("type") and (env_extracted.get("anon_key") or env_extracted.get("url")):
            combined["type"] = "Supabase"

    return combined if combined else None


def get_all_databases(project_path: str, base_url: str = None) -> list[dict]:
    """
    Avanceret version: finder ALLE databaser i projektet (ikke kun den første).
    Returnerer en liste – et projekt kan godt bruge både Supabase OG Redis OG Prisma.
    """
    found = []
    seen_types = set()

    # Lag 4
    if base_url:
        r = _detect_from_headers(base_url)
        if r and r.get("type") not in seen_types:
            r["method"] = "header-first"
            found.append(r)
            seen_types.add(r.get("type"))

    # Lag 3
    r = _detect_from_prisma(project_path)
    if r and r.get("type") not in seen_types:
        r.setdefault("method", "prisma-schema")
        found.append(r)
        seen_types.add(r.get("type"))

    # Lag 2 (value scan – søg alle matches)
    base = Path(project_path)
    for file_path in base.rglob("*"):
        # Self-scan prevention
        try:
            file_path.resolve().relative_to(SAFEVIBE_ROOT)
            continue
        except ValueError:
            pass
        
        if any(excl in file_path.parts for excl in EXCLUDE_DIRS):
            continue
        is_scannable = (
            file_path.suffix.lower() in SCAN_EXTENSIONS or
            file_path.name in SCAN_FILENAMES or
            file_path.name.startswith(".env")
        )
        if not is_scannable or not file_path.is_file():
            continue
        content = _read_file_safe(file_path)
        rel = str(file_path.relative_to(base))

        for val_pattern, db_tech, field in ENV_VALUE_PATTERNS:
            m = val_pattern.search(content)
            if m and db_tech not in seen_types:
                entry = {"type": db_tech, "method": "env-value-scan", "url_source": rel}
                if field == "anon_key":
                    entry["anon_key"] = m.group(0)
                elif field == "firebase_api_key":
                    entry["firebase_api_key"] = m.group(0)
                else:
                    entry["url"] = m.group(0)[:80]
                found.append(entry)
                seen_types.add(db_tech)

    return found
