"""
rls_prober.py – Aktiv RLS (Row Level Security) probe mod Supabase.
Understøtter både cloud (*.supabase.co) og self-hosted Supabase installationer.
"""

import re
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None

# Safevibe's egen rodmappe – ekskluderes fra scanning så vi ikke scanner os selv
SAFEVIBE_ROOT = Path(__file__).resolve().parent.parent.parent

# Import til dynamisk JWT extraction
try:
    from engine.dynamic.db_detector import extract_all_env_values
except ImportError:
    extract_all_env_values = None

# Kritiske tabeller der altid testes uanset hvad koden bruger
CRITICAL_TABLES = [
    "users", "profiles", "user_profiles", "accounts",
    "orders", "payments", "transactions", "invoices",
    "messages", "notifications", "chats",
    "admin", "admins", "roles", "permissions",
    "secrets", "tokens", "sessions", "api_keys",
    "subscriptions", "plans",
    "personal_data", "kyc", "documents",
    "audit_logs", "logs",
    "products", "inventory",
    "comments", "posts", "content",
]

# Mønstre til at udtrække tabelnavne fra kildekode
FROM_PATTERNS = [
    # Supabase .from('table') - enkelt og dobbelcitater
    re.compile(r"\.from\(['\"]([a-zA-Z0-9_]+)['\"]\)"),
    # Supabase .from(`table`) - template literals
    re.compile(r"\.from\(`([a-zA-Z0-9_]+)`\)"),
    # Prisma: prisma.tableName.findMany() / prisma.table_name.create()
    re.compile(r"prisma\.([a-zA-Z0-9_]+)\.(find|create|update|delete|upsert|count|aggregate)"),
    # Drizzle: db.select().from(table) / db.insert(table)
    re.compile(r"db\.(select|insert|update|delete)\([^)]*\)\.from\(([a-zA-Z0-9_]+)\)"),
    # Raw SQL: FROM tablename eller INSERT INTO tablename
    re.compile(r"(?i)(?:FROM|INTO|UPDATE|TABLE)\s+[`'\"]?([a-zA-Z0-9_]+)[`'\"]?\s"),
    # TypeORM: @Entity('tablename')
    re.compile(r"@Entity\(['\"`]([a-zA-Z0-9_]+)['\"`]\)"),
    # Sequelize: sequelize.define('tablename')
    re.compile(r"sequelize\.define\(['\"]([a-zA-Z0-9_]+)['\"]"),
]

SCAN_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py"}
EXCLUDE_DIRS = {"node_modules", ".git", ".next", "dist", "build", ".turbo", "__pycache__"}

# Supabase REST API endpoint mønstre
SUPABASE_REST_PATHS = ["/rest/v1", "/api/v1"]


def _is_supabase_url(url: str) -> bool:
    """Tjek om URL er en Supabase instans (cloud eller self-hosted)."""
    if not url:
        return False
    # Cloud Supabase
    if re.search(r"[a-z0-9]+\.supabase\.co", url, re.IGNORECASE):
        return True
    # Self-hosted kan have enhver domain – tjek om REST API svarer
    return False


def _find_supabase_url_from_files(project_path: str) -> str | None:
    """Find Supabase URL fra filer (inkl. self-hosted)."""
    base = Path(project_path)

    # Søg i env-filer
    env_url_patterns = [
        re.compile(r"(?i)(?:SUPABASE|NEXT_PUBLIC_SUPABASE|VITE_SUPABASE|PUBLIC_SUPABASE)[A-Z_]*URL[A-Z_]*\s*=\s*(.+)"),
        re.compile(r"(?i)(?:REACT_APP_|NUXT_|EXPO_PUBLIC_)?SUPABASE[A-Z_]*URL\s*=\s*(.+)"),
    ]

    for file_path in base.rglob("*"):
        # Self-scan prevention
        try:
            file_path.resolve().relative_to(SAFEVIBE_ROOT)
            continue
        except ValueError:
            pass

        if any(excl in file_path.parts for excl in EXCLUDE_DIRS):
            continue
        if not (file_path.name.startswith(".env") or file_path.suffix in (".env",)):
            continue
        if not file_path.is_file():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for line in content.splitlines():
            for pat in env_url_patterns:
                m = pat.search(line)
                if m:
                    url = m.group(1).strip().strip('"').strip("'")
                    if url.startswith("http"):
                        return url

    # Søg i kildekode
    code_patterns = [
        re.compile(r"createClient\s*\(\s*['\"`](https?://[^'\"`]+)['\"`]"),
        re.compile(r"SUPABASE_URL\s*[:=]\s*['\"`](https?://[^'\"`]+)['\"`]"),
    ]

    for file_path in base.rglob("*"):
        # Self-scan prevention
        try:
            file_path.resolve().relative_to(SAFEVIBE_ROOT)
            continue
        except ValueError:
            pass

        if any(excl in file_path.parts for excl in EXCLUDE_DIRS):
            continue
        if file_path.suffix.lower() not in {".js", ".ts", ".tsx", ".jsx", ".mjs"}:
            continue
        if not file_path.is_file():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for pat in code_patterns:
            m = pat.search(content)
            if m:
                return m.group(1).strip()

    return None


def extract_tables_from_code(project_path: str) -> list[str]:
    """Udtræk tabelnavne brugt i kildekoden via multiple mønstre."""
    tables = set()
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
        if file_path.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        if not file_path.is_file():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for pattern in FROM_PATTERNS:
            for match in pattern.finditer(content):
                # Nogle patterns har table i gruppe 1, andre i gruppe 2
                table_name = match.group(1) if match.lastindex >= 1 else None
                if table_name and len(table_name) > 1 and not table_name.startswith("_"):
                    tables.add(table_name.lower())

    return list(tables)


# Auth-kombinationer der testes for hver nøgle
# Orden: mest sandsynlig → mindst sandsynlig
_AUTH_COMBOS = [
    # Navn, header-builder
    ("apikey+bearer", lambda k: {"apikey": k, "Authorization": f"Bearer {k}"}),
    ("apikey-only",   lambda k: {"apikey": k}),
    ("bearer-only",   lambda k: {"Authorization": f"Bearer {k}"}),
    ("no-auth",       lambda k: {}),
]


def _probe_supabase_rest(
    supabase_url: str,
    key_token: str,
    tables: list[str],
    key_var: str = "unknown",
    key_role: str = "unknown",
    is_jwt: bool = True,
) -> list[dict]:
    """
    Test Supabase REST API for åbne tabeller uden RLS.

    Prøver ALLE 4 auth-kombinationer:
      1. apikey + Authorization: Bearer (standard Supabase)
      2. apikey alene
      3. Authorization: Bearer alene
      4. Ingen auth (baseline – hvad kan alle se?)

    Accepterer enhver nøgle-type: JWT, plain API-key, osv.
    """
    if requests is None:
        return [{"severity": "info", "description": "RLS-probe kræver requests-pakken (kør: python install.py)", "detail": ""}]

    findings = []
    all_tables = list(set([t.lower() for t in tables] + [t.lower() for t in CRITICAL_TABLES]))

    # Normaliser URL
    base_url = supabase_url.rstrip("/")
    rest_base = f"{base_url}/rest/v1"

    # Find fungerende REST endpoint
    base_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    try:
        probe_headers = {**base_headers, "apikey": key_token, "Authorization": f"Bearer {key_token}"}
        test_resp = requests.get(f"{rest_base}/", headers=probe_headers, timeout=5)
        if test_resp.status_code == 404:
            rest_base = f"{base_url}/api/v1"
            # Prøv igen
            test_resp = requests.get(f"{rest_base}/", headers=probe_headers, timeout=5)
            if test_resp.status_code == 404:
                return [{"severity": "info", "description": f"Supabase REST API ikke fundet på {supabase_url}", "detail": "Prøvede /rest/v1 og /api/v1"}]
    except requests.exceptions.RequestException as e:
        return [{"severity": "info", "description": f"Kan ikke forbinde til {supabase_url} ({key_var})", "detail": str(e)[:80]}]

    is_service_role = key_role == "service_role"
    seen_table_combos = set()  # (table, auth_combo) – undgå duplikate fund

    for table in all_tables:
        url = f"{rest_base}/{table}?limit=1"

        for combo_name, header_fn in _AUTH_COMBOS:
            auth_headers = {**base_headers, **header_fn(key_token)}
            try:
                resp = requests.get(url, headers=auth_headers, timeout=5)
            except requests.exceptions.RequestException:
                continue

            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    data = []

                if isinstance(data, list) and len(data) > 0:
                    dedup_key = (table, key_var)
                    if dedup_key in seen_table_combos:
                        continue
                    seen_table_combos.add(dedup_key)

                    if combo_name == "no-auth":
                        description = f"🚨 TABEL '{table}' ÅBEN UDEN AUTH – ingen nøgle påkrævet!"
                        detail = (
                            f"Tabellen returnerer {len(data)} rækker UDEN nogen form for autentificering. "
                            f"Alle på internettet kan læse data. Aktiver RLS STRAKS."
                        )
                        severity = "critical"
                    elif is_service_role:
                        description = (
                            f"🚨 SERVICE_ROLE KEY ({key_var}) kan læse '{table}' – "
                            f"denne nøgle er ALDRIG sikker i frontend/klient-kode"
                        )
                        detail = (
                            f"service_role ({key_var}) via [{combo_name}] returnerer {len(data)} rækker fra /{table}. "
                            f"service_role omgår RLS og hører UDELUKKENDE i server-side kode."
                        )
                        severity = "critical"
                    else:
                        key_type = "JWT" if is_jwt else "API-nøgle"
                        description = (
                            f"RLS MANGLER på '{table}' – data tilgængeligt via {key_var} "
                            f"(role: {key_role}, type: {key_type})"
                        )
                        detail = (
                            f"{key_var} via [{combo_name}] returnerer {len(data)} rækker fra /{table}. "
                            f"Aktiver RLS i Supabase Dashboard → Authentication → Policies."
                        )
                        severity = "critical"

                    findings.append({
                        "table": table,
                        "severity": severity,
                        "description": description,
                        "detail": detail,
                        "rows_returned": len(data),
                        "key_var": key_var,
                        "key_role": key_role,
                        "auth_combo": combo_name,
                    })
                    # Hvis vi fandt data – stop med at prøve andre auth-combos for samme tabel
                    break

            elif resp.status_code in (401, 403):
                # RLS/auth blokerer – det er godt, prøv næste combo
                pass

    return findings


def _direct_env_scan_for_keys(project_path: str) -> list[dict]:
    """
    Absolut last-resort: scan .env filer direkte for alle lange værdier.
    Bruges hvis extract_all_env_values returnerer ingenting.
    Finder 'bestemorhanne=7862378219838473982744783274237849' og lignende.
    """
    base = Path(project_path).resolve()
    found = []
    seen_values = set()

    for file_path in base.rglob("*"):
        try:
            file_path.resolve().relative_to(SAFEVIBE_ROOT)
            continue
        except ValueError:
            pass

        if any(excl in file_path.parts for excl in EXCLUDE_DIRS):
            continue
        if not (file_path.name.startswith(".env") or file_path.suffix == ".env"):
            continue
        if not file_path.is_file():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel = str(file_path.relative_to(base))
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, raw_value = line.partition("=")
            key = key.strip()
            value = raw_value.strip().strip('"').strip("'").strip()
            if len(value) >= 20 and value not in seen_values:
                seen_values.add(value)
                upper = key.upper()
                role = "service_role" if "SERVICE" in upper else ("anon" if "ANON" in upper else "unknown")
                found.append({
                    "var": key,
                    "token": value,
                    "role": role,
                    "is_jwt": False,
                    "source": rel,
                })

    return found


def run_rls_probe(project_path: str, db_info: dict) -> dict:
    """
    Samlet RLS-probe mod Supabase.

    Finder ALLE nøgler i .env (uanset variabelnavn og nøgle-type) og tester
    dem med ALLE 4 auth-kombinationer mod Supabase REST API.

    Fallback-rækkefølge for nøgler:
    1. db_info["all_keys"]  (fra detect_database → extract_all_env_values)
    2. extract_all_env_values(project_path)["all_keys"]  (direkte kald)
    3. db_info["anon_key"] / db_info["service_role_key"]  (klassisk)
    4. _direct_env_scan_for_keys()  (absolut last-resort: råscanning)
    """
    if not db_info:
        return {"skipped": True, "reason": "Ingen database-info tilgængelig", "findings": []}

    db_type = db_info.get("type", "")

    if "Supabase" not in db_type:
        return {"skipped": True, "reason": f"RLS-probe understøtter kun Supabase (fundet: {db_type})", "findings": []}

    supabase_url = db_info.get("url")
    if not supabase_url:
        supabase_url = _find_supabase_url_from_files(project_path)
    if not supabase_url:
        return {"skipped": True, "reason": "Supabase URL ikke fundet (hverken i env eller kode)", "findings": []}

    # ── Saml nøgler i prioriteret rækkefølge ─────────────────────────────────
    all_keys = db_info.get("all_keys", [])

    if not all_keys and extract_all_env_values is not None:
        env_data = extract_all_env_values(project_path)
        all_keys = env_data.get("all_keys", [])
        if not supabase_url and env_data.get("url"):
            supabase_url = env_data["url"]

    # Klassisk fallback: anon_key / service_role_key fra db_info
    if not all_keys:
        anon_key = db_info.get("anon_key")
        service_key = db_info.get("service_role_key")
        if anon_key:
            all_keys.append({"var": db_info.get("anon_key_var", "ANON_KEY"), "token": anon_key, "role": "anon", "is_jwt": True})
        if service_key:
            all_keys.append({"var": db_info.get("service_role_var", "SERVICE_ROLE_KEY"), "token": service_key, "role": "service_role", "is_jwt": True})

    # Absolut last-resort: råscanning af .env filer
    if not all_keys:
        all_keys = _direct_env_scan_for_keys(project_path)

    if not all_keys:
        return {"skipped": True, "reason": "Ingen nøgler/tokens fundet i .env filer – kan ikke teste RLS", "findings": []}

    # Deduplikér nøgler på token-værdi
    seen_tokens = set()
    unique_keys = []
    for k in all_keys:
        if k.get("token") and k["token"] not in seen_tokens:
            seen_tokens.add(k["token"])
            unique_keys.append(k)

    # Udtræk tabelnavne fra kildekode
    code_tables = extract_tables_from_code(project_path)
    all_tested = list(set([t.lower() for t in code_tables] + [t.lower() for t in CRITICAL_TABLES]))

    # ── Test ALLE keys med ALLE auth-kombinationer ────────────────────────────
    all_findings = []
    keys_tested = []

    for key_entry in unique_keys:
        key_token = key_entry.get("token", "")
        key_var   = key_entry.get("var", "UNKNOWN")
        key_role  = key_entry.get("role", "unknown")
        is_jwt    = key_entry.get("is_jwt", False)

        if not key_token:
            continue

        keys_tested.append(f"{key_var} (role: {key_role}, jwt: {is_jwt})")

        key_findings = _probe_supabase_rest(
            supabase_url, key_token, code_tables,
            key_var=key_var, key_role=key_role, is_jwt=is_jwt,
        )
        all_findings.extend(key_findings)

    return {
        "skipped": False,
        "supabase_url": supabase_url,
        "is_self_hosted": "supabase.co" not in supabase_url.lower(),
        "tables_probed": all_tested,
        "code_tables_found": code_tables,
        "keys_tested": keys_tested,
        "findings": all_findings,
    }
