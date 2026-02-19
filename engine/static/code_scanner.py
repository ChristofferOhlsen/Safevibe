"""
code_scanner.py – Statisk analyse af JS/TS/Python/PHP kildekode.
Scanner for kendte sikkerhedsmønstre, farlig praksis og dårlige mønstre.
"""

import re
from pathlib import Path

# Safevibe's egen rodmappe – ekskluderes fra scanning så vi ikke scanner os selv
SAFEVIBE_ROOT = Path(__file__).resolve().parent.parent.parent

# ─── FORMAT: (regex, beskrivelse, severity, stack-filter eller None) ─────────
CODE_CHECKS = [

    # ── XSS ──────────────────────────────────────────────────────────────────
    (r"dangerouslySetInnerHTML\s*=\s*\{",
     "dangerouslySetInnerHTML – potentiel XSS",
     "critical", "React"),

    (r"\.innerHTML\s*=\s*(?!(['\"])\s*\2)",  # Ikke tom streng
     "Direkte innerHTML-tildeling – potentiel XSS",
     "critical", None),

    (r"\.outerHTML\s*=\s*",
     "Direkte outerHTML-tildeling – potentiel XSS",
     "critical", None),

    (r"document\.write\s*\(",
     "document.write() – potentiel XSS",
     "warning", None),

    (r"\.insertAdjacentHTML\s*\(",
     "insertAdjacentHTML() – potentiel XSS hvis brugerdata indsættes",
     "warning", None),

    # ── Kode-injektion ────────────────────────────────────────────────────────
    (r"\beval\s*\(",
     "eval() – potentiel kode-injektion",
     "critical", None),

    (r"new\s+Function\s*\(",
     "new Function() – potentiel kode-injektion (som eval)",
     "critical", None),

    (r"setTimeout\s*\(\s*['\"`][^'\"`,]+\$\{",
     "setTimeout med template literal – potentiel injektion",
     "warning", None),

    # ── Command Injection (Node.js) ───────────────────────────────────────────
    (r"(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*(?:[`'\"].*\$\{|.*\+\s*(?:req\.|user|input|param|query))",
     "Command injection – exec() med bruger-input / string interpolation",
     "critical", None),

    (r"child_process\s*\.\s*(?:exec|execSync|spawn)\s*\(",
     "child_process.exec/spawn brugt – tjek for bruger-input",
     "warning", None),

    # ── Path Traversal (Node.js) ──────────────────────────────────────────────
    (r"(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
     "fs.readFile med request-parameter – mulig path traversal",
     "critical", None),

    # ── SQL Injection ─────────────────────────────────────────────────────────
    (r"(?i)([`'\"])SELECT .+\$\{",
     "SQL-injektion via template literal interpolation",
     "critical", None),

    (r"(?i)([`'\"])(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER).+\+\s*(?:req\.|user|input|param|query)",
     "SQL-injektion via strengsammensætning",
     "critical", None),

    # ── Prototype Pollution ───────────────────────────────────────────────────
    (r"Object\.assign\s*\(\s*\{\s*\}\s*,\s*req\.",
     "Object.assign med req.body – mulig prototype pollution",
     "warning", None),

    (r"_\.merge\s*\([^,]+,\s*req\.",
     "_.merge med req.body – mulig prototype pollution (lodash)",
     "warning", None),

    (r"\[['\"]\s*__proto__\s*['\"]\]",
     "__proto__ tildeling – prototype pollution risiko",
     "critical", None),

    (r"\[['\"]\s*constructor\s*['\"]\]\s*\[['\"]\s*prototype",
     "constructor.prototype manipulation – prototype pollution",
     "critical", None),

    # ── Open Redirect ─────────────────────────────────────────────────────────
    (r"res\.redirect\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
     "res.redirect() med request-parameter – mulig open redirect",
     "warning", None),

    (r"window\.location\s*(?:\.href\s*=|\.replace\s*\()\s*(?:req\.|params\.|query\.|.*\+)",
     "window.location redirect med variabel – mulig open redirect",
     "warning", None),

    # ── Hardcodede secrets i kode ─────────────────────────────────────────────
    (r"(?i)(api_key|apikey|api[-_]key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{10,}['\"]",
     "Hardcodet API-nøgle i kildekode",
     "critical", None),

    (r"(?i)(password|passwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
     "Hardcodet adgangskode i kildekode",
     "critical", None),

    (r"sk-[A-Za-z0-9]{20,}",
     "OpenAI API-nøgle hardcodet",
     "critical", None),

    (r"sk-ant-[A-Za-z0-9\-_]{40,}",
     "Anthropic/Claude API-nøgle hardcodet",
     "critical", None),

    (r"ghp_[A-Za-z0-9]{36}",
     "GitHub PAT hardcodet",
     "critical", None),

    (r"AKIA[A-Z0-9]{16}",
     "AWS Access Key hardcodet",
     "critical", None),

    (r"AIza[0-9A-Za-z\-_]{35}",
     "Google/Firebase API-nøgle hardcodet",
     "critical", None),

    (r"whsec_[A-Za-z0-9]{32,}",
     "Stripe Webhook Secret hardcodet",
     "critical", None),

    (r"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+",
     "Slack Bot Token hardcodet",
     "critical", None),

    # ── Supabase service_role i kode ──────────────────────────────────────────
    (r"['\"]service_role['\"]|SERVICE_ROLE[A-Z_]*\s*[:=]",
     "Supabase service_role nøgle i klientkode – kritisk eksponering",
     "critical", None),

    # ── Usikker kryptografi ───────────────────────────────────────────────────
    (r"Math\.random\s*\(\s*\).*(?:token|session|secret|password|nonce|csrf|salt|key)",
     "Math.random() til sikkerhedsformål – ikke kryptografisk sikker",
     "critical", None),

    (r"(?i)(?:createCipher|createDecipher)\s*\(",
     "Forældet crypto.createCipher() – brug createCipheriv()",
     "warning", None),

    (r"(?i)md5\s*\(",
     "MD5 brugt – kryptografisk svag hash-funktion",
     "warning", None),

    (r"(?i)sha1\s*\(",
     "SHA1 brugt – kryptografisk svag hash-funktion",
     "warning", None),

    # ── JWT sikkerhed ─────────────────────────────────────────────────────────
    (r"jwt\.sign\s*\([^)]*\)\s*(?!.*expiresIn)",
     "jwt.sign() uden expiresIn – token udløber aldrig",
     "warning", None),

    (r"(?i)algorithm\s*:\s*['\"]none['\"]",
     "JWT algorithm: none – fuldstændig deaktiveret signatur-tjek",
     "critical", None),

    # ── localStorage med sensitive data ───────────────────────────────────────
    (r"localStorage\.setItem\s*\([^)]*(?:token|password|secret|auth|jwt|session|key)",
     "Sensitiv data gemt i localStorage (sårbar over for XSS)",
     "warning", None),

    (r"sessionStorage\.setItem\s*\([^)]*(?:token|password|secret|auth|jwt)",
     "Sensitiv data gemt i sessionStorage",
     "warning", None),

    # ── Console.log med sensitive data ────────────────────────────────────────
    (r"console\.log\s*\(.*(?:password|token|secret|key|auth|jwt|credential).*\)",
     "console.log() med potentielt sensitiv data",
     "warning", None),

    (r"console\.log\s*\(\s*(?:process\.env|import\.meta\.env)",
     "console.log() logger environment variabler",
     "warning", None),

    # ── Usikker HTTP ──────────────────────────────────────────────────────────
    (r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)[A-Za-z0-9]",
     "Ukrypteret HTTP-URL til ekstern server (brug HTTPS)",
     "warning", None),

    # ── CORS konfiguration ────────────────────────────────────────────────────
    (r"['\"]Access-Control-Allow-Origin['\"].*['\*]['\"]",
     "CORS wildcard (*) hardcodet i kode",
     "warning", None),

    (r"origin\s*:\s*(?:true|\*|['\"][*]['\"])",
     "CORS origin: true/*  – tillader alle origins",
     "warning", None),

    # ── SSL / TLS ─────────────────────────────────────────────────────────────
    (r"rejectUnauthorized\s*:\s*false",
     "SSL-verificering deaktiveret (rejectUnauthorized: false)",
     "critical", None),

    (r"(?i)verify\s*=\s*False",
     "SSL-verificering deaktiveret (verify=False)",
     "critical", None),

    (r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]0['\"]",
     "NODE_TLS_REJECT_UNAUTHORIZED=0 – SSL komplet deaktiveret",
     "critical", None),

    # ── Farlige React-mønstre ─────────────────────────────────────────────────
    (r"__html\s*:\s*(?!['\"]\s*['\"])",
     "__html property sat – tjek om det er bruger-input (XSS)",
     "warning", "React"),

    # ── Server-Side Request Forgery (SSRF) hint ───────────────────────────────
    (r"(?:fetch|axios\.get|http\.get|request\.get)\s*\(\s*(?:req\.|params\.|query\.|body\.)",
     "fetch/http med request-parameter som URL – mulig SSRF",
     "warning", None),

    # ── Hardcodet Supabase createClient ──────────────────────────────────────
    (r"createClient\s*\(\s*['\"]https://[^'\"]+\.supabase\.co['\"]",
     "Supabase createClient() med hardcodet URL i kildekode",
     "warning", None),

    # ── Firebase initializeApp med hardcodet config ───────────────────────────
    (r"initializeApp\s*\(\s*\{[^}]*apiKey\s*:",
     "Firebase initializeApp() med hardcodet config-objekt",
     "warning", None),

    # ── Debugger i prod ───────────────────────────────────────────────────────
    (r"^\s*debugger\s*;?\s*$",
     "debugger statement fundet – fjern inden deployment",
     "info", None),

    # ── Rate limiting mangler (Node.js) ──────────────────────────────────────
    # Dette er et positiv-mønster (finder MANGEL) – scanner login-endpoints
    (r"(?:app|router)\.post\s*\(['\"][^'\"]*(?:login|signin|auth|password)[^'\"]*['\"]",
     "Login-endpoint fundet – tjek at rate limiting er aktiveret",
     "info", None),

    # ── Hardcoded IP/intern adresse i prod-kode ───────────────────────────────
    (r"(?:fetch|axios)\s*\(\s*['\"]http://(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)\d+",
     "Hardcodet intern IP-adresse i fetch() – ikke egnet til produktion",
     "warning", None),
]

SCAN_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".vue", ".svelte", ".py", ".php",
}
EXCLUDE_DIRS = {
    "node_modules", ".git", ".next", "dist", "build",
    ".turbo", "out", ".svelte-kit", "__pycache__", "venv", ".venv",
    "vendor",  # PHP composer
}

# Bredere extensions til hardcoded-secret scanning (inkl. config-filer)
HARDCODED_SCAN_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".vue", ".svelte", ".py", ".php",
    ".json", ".toml", ".yaml", ".yml",
    ".config", ".ini", ".xml", ".html", ".htm",
}

# Filnavne der MÅ indeholde secrets (selve .env-filerne)
_SKIP_ENV_FILENAMES = {
    ".env", ".env.local", ".env.development", ".env.production",
    ".env.staging", ".env.test", ".env.preview", ".env.example",
    ".env.sample", ".env.vault", ".envrc",
}


def scan_hardcoded_env_values(project_path: str, env_values: dict) -> list[dict]:
    """
    Scanner ALLE kildefiler i projektet for hardcodede .env-værdier.

    Finder tilfælde hvor en secret er smuttet direkte ind i koden i stedet
    for at bruge en env-variabel. Eksempel:
        const client = createClient("https://xyz.supabase.co", "eyJhbGci...")
                                                                 ↑ hardcodet fra .env!

    Args:
        project_path: Sti til projektet
        env_values:   Dict fra extract_all_env_values()["all_values"]
                      Format: {"VAR_NAME": {"value": "...", "source": ".env"}}

    Returns:
        Liste af findings (severity=critical) med fil, linje og variabelnavn.
    """
    if not env_values:
        return []

    # Byg mønstre – kun værdier ≥ 20 tegn for at undgå false positives
    patterns = []
    for var_name, meta in env_values.items():
        value = meta.get("value", "")
        source_file = meta.get("source", ".env")
        if len(value) < 20:
            continue
        try:
            patterns.append((re.compile(re.escape(value)), var_name, source_file))
        except re.error:
            continue

    if not patterns:
        return []

    findings = []
    seen = set()
    base = Path(project_path).resolve()

    for file_path in base.rglob("*"):
        # Self-scan prevention
        try:
            file_path.resolve().relative_to(SAFEVIBE_ROOT)
            continue
        except ValueError:
            pass

        if any(excluded in file_path.parts for excluded in EXCLUDE_DIRS):
            continue

        # Spring .env-filer over – de MÅ have disse værdier
        if file_path.name in _SKIP_ENV_FILENAMES or file_path.name.startswith(".env"):
            continue

        # Scan relevante fil-typer (bredere end kun kode)
        is_scannable = (
            file_path.suffix.lower() in HARDCODED_SCAN_EXTENSIONS
            or file_path.name in {"vercel.json", "netlify.toml", "wrangler.toml",
                                   "railway.toml", "fly.toml", "docker-compose.yml",
                                   "docker-compose.yaml"}
        )
        if not is_scannable or not file_path.is_file():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # Undgå at scanne meget store filer (over 1MB)
        if len(content) > 1_000_000:
            continue

        rel_path = str(file_path.relative_to(base))

        for pattern, var_name, env_source in patterns:
            if not pattern.search(content):
                continue

            dedup_key = (var_name, rel_path)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Find linjenummer
            line_num = None
            for i, line in enumerate(content.splitlines(), 1):
                if pattern.search(line):
                    line_num = i
                    break

            findings.append({
                "severity": "critical",
                "description": f"Hardcodet secret ({var_name}) fundet i kildekode",
                "detail": (
                    f"Værdien fra {env_source} er hardcodet i stedet for at bruge env-variablen. "
                    f"Fjern værdien og brug process.env.{var_name} / import.meta.env.{var_name}"
                ),
                "file": rel_path,
                "line": line_num,
                "env_var": var_name,
                "env_source_file": env_source,
            })

    return findings


def scan_code_files(project_path: str, stack: list[str] = None) -> list[dict]:
    """Scanner alle kildekode-filer i projektet for sikkerhedsproblemer."""
    if stack is None:
        stack = []

    findings = []
    base = Path(project_path).resolve()

    for file_path in base.rglob("*"):
        # Spring Safevibe's egne filer over (self-scan prevention)
        try:
            file_path.resolve().relative_to(SAFEVIBE_ROOT)
            continue  # Filen er inden i Safevibe's egen mappe
        except ValueError:
            pass  # Ikke en Safevibe-fil – fortsæt

        if any(excluded in file_path.parts for excluded in EXCLUDE_DIRS):
            continue
        if file_path.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        if not file_path.is_file():
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        # Undgå at scanne meget store filer (over 1MB)
        if len(content) > 1_000_000:
            continue

        rel_path = str(file_path.relative_to(base))
        
        # Track info-level findings per file for deduplication
        info_findings_in_file = set()

        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern, description, severity, stack_filter in CODE_CHECKS:
                if stack_filter and stack_filter not in stack:
                    continue
                
                try:
                    if re.search(pattern, line):
                        # Info-level findings: kun første match per fil
                        if severity == "info":
                            if description in info_findings_in_file:
                                continue  # Skip – allerede rapporteret i denne fil
                            info_findings_in_file.add(description)
                        
                        findings.append({
                            "file": rel_path,
                            "line": line_num,
                            "description": description,
                            "severity": severity,
                            "detail": line.strip()[:120],
                        })
                except re.error:
                    pass

    # Deduplicate findings per (description, file) for non-info levels
    seen = set()
    unique_findings = []
    for f in findings:
        # Info-level er allerede deduplikeret, spring dem over
        if f["severity"] == "info":
            unique_findings.append(f)
            continue
        
        # For andre severity levels: deduplicate på (description, file)
        dedup_key = (f["description"], f["file"])
        if dedup_key not in seen:
            seen.add(dedup_key)
            unique_findings.append(f)

    return unique_findings
