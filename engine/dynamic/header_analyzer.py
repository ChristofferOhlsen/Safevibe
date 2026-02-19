"""
header_analyzer.py – Analyserer HTTP response headers fra den kørende app.
Dækker moderne sikkerhedsheaders inkl. COOP, COEP, CORP, cookie-sikkerhed.
"""

import re

try:
    import requests
except ImportError:
    requests = None


# ─── HEADER CHECKS: (header-navn, tjek-funktion, beskrivelse, severity) ──────
HEADER_CHECKS = [
    # ── Kritiske headers ──────────────────────────────────────────────────────
    ("content-security-policy",
     lambda v: v is not None,
     "Content-Security-Policy (CSP) header mangler – ingen XSS-beskyttelse",
     "warning"),

    ("access-control-allow-origin",
     lambda v: v is None or v.strip() != "*",
     "CORS: Access-Control-Allow-Origin er sat til wildcard (*)",
     "critical"),

    # ── Vigtige headers ───────────────────────────────────────────────────────
    ("x-frame-options",
     lambda v: v is not None,
     "X-Frame-Options mangler – risiko for clickjacking",
     "warning"),

    ("x-content-type-options",
     lambda v: v is not None and "nosniff" in v.lower(),
     "X-Content-Type-Options: nosniff mangler – MIME-sniffing risiko",
     "warning"),

    ("x-xss-protection",
     lambda v: v is not None,
     "X-XSS-Protection header mangler (legacy men stadig relevant)",
     "info"),

    # ── Transport Security ────────────────────────────────────────────────────
    ("strict-transport-security",
     lambda v: v is not None,
     "HSTS (Strict-Transport-Security) mangler",
     "warning"),

    # ── Cross-Origin policies (moderne) ──────────────────────────────────────
    ("cross-origin-opener-policy",
     lambda v: v is not None,
     "Cross-Origin-Opener-Policy (COOP) mangler – Spectre-angreb risiko",
     "info"),

    ("cross-origin-embedder-policy",
     lambda v: v is not None,
     "Cross-Origin-Embedder-Policy (COEP) mangler",
     "info"),

    ("cross-origin-resource-policy",
     lambda v: v is not None,
     "Cross-Origin-Resource-Policy (CORP) mangler",
     "info"),

    # ── Privacy & referrer ────────────────────────────────────────────────────
    ("referrer-policy",
     lambda v: v is not None,
     "Referrer-Policy header mangler – URL kan lækkes til tredjeparter",
     "info"),

    ("permissions-policy",
     lambda v: v is not None,
     "Permissions-Policy header mangler – ingen kontrol over browser-API'er",
     "info"),

    # ── Server info-lækage ────────────────────────────────────────────────────
    ("server",
     lambda v: v is None,
     "Server header eksponerer server-software (info-lækage)",
     "info"),

    ("x-powered-by",
     lambda v: v is None,
     "X-Powered-By header eksponerer teknologi-stack (info-lækage)",
     "warning"),

    ("x-aspnet-version",
     lambda v: v is None,
     "X-AspNet-Version eksponerer .NET version",
     "warning"),

    ("x-aspnetmvc-version",
     lambda v: v is None,
     "X-AspNetMvc-Version eksponerer MVC version",
     "warning"),
]

# ─── CSP-indhold checks ───────────────────────────────────────────────────────
CSP_CONTENT_CHECKS = [
    (r"'unsafe-inline'",
     "CSP tillader 'unsafe-inline' scripts – svækker XSS-beskyttelse",
     "warning"),
    (r"'unsafe-eval'",
     "CSP tillader 'unsafe-eval' – svækker XSS-beskyttelse",
     "warning"),
    (r"script-src ['\"]?\*",
     "CSP script-src tillader wildcard (*) – ingen script-begrænsning",
     "critical"),
    (r"default-src ['\"]?\*",
     "CSP default-src er wildcard (*) – ingen begrænsninger",
     "critical"),
]

# ─── Service-detektion via headers ───────────────────────────────────────────
SUPABASE_HEADER_PATTERNS = ["x-client-info", "sb-gateway-version", "x-supabase"]
FIREBASE_HEADER_PATTERNS = ["x-firebase-appcheck", "x-firebase-locale"]
VERCEL_HEADER_PATTERNS = ["x-vercel-id", "x-vercel-cache"]
CLOUDFLARE_HEADER_PATTERNS = ["cf-ray", "cf-cache-status"]
NETLIFY_HEADER_PATTERNS = ["x-nf-request-id", "netlify-cache-tag"]
NEXTJS_HEADER_PATTERNS = ["x-nextjs-cache", "x-nextjs-stale-time"]


def _check_cookie_security(headers: dict) -> list[dict]:
    """Analyser Set-Cookie headers for sikkerhedsproblemer."""
    findings = []
    set_cookie = headers.get("set-cookie", "")

    if not set_cookie:
        return []

    # Cookies kan være multiple (header repeated) – behandl som tekst
    cookie_str = set_cookie.lower()

    if "httponly" not in cookie_str:
        findings.append({
            "header": "set-cookie",
            "description": "Cookie mangler HttpOnly flag – JavaScript kan tilgå cookien (XSS risiko)",
            "severity": "warning",
            "detail": "Tilføj HttpOnly til alle session-cookies",
        })

    if "secure" not in cookie_str:
        findings.append({
            "header": "set-cookie",
            "description": "Cookie mangler Secure flag – sendes over ukrypteret HTTP",
            "severity": "warning",
            "detail": "Tilføj Secure til alle cookies med sensitiv data",
        })

    if "samesite" not in cookie_str:
        findings.append({
            "header": "set-cookie",
            "description": "Cookie mangler SameSite attribut – risiko for CSRF",
            "severity": "warning",
            "detail": "Tilføj SameSite=Strict eller SameSite=Lax",
        })
    elif "samesite=none" in cookie_str and "secure" not in cookie_str:
        findings.append({
            "header": "set-cookie",
            "description": "SameSite=None kræver Secure flag – browser vil afvise cookien",
            "severity": "warning",
            "detail": "Tilføj Secure til cookie med SameSite=None",
        })

    return findings


def _detect_services(headers: dict) -> list[dict]:
    """Identificer kendte services via header-fingerprinting."""
    services = []

    for pattern in SUPABASE_HEADER_PATTERNS:
        if pattern in headers:
            services.append({"service": "Supabase", "via": f"header: {pattern}"})

    for pattern in FIREBASE_HEADER_PATTERNS:
        if pattern in headers:
            services.append({"service": "Firebase", "via": f"header: {pattern}"})

    for pattern in VERCEL_HEADER_PATTERNS:
        if pattern in headers:
            services.append({"service": "Vercel", "via": f"header: {pattern}"})

    for pattern in CLOUDFLARE_HEADER_PATTERNS:
        if pattern in headers:
            services.append({"service": "Cloudflare", "via": f"header: {pattern}"})

    for pattern in NETLIFY_HEADER_PATTERNS:
        if pattern in headers:
            services.append({"service": "Netlify", "via": f"header: {pattern}"})

    for pattern in NEXTJS_HEADER_PATTERNS:
        if pattern in headers:
            services.append({"service": "Next.js", "via": f"header: {pattern}"})

    return services


def analyze_headers(base_url: str) -> dict:
    """Hent og analyser headers fra den kørende app."""
    if requests is None:
        return {
            "error": "requests-biblioteket er ikke installeret (kør: python install.py)",
            "findings": [],
            "raw_headers": {},
            "detected_services": [],
        }

    try:
        response = requests.get(base_url, timeout=5, allow_redirects=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
        status_code = response.status_code
    except requests.exceptions.ConnectionError:
        return {
            "error": f"Kan ikke forbinde til {base_url} – er dev-serveren startet?",
            "findings": [],
            "raw_headers": {},
            "detected_services": [],
        }
    except requests.exceptions.Timeout:
        return {
            "error": f"Timeout ved forbindelse til {base_url}",
            "findings": [],
            "raw_headers": {},
            "detected_services": [],
        }
    except Exception as e:
        return {
            "error": f"Fejl: {str(e)}",
            "findings": [],
            "raw_headers": {},
            "detected_services": [],
        }

    findings = []

    # ── Standard header-checks ─────────────────────────────────────────────
    for header_name, check_fn, description, severity in HEADER_CHECKS:
        value = headers.get(header_name)
        try:
            passes = check_fn(value)
        except Exception:
            passes = True

        if not passes:
            findings.append({
                "header": header_name,
                "description": description,
                "severity": severity,
                "detail": f"Aktuel værdi: {value}" if value else "Header ikke tilstede",
            })

    # ── CSP indholdsanalyse ────────────────────────────────────────────────
    csp = headers.get("content-security-policy", "")
    if csp:
        for csp_pattern, csp_desc, csp_sev in CSP_CONTENT_CHECKS:
            if re.search(csp_pattern, csp, re.IGNORECASE):
                findings.append({
                    "header": "content-security-policy",
                    "description": csp_desc,
                    "severity": csp_sev,
                    "detail": f"CSP: {csp[:120]}",
                })

    # ── Cookie sikkerhed ───────────────────────────────────────────────────
    cookie_findings = _check_cookie_security(headers)
    findings.extend(cookie_findings)

    # ── HSTS styrke-tjek ───────────────────────────────────────────────────
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        max_age_match = re.search(r"max-age=(\d+)", hsts)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # 1 år
                findings.append({
                    "header": "strict-transport-security",
                    "description": f"HSTS max-age er kun {max_age}s – anbefalet minimum er 31536000 (1 år)",
                    "severity": "info",
                    "detail": f"Aktuel: {hsts}",
                })
        if "includeSubDomains" not in hsts:
            findings.append({
                "header": "strict-transport-security",
                "description": "HSTS mangler includeSubDomains",
                "severity": "info",
                "detail": f"Aktuel: {hsts}",
            })

    # ── CORS credentials check ─────────────────────────────────────────────
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        findings.append({
            "header": "access-control-allow-credentials",
            "description": "CORS: wildcard origin + credentials:true – browsers tillader ikke dette, men indikerer fejlkonfiguration",
            "severity": "warning",
            "detail": f"Origin: {acao}, Credentials: {acac}",
        })

    # ── Service-detektion ──────────────────────────────────────────────────
    detected_services = _detect_services(headers)

    return {
        "error": None,
        "status_code": status_code,
        "findings": findings,
        "raw_headers": dict(headers),
        "detected_services": detected_services,
    }
