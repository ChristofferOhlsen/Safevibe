"""
browser_probe.py – Browser-baseret sikkerhedsscanning af kørende web-app.

Bruger Playwright til at:
  1. Intercepte alle network requests (fetch, XHR, WebSocket)
  2. Analysere request/response indhold for API-nøgler og tokens
  3. Scanne DOM (HTML-elementer, meta-tags, data-attributter, script-tags)
  4. Scanne JavaScript bundle-indhold i <script> tags for eksponerede secrets
  5. Dynamisk matching af .env-værdier mod netværkstrafik og DOM (Feature 3)

Playwright er en optional afhængighed – modulet degraderer gracefully
hvis playwright ikke er installeret.
"""

import re
import json
from typing import Optional

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# ─── Mønstre der søges efter i network responses og DOM ──────────────────────
SECRET_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{10,}"),
     "JWT/Supabase token eksponeret i netværkstrafik", "critical"),

    (re.compile(r"https://[a-z0-9]{4,}\.supabase\.co", re.I),
     "Supabase URL eksponeret", "warning"),

    (re.compile(r"sk-[A-Za-z0-9]{20,}"),
     "OpenAI API-nøgle eksponeret i netværkstrafik", "critical"),

    (re.compile(r"sk-ant-[A-Za-z0-9\-_]{40,}"),
     "Anthropic API-nøgle eksponeret", "critical"),

    (re.compile(r"AKIA[A-Z0-9]{16}"),
     "AWS Access Key eksponeret i netværkstrafik", "critical"),

    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
     "Google/Firebase API-nøgle eksponeret", "critical"),

    (re.compile(r"ghp_[A-Za-z0-9]{36}"),
     "GitHub PAT eksponeret i netværkstrafik", "critical"),

    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
     "Stripe LIVE Secret Key eksponeret", "critical"),

    (re.compile(r"whsec_[A-Za-z0-9]{32,}"),
     "Stripe Webhook Secret eksponeret", "critical"),

    (re.compile(r"xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+"),
     "Slack Bot Token eksponeret", "critical"),

    (re.compile(r"hf_[A-Za-z0-9]{34,}"),
     "HuggingFace token eksponeret", "critical"),

    (re.compile(r"npm_[A-Za-z0-9]{36}"),
     "NPM token eksponeret", "critical"),

    (re.compile(r"(postgres|mysql|mongodb)://[^:\"'\s]+:[^@\"'\s]+@"),
     "Database URL med credentials eksponeret", "critical"),

    (re.compile(r"(?i)service_role"),
     "Supabase service_role eksponeret i frontend", "critical"),

    # Firebase config object
    (re.compile(r'"apiKey"\s*:\s*"AIza[0-9A-Za-z\-_]{35}"'),
     "Firebase config med API-nøgle eksponeret i script", "warning"),

    # Vercel token
    (re.compile(r"vercel_[A-Za-z0-9_]{24,}", re.I),
     "Vercel token eksponeret", "critical"),
]

# Kendte API endpoints der indikerer backend-teknologier
INTERESTING_API_PATTERNS = [
    (re.compile(r"/rest/v1/"), "Supabase REST API kald"),
    (re.compile(r"\.supabase\.co"), "Supabase request"),
    (re.compile(r"firebaseio\.com"), "Firebase Realtime DB request"),
    (re.compile(r"firebase\.googleapis\.com"), "Firebase API request"),
    (re.compile(r"convex\.cloud"), "Convex request"),
    (re.compile(r"turso\.io"), "Turso request"),
    (re.compile(r"upstash\.io"), "Upstash request"),
    (re.compile(r"neon\.tech"), "Neon request"),
    (re.compile(r"/graphql"), "GraphQL endpoint"),
    (re.compile(r"/trpc/"), "tRPC endpoint"),
    (re.compile(r"/api/"), "API endpoint"),
]

# Minimumslængde for at en .env-værdi er interessant nok til dynamisk scanning.
# 16 tegn reducerer false positives fra korte almene strenge ("postgres", "admin" osv.)
_MIN_ENV_VALUE_LEN = 16

# Variabelnavne der er kendte "mode/environment"-indikatorer – aldrig secrets.
# Bundlers (Vite, webpack, Next.js) inliner disse med vilje i JS-bundlet.
_NON_SECRET_VAR_NAMES = {
    "NODE_ENV", "APP_ENV", "VITE_MODE", "APP_MODE", "MODE",
    "ENVIRONMENT", "ENV", "BUILD_ENV", "REACT_APP_ENV",
    "NEXT_PUBLIC_APP_ENV", "CF_PAGES_BRANCH", "VERCEL_ENV",
    "CI", "DEBUG", "PORT", "HOST", "LANG", "TZ",
    "NEXT_PUBLIC_ENV", "NUXT_ENV", "GATSBY_ENV",
}

# Almene strenge der ikke er secrets og som optræder overalt i JS-bundler –
# ville give konstante false positives hvis de matches.
_NON_SECRET_VALUES = {
    "development", "production", "test", "staging", "local",
    "preview", "true", "false", "yes", "no", "1", "0",
    "dev", "prod", "none", "info", "debug", "warn", "error",
    "localhost", "http", "https", "enabled", "disabled",
}


# Regex der matcher credentials embeddet i en URL (f.eks. postgres://user:pass@host)
_CREDENTIALS_IN_URL = re.compile(r"://[^:@/\s]+:[^@/\s]+@")


def _build_env_patterns(env_values: dict) -> list[tuple]:
    """
    Byg dynamiske regex-mønstre fra alle .env-værdier.

    Args:
        env_values: dict fra extract_all_env_values()["all_values"]
                    Format: {"VAR_NAME": {"value": "...", "source": ".env"}}

    Returns:
        Liste af (compiled_pattern, var_name, value_preview, source_file, severity)

    Bemærk om URL-variabler:
        Variabler med "URL" i navnet (f.eks. SUPABASE_URL, DATABASE_URL,
        NEXT_PUBLIC_SUPABASE_URL) er typisk service-endepunkter som browseren
        naturligt laver requests til – det er forventet og korrekt adfærd at
        de optræder i netværkstrafikken.

        Vi springer dem over MEDMINDRE de indeholder embedded credentials på
        formen ://user:pass@host – sådanne URLs fanges allerede af de statiske
        SECRET_PATTERNS (Database URL med credentials).
    """
    patterns = []
    seen_values = set()

    for var_name, meta in (env_values or {}).items():
        value = meta.get("value", "")
        source_file = meta.get("source", ".env")

        var_upper = var_name.upper()

        # ── Skip kendte non-secret variabelnavne (environment-mode indikatorer) ──
        # NODE_ENV, APP_ENV m.fl. er beregnet til at fremgå i browser-bundlet –
        # bundlers inliner dem med vilje. At finde "production" i et JS-bundle
        # er 100% forventet adfærd, ikke en sikkerhedsfejl.
        if var_upper in _NON_SECRET_VAR_NAMES:
            continue

        # ── Skip trivielle værdier der er alment brugte ord ─────────────────
        # Strenge som "development", "production", "true" m.fl. optræder naturligt
        # i enhver JS-kodebase og vil give konstante false positives.
        if value.lower() in _NON_SECRET_VALUES:
            continue

        # ── Ignorer korte, trivielle eller duplikerede værdier ───────────────
        if not value or len(value) < _MIN_ENV_VALUE_LEN:
            continue
        if value in seen_values:
            continue
        seen_values.add(value)

        # ── URL-variabler uden credentials springes over ────────────────────
        # En URL der bruges som API-endepunkt vil naturligt fremgå i netværks-
        # trafikken – det er korrekt og forventet. Kun URL'er med embedded
        # credentials (://user:pass@) er et problem, og de fanges af
        # SECRET_PATTERNS allerede.
        if "URL" in var_upper and not _CREDENTIALS_IN_URL.search(value):
            continue

        # Bestem severity baseret på variabelnavn og indhold
        severity = "warning"
        if any(kw in var_upper for kw in (
            "SERVICE_ROLE", "SECRET", "PRIVATE", "ADMIN", "PASSWORD",
            "PASS", "TOKEN", "AUTH", "SIGNING", "WEBHOOK",
        )):
            severity = "critical"
        elif any(kw in var_upper for kw in ("ANON", "PUBLIC", "NEXT_PUBLIC", "VITE_")):
            severity = "warning"

        try:
            pattern = re.compile(re.escape(value))
            patterns.append((pattern, var_name, value[:20] + "...", source_file, severity))
        except re.error:
            continue

    return patterns


def _scan_text_for_secrets(text: str, source: str, max_len: int = 500000) -> list[dict]:
    """Scanner en tekststreng for kendte secret-mønstre."""
    findings = []
    if not text or len(text) > max_len:
        return findings

    seen = set()
    for pattern, description, severity in SECRET_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            match_str = match if isinstance(match, str) else match[0]
            dedup_key = (description, match_str[:20])
            if dedup_key not in seen:
                seen.add(dedup_key)
                findings.append({
                    "severity": severity,
                    "description": description,
                    "detail": f"Fundet i: {source} | Mønster: {match_str[:40]}...",
                    "source": source,
                })
    return findings


def _scan_text_with_env_values(
    text: str,
    source: str,
    env_patterns: list[tuple],
    max_len: int = 500000,
) -> list[dict]:
    """
    Scanner en tekststreng for dynamiske .env-værdier.

    Args:
        text:         Teksten der scannes (response body, script, DOM osv.)
        source:       Beskrivelse af kilden (til rapportering)
        env_patterns: Output fra _build_env_patterns()
        max_len:      Maksimal tekststørrelse der scannes

    Returns:
        Liste af findings med var_name og kilde
    """
    findings = []
    if not text or not env_patterns or len(text) > max_len:
        return findings

    seen = set()
    for pattern, var_name, value_preview, source_file, severity in env_patterns:
        if pattern.search(text):
            dedup_key = (var_name, source[:40])
            if dedup_key not in seen:
                seen.add(dedup_key)
                findings.append({
                    "severity": severity,
                    "description": f"{var_name} (fra {source_file}) eksponeret i browser",
                    "detail": (
                        f"Værdi starter med: {value_preview} | "
                        f"Fundet i: {source}"
                    ),
                    "source": source,
                    "env_var": var_name,
                    "env_source_file": source_file,
                    "dynamic_match": True,
                })
    return findings


def run_browser_probe(
    base_url: str,
    timeout_ms: int = 15000,
    env_values: dict | None = None,
) -> dict:
    """
    Kør fuld browser-probe mod den kørende app.

    Args:
        base_url:    URL til den kørende app
        timeout_ms:  Timeout i millisekunder for sideindlæsning
        env_values:  Dict fra extract_all_env_values()["all_values"] – bruges til
                     dynamisk matching af .env-værdier mod netværkstrafik og DOM.
                     Format: {"VAR_NAME": {"value": "...", "source": ".env"}}

    Returns:
        dict med keys: skipped, reason, findings, network_requests, dom_findings
    """
    if not PLAYWRIGHT_AVAILABLE:
        return {
            "skipped": True,
            "reason": "Playwright ikke installeret – kør: python install.py",
            "findings": [],
            "network_requests": [],
            "dom_findings": [],
        }

    if not base_url:
        return {
            "skipped": True,
            "reason": "Ingen URL tilgængelig til browser-probe",
            "findings": [],
            "network_requests": [],
            "dom_findings": [],
        }

    # Byg dynamiske mønstre fra .env-værdier én gang (genbrug i alle callbacks)
    env_patterns = _build_env_patterns(env_values) if env_values else []

    findings = []
    network_requests = []
    dom_findings = []
    intercepted_responses = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (compatible; Safevibe-Scanner/2.0)",
            )
            page = context.new_page()

            # ── Network interception ──────────────────────────────────────
            def on_request(request):
                url = request.url
                method = request.method
                headers = dict(request.headers)

                # Gem request-info
                req_entry = {
                    "url": url,
                    "method": method,
                    "type": request.resource_type,
                }

                # Tjek headers for kendte secrets
                header_text = " ".join(f"{k}: {v}" for k, v in headers.items())
                source_label = f"request-header [{method} {url[:60]}]"

                secrets = _scan_text_for_secrets(header_text, source_label)
                findings.extend(secrets)

                # Tjek headers for dynamiske .env-værdier
                if env_patterns:
                    env_hits = _scan_text_with_env_values(
                        header_text, source_label, env_patterns
                    )
                    findings.extend(env_hits)

                # Tjek request URL for dynamiske .env-værdier (f.eks. API-nøgle i query string)
                if env_patterns:
                    url_hits = _scan_text_with_env_values(
                        url, f"request-url [{method} {url[:60]}]", env_patterns
                    )
                    findings.extend(url_hits)

                # Marker interessante API-calls
                for pattern, label in INTERESTING_API_PATTERNS:
                    if pattern.search(url):
                        req_entry["label"] = label
                        break

                network_requests.append(req_entry)

            def on_response(response):
                url = response.url
                content_type = response.headers.get("content-type", "")

                # Scan kun JSON og JS responses
                if not any(ct in content_type for ct in ["json", "javascript", "text/"]):
                    return

                try:
                    body = response.body()
                    if body and len(body) < 2_000_000:  # Max 2MB
                        text = body.decode("utf-8", errors="ignore")
                        source_label = f"response [{url[:60]}]"

                        # Kendte secret-mønstre
                        secrets = _scan_text_for_secrets(text, source_label)
                        findings.extend(secrets)

                        # Dynamiske .env-værdier
                        if env_patterns:
                            env_hits = _scan_text_with_env_values(
                                text, source_label, env_patterns
                            )
                            findings.extend(env_hits)

                        intercepted_responses.append({
                            "url": url,
                            "size": len(body),
                            "secrets_found": len(secrets),
                            "env_hits": len(env_hits) if env_patterns else 0,
                        })
                except Exception:
                    pass

            page.on("request", on_request)
            page.on("response", on_response)

            # ── WebSocket tracking (skal registreres FØR navigation) ─────
            ws_connections = []
            try:
                def on_websocket(ws):
                    ws_connections.append({"url": ws.url})
                page.on("websocket", on_websocket)
            except Exception:
                pass

            # ── Naviger til URL ───────────────────────────────────────────
            try:
                page.goto(base_url, timeout=timeout_ms, wait_until="networkidle")
            except PlaywrightTimeout:
                # Timeout er OK – vi scanner hvad der er indlæst
                pass
            except Exception as e:
                browser.close()
                return {
                    "skipped": True,
                    "reason": f"Kunne ikke indlæse {base_url}: {str(e)[:100]}",
                    "findings": [],
                    "network_requests": [],
                    "dom_findings": [],
                }

            # ── DOM scanning ──────────────────────────────────────────────
            try:
                # Scan alle script tags for eksponerede secrets
                script_contents = page.evaluate("""
                    () => Array.from(document.querySelectorAll('script:not([src])'))
                         .map(s => s.textContent)
                         .filter(t => t && t.length > 10)
                """)

                for idx, script_text in enumerate(script_contents or []):
                    source_label = f"inline-script[{idx}]"

                    # Kendte mønstre
                    secrets = _scan_text_for_secrets(
                        script_text, source_label, max_len=200000
                    )
                    dom_findings.extend(secrets)
                    findings.extend(secrets)

                    # Dynamiske .env-værdier
                    if env_patterns:
                        env_hits = _scan_text_with_env_values(
                            script_text, source_label, env_patterns, max_len=200000
                        )
                        dom_findings.extend(env_hits)
                        findings.extend(env_hits)

                # Scan meta-tags
                meta_content = page.evaluate("""
                    () => Array.from(document.querySelectorAll('meta[content]'))
                         .map(m => ({ name: m.getAttribute('name') || m.getAttribute('property'), content: m.content }))
                """)

                for meta in (meta_content or []):
                    content = meta.get("content", "")
                    source_label = f"meta[{meta.get('name', '?')}]"

                    secrets = _scan_text_for_secrets(content, source_label)
                    dom_findings.extend(secrets)
                    findings.extend(secrets)

                    if env_patterns:
                        env_hits = _scan_text_with_env_values(
                            content, source_label, env_patterns
                        )
                        dom_findings.extend(env_hits)
                        findings.extend(env_hits)

                # Scan data-attributter
                data_attrs = page.evaluate("""
                    () => {
                        const results = [];
                        document.querySelectorAll('[data-key],[data-token],[data-api-key],[data-secret]')
                            .forEach(el => {
                                for (const attr of el.attributes) {
                                    if (attr.name.startsWith('data-')) {
                                        results.push({ attr: attr.name, value: attr.value });
                                    }
                                }
                            });
                        return results;
                    }
                """)

                for item in (data_attrs or []):
                    content = item.get("value", "")
                    source_label = f"data-attr[{item.get('attr', '?')}]"

                    secrets = _scan_text_for_secrets(content, source_label)
                    dom_findings.extend(secrets)
                    findings.extend(secrets)

                    if env_patterns:
                        env_hits = _scan_text_with_env_values(
                            content, source_label, env_patterns
                        )
                        dom_findings.extend(env_hits)
                        findings.extend(env_hits)

                # Scan __NEXT_DATA__ eller __NUXT__ global state
                global_state = page.evaluate("""
                    () => {
                        const nextData = window.__NEXT_DATA__;
                        const nuxtData = window.__NUXT__;
                        const remixData = window.__remixContext;
                        return {
                            next: nextData ? JSON.stringify(nextData) : null,
                            nuxt: nuxtData ? JSON.stringify(nuxtData) : null,
                            remix: remixData ? JSON.stringify(remixData) : null,
                        };
                    }
                """)

                for framework, state_json in (global_state or {}).items():
                    if state_json:
                        source_label = f"window.__{framework.upper()}_DATA__"

                        secrets = _scan_text_for_secrets(
                            state_json, source_label, max_len=500000
                        )
                        dom_findings.extend(secrets)
                        findings.extend(secrets)

                        if env_patterns:
                            env_hits = _scan_text_with_env_values(
                                state_json, source_label, env_patterns, max_len=500000
                            )
                            dom_findings.extend(env_hits)
                            findings.extend(env_hits)

                # Scan window.ENV eller window.config
                window_env = page.evaluate("""
                    () => {
                        const env = window.ENV || window.env || window.config || window.CONFIG;
                        return env ? JSON.stringify(env) : null;
                    }
                """)

                if window_env:
                    source_label = "window.ENV/config"

                    secrets = _scan_text_for_secrets(window_env, source_label)
                    dom_findings.extend(secrets)
                    findings.extend(secrets)

                    if env_patterns:
                        env_hits = _scan_text_with_env_values(
                            window_env, source_label, env_patterns
                        )
                        dom_findings.extend(env_hits)
                        findings.extend(env_hits)

            except Exception:
                pass

            browser.close()

    except Exception as e:
        return {
            "skipped": True,
            "reason": f"Browser-probe fejlede: {str(e)[:200]}",
            "findings": [],
            "network_requests": [],
            "dom_findings": [],
        }

    # Deduplikér findings (static + dynamic separat nøgle for at bevare begge)
    seen_findings = set()
    unique_findings = []
    for f in findings:
        # Dynamiske .env-fund bruger var_name som del af nøgle for bedre præcision
        if f.get("dynamic_match"):
            key = (f.get("env_var", ""), f.get("source", "")[:40])
        else:
            key = (f.get("description", ""), f.get("source", "")[:30])
        if key not in seen_findings:
            seen_findings.add(key)
            unique_findings.append(f)

    # Filtrer network_requests til kun interessante
    interesting_requests = [r for r in network_requests if r.get("label")]

    return {
        "skipped": False,
        "findings": unique_findings,
        "network_requests": interesting_requests,
        "all_request_count": len(network_requests),
        "dom_findings": dom_findings,
        "intercepted_responses": intercepted_responses,
        "env_patterns_used": len(env_patterns),
    }
