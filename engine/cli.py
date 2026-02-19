"""
cli.py – Hoved-entry for Safevibe v2.
Orkestrerer alle scannere og printer den endelige Vibe-Report.
"""

import os
import sys
import argparse
import time

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    from rich.text import Text
    from rich.rule import Rule
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from engine.detector import run_detection
from engine.static.env_scanner import scan_env_files, check_env_example_exists, check_env_vault
from engine.static.git_scanner import check_gitignore, check_secrets_in_git
from engine.static.code_scanner import scan_code_files, scan_hardcoded_env_values
from engine.dynamic.header_analyzer import analyze_headers
from engine.dynamic.db_detector import detect_database, get_all_databases, extract_all_env_values  # noqa: F401 (bruges via variabel)
from engine.dynamic.rls_prober import run_rls_probe
from engine.dynamic.browser_probe import run_browser_probe, PLAYWRIGHT_AVAILABLE

console = Console() if RICH_AVAILABLE else None

SEVERITY_STYLES = {
    "critical": ("[bold red]🔴 KRITISK [/bold red]",  "red"),
    "warning":  ("[bold yellow]🟡 ADVARSEL[/bold yellow]", "yellow"),
    "info":     ("[bold blue]🔵 INFO    [/bold blue]",  "blue"),
    "ok":       ("[bold green]🟢 OK      [/bold green]", "green"),
}

SCORE_PENALTIES = {
    "critical": 15,
    "warning":  5,
    "info":     1,
}

# DB-specifikke advarsler baseret på type
DB_SECURITY_HINTS = {
    "MongoDB":   [
        ("warning", "MongoDB fundet – tjek at autentificering er aktiveret (--auth flag)", "Ingen auth = komplet åben database"),
        ("info",    "MongoDB – sørg for at bruge TLS/SSL forbindelser", ""),
    ],
    "PostgreSQL": [
        ("info",    "PostgreSQL fundet – tjek at SSL er aktiveret (sslmode=require)", "Brug sslmode=require i forbindelsesstrengen"),
    ],
    "MySQL":     [
        ("info",    "MySQL fundet – tjek at brugere har mindst-privilegier", "Undgå root-bruger i applikationskode"),
    ],
    "MariaDB":   [
        ("info",    "MariaDB fundet – tjek at brugere har mindst-privilegier", ""),
    ],
    "Redis":     [
        ("warning", "Redis fundet – tjek at adgangskode er sat (requirepass) og at Redis ikke er eksponeret uden for localhost", "Redis uden auth er fuldstændig åben"),
    ],
    "Upstash Redis": [
        ("info",    "Upstash Redis fundet – tjek at REST token ikke er eksponeret i klientkode", ""),
    ],
    "MSSQL":     [
        ("info",    "MS SQL Server fundet – tjek at SQL Server Auth er konfigureret korrekt", ""),
    ],
    "Turso":     [
        ("info",    "Turso SQLite Edge fundet – tjek at auth token ikke er eksponeret", ""),
    ],
    "Neon":      [
        ("info",    "Neon serverless Postgres fundet – tjek at connection pooling er konfigureret", ""),
    ],
    "PlanetScale": [
        ("info",    "PlanetScale fundet – tjek at branch-kodeord ikke er committed til git", ""),
    ],
    "CockroachDB": [
        ("info",    "CockroachDB fundet – tjek at TLS krav er opfyldt", ""),
    ],
    "Hasura":    [
        ("warning", "Hasura fundet – tjek at admin secret er sat og ikke eksponeret", "HASURA_GRAPHQL_ADMIN_SECRET skal holdes hemmelig"),
    ],
    "Convex":    [
        ("info",    "Convex fundet – tjek at deployment key ikke er i frontend-kode", ""),
    ],
    "Firebase":  [
        ("warning", "Firebase fundet – tjek Firestore Security Rules og Firebase Storage Rules", "Åbne rules = alle kan læse/skrive alle data"),
    ],
}


def _print_fallback(msg: str):
    import re
    clean = re.sub(r"\[/?[^\]]+\]", "", msg)
    print(clean)


def _print(msg: str):
    if RICH_AVAILABLE:
        console.print(msg)
    else:
        _print_fallback(msg)


def _findings_table(findings: list[dict], title: str) -> None:
    if not findings:
        return

    if not RICH_AVAILABLE:
        _print(f"\n  {title}")
        for f in findings:
            _print(f"  [{f['severity'].upper()}] {f['description']}")
            if f.get("detail"):
                _print(f"         → {f['detail'][:100]}")
        return

    table = Table(title=title, box=box.ROUNDED, show_header=True, header_style="bold", expand=True)
    table.add_column("Niveau", width=12, no_wrap=True)
    table.add_column("Beskrivelse", ratio=3)
    table.add_column("Detalje", ratio=4, overflow="fold")

    location_col = any(f.get("file") or f.get("table") or f.get("header") for f in findings)
    if location_col:
        table.add_column("Placering", ratio=2, overflow="fold")

    for f in findings:
        sev = f.get("severity", "info")
        label, color = SEVERITY_STYLES.get(sev, SEVERITY_STYLES["info"])
        desc = f.get("description", "")
        detail = f.get("detail", "")[:120]
        location = f.get("file") or f.get("table") or f.get("header") or ""
        if f.get("line"):
            location += f":{f['line']}"

        if location_col:
            table.add_row(label, desc, detail, f"[dim]{location}[/dim]")
        else:
            table.add_row(label, desc, detail)

    console.print(table)
    console.print()


def _ok_line(msg: str):
    _print(f"  [bold green]🟢[/bold green] {msg}")


def _section(title: str):
    if RICH_AVAILABLE:
        console.print(Rule(f"[bold]{title}[/bold]", style="dim"))
    else:
        print(f"\n{'─'*50}\n  {title}\n{'─'*50}")


def _calculate_score(all_findings: list[dict]) -> int:
    score = 100
    for f in all_findings:
        score -= SCORE_PENALTIES.get(f.get("severity", "info"), 0)
    return max(0, score)


def _vibe_verdict(score: int) -> tuple[str, str]:
    if score >= 80:
        return "✅ Good Vibes", "green"
    elif score >= 50:
        return "⚠️  Sus Vibes", "yellow"
    elif score >= 25:
        return "😬 Bad Vibes", "red"
    else:
        return "💀 Toxic Vibes", "bold red"


def _db_security_findings(db_info: dict) -> list[dict]:
    """Generer DB-specifikke sikkerhedsadvarsler baseret på type."""
    if not db_info:
        return []

    db_type = db_info.get("type", "")
    findings = []

    # Find matchende hints (søg på delstrenge for at dække "Supabase (cloud)" osv.)
    for db_key, hints in DB_SECURITY_HINTS.items():
        if db_key.lower() in db_type.lower():
            for sev, desc, detail in hints:
                findings.append({
                    "severity": sev,
                    "description": desc,
                    "detail": detail,
                })
            break

    # Prisma-specifikke checks
    if db_info.get("prisma"):
        provider = db_info.get("provider", "")
        url_env = db_info.get("url_env_var", "")
        if url_env:
            findings.append({
                "severity": "info",
                "description": f"Prisma bruger env var '{url_env}' til database URL",
                "detail": "Sørg for at denne variabel aldrig commites til git",
            })
        if provider == "sqlite":
            findings.append({
                "severity": "warning",
                "description": "Prisma med SQLite – ikke egnet til produktionsbrug",
                "detail": "Skift til PostgreSQL, MySQL eller andet produktionssystem",
            })

    return findings


def run(default_path: str = "."):
    parser = argparse.ArgumentParser(
        prog="safevibe",
        description="🛡️  Safevibe v2 – Lokal sikkerhedsscanner til webprojekter",
    )
    parser.add_argument(
        "path", nargs="?", default=default_path,
        help=f"Sti til projektet (standard: {default_path})"
    )
    parser.add_argument("--no-dynamic", action="store_true", help="Spring dynamisk analyse over")
    parser.add_argument("--no-rls", action="store_true", help="Spring RLS-probe over")
    parser.add_argument("--no-browser", action="store_true", help="Spring browser-probe over")
    parser.add_argument("--url", default=None, help="Angiv URL manuelt (f.eks. http://localhost:4000)")
    args = parser.parse_args()

    project_path = os.path.abspath(args.path)

    if RICH_AVAILABLE:
        console.print()
        console.print(Panel.fit(
            "[bold cyan]🛡️  SAFEVIBE v2[/bold cyan]  [dim]– Lokal Sikkerhedsscanner[/dim]\n"
            f"[dim]Projekt: {project_path}[/dim]",
            border_style="cyan", padding=(0, 2),
        ))
        console.print()
    else:
        print(f"\n{'='*60}\n  🛡️  SAFEVIBE v2 – Lokal Sikkerhedsscanner\n  Projekt: {project_path}\n{'='*60}\n")

    all_findings: list[dict] = []
    start_time = time.time()

    # ── Fase 1: Detektion ────────────────────────────────────────────────────
    _section("📡 Fase 1 – Detektion")

    detection = run_detection(project_path)
    stack = detection["stack"]
    has_project_file = detection.get("has_project_file", False)
    base_url = args.url or detection["base_url"]

    if stack:
        _print(f"  [bold]Stack:[/bold] {', '.join(stack)}")
    elif has_project_file:
        _print("  [dim]Stack: Projektfil fundet men ingen kendte frameworks identificeret[/dim]")
    else:
        _print("  [dim]Stack: Ingen projektfil fundet (package.json / requirements.txt / composer.json)[/dim]")

    if base_url:
        _print(f"  [bold]Server:[/bold] {base_url} [green]● AKTIV[/green]")
    else:
        _print("  [yellow]Server: Ingen aktiv localhost-server fundet[/yellow]")
        if not args.url:
            _print("  [dim]Tip: Start din dev-server eller angiv URL med --url[/dim]")

    console.print() if RICH_AVAILABLE else print()

    # ── Fase 2: Statisk Analyse ──────────────────────────────────────────────
    _section("🔍 Fase 2 – Statisk Analyse")

    # Udtræk alle .env-værdier én gang – bruges til hardcoded-scan + browser-probe
    env_extracted = extract_all_env_values(project_path)

    # .env scanning
    _print("  Scanner .env filer...")
    env_findings = scan_env_files(project_path)
    vault_findings = check_env_vault(project_path)
    all_findings.extend(env_findings)
    all_findings.extend(vault_findings)
    env_example = check_env_example_exists(project_path)

    if env_findings:
        _findings_table(env_findings, "🔑 .env Sikkerhedsproblemer")
    else:
        _ok_line("Ingen kritiske secrets fundet i .env filer")

    if vault_findings:
        _findings_table(vault_findings, "🔒 .env.vault Status")

    if env_example["exists"]:
        _ok_line(f".env.example findes ({env_example['file']})")
    else:
        all_findings.append({
            "severity": "info",
            "description": ".env.example mangler – god praksis at have en",
            "detail": "Opret .env.example med placeholders for alle nødvendige variabler",
        })
        _print("  [blue]🔵[/blue] .env.example mangler (god praksis)")

    console.print() if RICH_AVAILABLE else print()

    # Git scanning
    _print("  Tjekker .gitignore og git-historik...")
    git_findings = check_gitignore(project_path) + check_secrets_in_git(project_path)
    all_findings.extend(git_findings)

    if git_findings:
        _findings_table(git_findings, "🗂️  Git Konfiguration & Historik")
    else:
        _ok_line(".gitignore dækker alle kritiske filer / ingen secrets i historik")

    console.print() if RICH_AVAILABLE else print()

    # Kode scanning (kendte mønstre)
    _print("  Scanner kildekode for sikkerhedsproblemer...")
    code_findings = scan_code_files(project_path, stack)
    all_findings.extend(code_findings)

    if code_findings:
        _findings_table(code_findings, "💻 Kildekode Analyse")
    else:
        _ok_line("Ingen kendte sikkerhedsmønstre fundet i kildekode")

    console.print() if RICH_AVAILABLE else print()

    # Hardcodet secret scanning – sammenlign .env-værdier mod ALLE kildefiler
    env_all_values = env_extracted.get("all_values", {}) if env_extracted else {}
    if env_all_values:
        _print(f"  Scanner kodebasen for hardcodede .env-værdier ({len(env_all_values)} variable)...")
        hardcoded_findings = scan_hardcoded_env_values(project_path, env_all_values)
        all_findings.extend(hardcoded_findings)
        if hardcoded_findings:
            _findings_table(hardcoded_findings, "🔐 Hardcodede Secrets i Kodebasen")
        else:
            _ok_line("Ingen .env-værdier fundet hardcodet i kildekode")
        console.print() if RICH_AVAILABLE else print()

    # ── Fase 3: Dynamisk Analyse ─────────────────────────────────────────────
    _section("⚡ Fase 3 – Dynamisk Analyse (Live)")

    if args.no_dynamic or not base_url:
        reason = "--no-dynamic" if args.no_dynamic else "ingen aktiv server"
        _print(f"  [dim]Dynamisk analyse sprunget over ({reason})[/dim]")
    else:
        # Header analyse
        _print(f"  Analyserer HTTP headers fra {base_url}...")
        header_result = analyze_headers(base_url)

        if header_result.get("error"):
            _print(f"  [yellow]⚠ Header-analyse fejlede: {header_result['error']}[/yellow]")
        else:
            header_findings = header_result.get("findings", [])
            all_findings.extend(header_findings)
            if header_findings:
                _findings_table(header_findings, "🌐 HTTP Header Analyse")
            else:
                _ok_line("Alle vigtige sikkerhedsheaders er sat korrekt")

            for svc in header_result.get("detected_services", []):
                _print(f"  [dim]Service opdaget: {svc['service']} (via {svc['via']})[/dim]")

        console.print() if RICH_AVAILABLE else print()

        # Database detektion – find ALLE databaser
        _print("  Detekterer databaser (alle lag)...")
        all_dbs = get_all_databases(project_path, base_url)
        db_info = detect_database(project_path, base_url)  # primær til RLS
        # env_extracted er allerede beregnet i Fase 2 – genbruges her

        if all_dbs:
            for db in all_dbs:
                db_type = db.get("type", "Ukendt")
                method = db.get("method", "")
                schema = db.get("schema_file", "")
                schema_info = f" [dim](schema: {schema})[/dim]" if schema else ""
                _print(f"  [bold]Database:[/bold] {db_type} [dim](via {method})[/dim]{schema_info}")

                # Vis URL env var hvis fundet via nøgle-navn
                if db.get("key_env_var"):
                    _print(f"  [dim]  → Env var: {db['key_env_var']}[/dim]")

                # Supabase anon-nøgle eksponeret
                if db.get("anon_key"):
                    source = "klient-HTML" if method == "header-first" else db.get("key_source", "fil")
                    all_findings.append({
                        "severity": "warning",
                        "description": f"Supabase anon-nøgle eksponeret i {source}",
                        "detail": f"Nøgle: {db['anon_key'][:30]}...",
                        "file": db.get("key_source", ""),
                    })

                # Firebase API key
                if db.get("firebase_api_key"):
                    all_findings.append({
                        "severity": "warning",
                        "description": "Firebase API-nøgle fundet i klientkode",
                        "detail": f"Key: {db['firebase_api_key'][:20]}...",
                        "file": db.get("key_source", ""),
                    })

                # DB-specifikke sikkerhedsadvarsler
                db_sec_findings = _db_security_findings(db)
                if db_sec_findings:
                    all_findings.extend(db_sec_findings)
                    _findings_table(db_sec_findings, f"🗄️  {db_type} Sikkerhedsanbefalinger")

        else:
            _print("  [dim]Ingen kendte database-konfigurationer fundet[/dim]")
            _print("  [dim]Tip: Prøv --url hvis appen kører på en anden port[/dim]")

        console.print() if RICH_AVAILABLE else print()

        # RLS Probe (Supabase)
        if not args.no_rls and db_info and "Supabase" in db_info.get("type", ""):
            is_self_hosted = "supabase.co" not in (db_info.get("url") or "").lower()
            host_type = "self-hosted" if is_self_hosted else "cloud"
            _print(f"  Kører RLS-probe mod Supabase ({host_type})...")
            rls_result = run_rls_probe(project_path, db_info)

            if rls_result.get("skipped"):
                _print(f"  [dim]RLS-probe sprunget over: {rls_result.get('reason')}[/dim]")
            else:
                rls_findings = rls_result.get("findings", [])
                all_findings.extend(rls_findings)
                tables_count = len(rls_result.get("tables_probed", []))
                code_tables = len(rls_result.get("code_tables_found", []))
                keys_tested = rls_result.get("keys_tested", [])
                if rls_findings:
                    _findings_table(
                        rls_findings,
                        f"🗄️  RLS Probe ({tables_count} tabeller × {len(keys_tested)} nøgle(r) × 4 auth-kombinationer)"
                    )
                else:
                    _ok_line(f"RLS ser aktiv ud ({tables_count} tabeller, {len(keys_tested)} nøgle(r) testet)")
                if keys_tested:
                    _print(f"  [dim]Nøgler testet: {', '.join(keys_tested[:5])}{' ...' if len(keys_tested) > 5 else ''}[/dim]")

            console.print() if RICH_AVAILABLE else print()

        # Browser Probe
        if not args.no_browser:
            if PLAYWRIGHT_AVAILABLE:
                env_pattern_count = len(env_extracted.get("all_values", {})) if env_extracted else 0
                _print(f"  Kører browser-probe (network + DOM scanning, {env_pattern_count} .env-værdier matchet dynamisk)...")
                browser_result = run_browser_probe(
                    base_url,
                    env_values=env_extracted.get("all_values") if env_extracted else None,
                )

                if browser_result.get("skipped"):
                    _print(f"  [dim]Browser-probe sprunget over: {browser_result.get('reason')}[/dim]")
                else:
                    browser_findings = browser_result.get("findings", [])
                    all_findings.extend(browser_findings)

                    req_count = browser_result.get("all_request_count", 0)
                    interesting = browser_result.get("network_requests", [])

                    if browser_findings:
                        _findings_table(browser_findings, "🌐 Browser Probe – Network & DOM Scanning")
                    else:
                        _ok_line(f"Browser-probe: ingen secrets fundet ({req_count} requests interceptet)")

                    if interesting:
                        _print(f"  [dim]Interessante API-kald ({len(interesting)}):[/dim]")
                        for req in interesting[:10]:
                            _print(f"  [dim]  → [{req.get('method','GET')}] {req.get('url','')[:80]} – {req.get('label','')}[/dim]")

                    env_hits_used = browser_result.get("env_patterns_used", 0)
                    if env_hits_used:
                        _print(f"  [dim]Dynamisk .env-matching: {env_hits_used} mønstre afprøvet mod netværkstrafik og DOM[/dim]")
            else:
                _print("  [dim]Browser-probe: Playwright ikke installeret[/dim]")
                _print("  [dim]  → Installer med: python install.py[/dim]")

        console.print() if RICH_AVAILABLE else print()

    # ── Final Rapport ────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    score = _calculate_score(all_findings)
    verdict, verdict_color = _vibe_verdict(score)

    critical_count = sum(1 for f in all_findings if f.get("severity") == "critical")
    warning_count  = sum(1 for f in all_findings if f.get("severity") == "warning")
    info_count     = sum(1 for f in all_findings if f.get("severity") == "info")

    if RICH_AVAILABLE:
        score_color = "green" if score >= 80 else ("yellow" if score >= 50 else "red")
        summary = (
            f"[bold {score_color}]Vibe Score: {score}/100[/bold {score_color}]   "
            f"[bold {verdict_color}]{verdict}[/bold {verdict_color}]\n\n"
            f"[red]🔴 Kritiske:[/red] {critical_count}   "
            f"[yellow]🟡 Advarsler:[/yellow] {warning_count}   "
            f"[blue]🔵 Info:[/blue] {info_count}\n"
            f"[dim]Scan afsluttet på {elapsed:.1f}s[/dim]"
        )
        console.print(Panel(
            summary,
            title="[bold]🛡️  SAFEVIBE v2 RAPPORT[/bold]",
            border_style=verdict_color,
            padding=(1, 4)
        ))
        console.print()
    else:
        print(f"\n{'='*60}\n  🛡️  SAFEVIBE v2 RAPPORT\n{'='*60}")
        print(f"  Vibe Score: {score}/100  {verdict}")
        print(f"  🔴 Kritiske: {critical_count}  🟡 Advarsler: {warning_count}  🔵 Info: {info_count}")
        print(f"  Scan afsluttet på {elapsed:.1f}s\n{'='*60}\n")

    sys.exit(1 if critical_count > 0 else 0)
