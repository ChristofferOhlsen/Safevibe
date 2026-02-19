# 🛡️ Safevibe

**Lokal sikkerhedsscanner til moderne webprojekter.**  
Kører 100% på din maskine – ingen data sendes til skyen.

---

## 🚀 Kom i gang

### 1. Installer afhængigheder (kun første gang)
```bash
python install.py
```

### 2. Scan et projekt
```bash
# Scan det nuværende projekt
python .

# Scan et specifikt projekt
python . /sti/til/dit/projekt

# Scan med en kørende dev-server
python . /sti/til/projekt --url http://localhost:3000
```

---

## 📋 Hvad scanner Safevibe?

### 🔍 Statisk Analyse (kildekode)
| Tjek | Beskrivelse |
|------|-------------|
| `.env` scanner | Finder eksponerede API-nøgler, passwords, JWT-tokens |
| Kode scanner | `dangerouslySetInnerHTML`, `eval()`, hardcoded secrets, SQL-injektion |
| Git scanner | Manglende `.gitignore`, secrets i commit-historik |

### ⚡ Dynamisk Analyse (live localhost)
| Tjek | Beskrivelse |
|------|-------------|
| Header-First detektion | Identificerer Supabase/Firebase via HTTP headers |
| Header analyse | CSP, CORS, X-Frame-Options, HSTS, X-Powered-By |
| RLS Probe | Tester Supabase Row Level Security aktivt |
| DB detektion | Finder database-URL og anon-nøgler i HTML/filer |

---

## 🎛️ Flagge

```
python . [sti]          Sti til projektet (standard: .)
--url URL               Angiv server URL manuelt
--no-dynamic            Spring dynamisk analyse over
--no-rls                Spring RLS-probe over
--help                  Vis hjælp
```

---

## 🎨 Vibe Score

| Score | Dom |
|-------|-----|
| 80–100 | ✅ Good Vibes |
| 50–79 | ⚠️ Sus Vibes |
| 25–49 | 😬 Bad Vibes |
| 0–24 | 💀 Toxic Vibes |

---

## 📁 Projektstruktur

```
safevibe/
├── __main__.py              # Entry point
├── install.py               # Installér afhængigheder
├── lib/                     # Vendored deps (auto-genereret)
└── engine/
    ├── cli.py               # Hoved-CLI og rapport
    ├── detector.py          # Port & stack detektion
    ├── static/
    │   ├── env_scanner.py   # .env analyse
    │   ├── code_scanner.py  # Kildekode analyse
    │   └── git_scanner.py   # Git konfiguration
    └── dynamic/
        ├── header_analyzer.py  # HTTP header analyse
        ├── db_detector.py      # Database detektion
        └── rls_prober.py       # Supabase RLS probe
```

---

## 🔒 Privatliv

- Kører **100% lokalt** i Python
- Ingen kode, API-nøgler eller database-strukturer forlader din maskine
- Anon-nøgler maskeres i output

---

## 🛠️ Understøttede teknologier

**Frameworks:** Next.js, Vite, React, Vue, Svelte, Nuxt, Astro, Remix  
**Databaser:** Supabase (inkl. RLS probe), Firebase, PostgreSQL, MongoDB  
**Sprog:** JavaScript, TypeScript, JSX, TSX, Vue, Svelte
