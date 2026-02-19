# 🛡️ Safevibe

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![Made with ❤️ in Denmark](https://img.shields.io/badge/Made%20with%20%E2%9D%A4%EF%B8%8F%20in-Denmark-red.svg)

**Lokal sikkerhedsscanner til moderne webprojekter.**  
Kører 100% på din maskine – ingen data sendes til skyen.

[Quick Start](#-quick-start) • [Hvorfor Safevibe?](#-hvorfor-safevibe) • [Features](#-hvad-scanner-safevibe) • [Advanced Usage](#-advanced-usage) • [Contributing](#-contributing)

</div>

---

## 🎯 Intro

Safevibe er et **dansk sikkerhedsværktøj** skabt til at hjælpe danske udviklere med at vibecode sikkert. 

I 2026 alene blev **64+ danske vibecodet projekter** fundet med kritiske sikkerhedssårbarheder - åbne databaser, eksponerede API-nøgler, manglende RLS (Row Level Security), og secrets committed til git. 

**Safevibe er mit bidrag til en sikker vibecoding kultur i Danmark.** 🇩🇰

---

## 🚀 Quick Start

### 🎯 For Folk Med Minimal GitHub/Python Erfaring

Denne guide hjælper dig med at komme i gang **selv hvis du aldrig har brugt GitHub før**. Følg hvert trin nøje! ✅

---

### 🔧 Trin 0: Tjek Om Du Har Python Installeret

**Åbn din terminal/kommandoprompt:**
- **Windows**: Tryk `Win + R`, skriv `cmd`, tryk Enter
- **Mac**: Tryk `Cmd + Space`, skriv `terminal`, tryk Enter
- **Linux**: Tryk `Ctrl + Alt + T`

**Tjek Python version:**
```bash
python --version
```

**Hvad skal jeg se?**
- ✅ `Python 3.8.x` eller højere → Du er klar! Gå til Trin 1
- ❌ `command not found` eller `Python 2.x` → Installer Python først (se nedenfor)

#### 🐍 Installer Python (hvis nødvendigt)

**Windows:**
1. Gå til [python.org/downloads](https://www.python.org/downloads/)
2. Download **Python 3.11** (eller nyere)
3. Kør installeren
4. ⚠️ **VIGTIGT**: Sæt flueben ved **"Add Python to PATH"**
5. Klik "Install Now"
6. Genstart din terminal og tjek igen med `python --version`

**Mac:**
```bash
# Brug Homebrew (hvis du har det)
brew install python3

# Eller download fra python.org/downloads
```

**Linux:**
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install python3 python3-pip

# Fedora
sudo dnf install python3 python3-pip
```

---

### 📦 Trin 1: Hent Safevibe Fra GitHub

Du har **to muligheder** - vælg den nemmeste for dig:

#### **Mulighed A: Download ZIP** (Nemmest! 🎉)

1. **Gå til**: [github.com/ChristofferOhlsen/Safevibe](https://github.com/ChristofferOhlsen/Safevibe)
2. **Klik på den grønne "Code" knap** (øverst til højre)
3. **Vælg "Download ZIP"**
4. **Pak ZIP-filen ud** (højreklik → "Extract All" / "Pak ud")
5. **Omdøb mappen** fra `Safevibe-main` til bare `safevibe` (lille s!)

#### **Mulighed B: Git Clone** (Hvis du har Git)

```bash
git clone https://github.com/ChristofferOhlsen/Safevibe.git safevibe
```

✅ **Du har nu en mappe der hedder `safevibe`** (lille s!)

---

### 📁 Trin 2: Placer Safevibe I Din Projekt-Rod

**VIGTIGT**: Safevibe skal placeres **i roden** af dit vibecode-projekt!

#### 🗂️ Sådan Skal Din Mappestruktur Se Ud:

```
mit-projekt/                    ← DIN PROJEKT-ROD
│
├── safevibe/                  ← PLACER SAFEVIBE MAPPEN HER!
│   ├── engine/
│   │   ├── cli.py
│   │   ├── detector.py
│   │   ├── static/
│   │   └── dynamic/
│   ├── lib/                   (kommer efter installation)
│   ├── __main__.py
│   ├── install.py
│   ├── README.md
│   └── safevibe               ← Kørbar fil
│
├── src/                       ← DIT PROJEKTS KODE
│   ├── app/
│   ├── components/
│   └── ...
│
├── .env                       ← Dine miljøvariabler
├── .gitignore
├── package.json               (hvis Node.js projekt)
├── requirements.txt           (hvis Python projekt)
└── ...
```

#### 📋 Step-by-Step Placering:

1. **Find din projekt-rod**:
   - Det er mappen med `package.json` (Node.js) eller `requirements.txt` (Python)
   - Normalt hvor din `.env` fil ligger
   - Mappen hvor du kører `npm run dev` eller `python manage.py runserver`

2. **Flyt/kopier** `safevibe` mappen **direkte ind i projekt-roden**

3. **Tjek at det er rigtigt**:
   ```bash
   # Naviger til din projekt-rod i terminalen
   cd /sti/til/mit-projekt
   
   # Tjek at safevibe mappen findes
   dir safevibe        # Windows
   ls safevibe         # Mac/Linux
   ```
   
   Du skal se: `engine`, `install.py`, `README.md`, osv.

✅ **Godt klaret! Safevibe er nu placeret korrekt.**

---

### ⚙️ Trin 3: Installer Safevibe Afhængigheder

**Navigér IND i safevibe mappen** og kør installationen:

```bash
# Fra din projekt-rod, gå ind i safevibe mappen
cd safevibe

# Kør installation
python install.py
```

#### ⏳ Hvad Sker Der?

- 🔄 Downloader dependencies (requests, rich, playwright, beautifulsoup4)
- 📦 Installerer alt lokalt i `/lib/` mappen (ingen global pip install)
- 🌐 Downloader Chromium browser (~200MB) til dynamisk scanning
- ⏱️ **Forventet tid**: 2-5 minutter (afhængig af internet hastighed)

#### 🎉 Færdig Når Du Ser:

```
✅ Dependencies installeret i /lib/
✅ Playwright installeret
✅ Browser installeret
🎉 Safevibe er klar til brug!
```

---

### 🚀 Trin 4: Start Dit Projekt

**Navigér TILBAGE til din projekt-rod:**

```bash
cd ..    # Gå en mappe op (tilbage til projekt-roden)
```

**Start dit projekt som normalt:**

```bash
# Next.js / Vite / React
npm run dev

# Django
python manage.py runserver

# Flask
flask run

# Andre frameworks
# ... brug din normale start-kommando
```

**Lad serveren køre!** Åbn en **ny terminal** til næste trin.

---

### 🔍 Trin 5: Scan Dit Projekt

**Åbn en NY terminal** og navigér til din projekt-rod:

```bash
cd /sti/til/mit-projekt
```

**Kør Safevibe scanning:**

```bash
# Scan nuværende projekt (fuld scanning)
python safevibe/safevibe

# ELLER hvis du stadig er i safevibe mappen:
cd ..
python safevibe/safevibe
```

#### 🎯 Scanning Modes:

```bash
# Scan et specifikt projekt
python safevibe/safevibe /sti/til/andet/projekt

# Scan med kørende server på custom port
python safevibe/safevibe --url http://localhost:4000

# Kun statisk analyse (ingen server nødvendig)
python safevibe/safevibe --no-dynamic
```

---

### ✅ Hvad Får Du?

Efter scanning viser Safevibe:

- **🎨 Vibe Score** (0-100) der viser din overordnede sikkerhed
- **📊 Detaljeret rapport** med fundne sårbarheder
- **⚠️ Prioriterede anbefalinger** (kritisk → advarsel → info)
- **💡 Konkrete løsninger** til hvert problem

---

### 🆘 Troubleshooting - Almindelige Fejl

#### ❌ "python: command not found"
**Løsning**: Python er ikke installeret eller ikke i PATH
- Gå tilbage til Trin 0 og installer Python
- Husk at sætte flueben ved "Add Python to PATH"

#### ❌ "No module named 'requests'" (eller lignende)
**Løsning**: Dependencies ikke installeret korrekt
```bash
cd safevibe
python install.py
```

#### ❌ "FileNotFoundError: safevibe"
**Løsning**: Du kører kommandoen fra forkert mappe
- Du skal være i **projekt-roden** (ikke inde i safevibe mappen)
- Brug `python safevibe/safevibe` (med mappe-præfix)

#### ❌ Scanning finder ingen server
**Løsning**: 
1. Tjek at din dev-server KØR ER (`npm run dev`, osv.)
2. Angiv URL manuelt: `python safevibe/safevibe --url http://localhost:3000`
3. Eller spring dynamisk analyse over: `python safevibe/safevibe --no-dynamic`

#### ❌ "Permission denied" (Mac/Linux)
**Løsning**: Gør safevibe filen eksekverbar
```bash
chmod +x safevibe/safevibe
```

---

### 🎓 Hurtig Recap

```
✅ Trin 0: Tjek Python (python --version)
✅ Trin 1: Download Safevibe fra GitHub
✅ Trin 2: Placer i projekt-roden
✅ Trin 3: cd safevibe → python install.py
✅ Trin 4: cd .. → start dit projekt (npm run dev, osv.)
✅ Trin 5: python safevibe/safevibe
```

**Du er nu klar til at vibecode sikkert! 🛡️**

### ✅ Hvad får du?
Safevibe giver dig:
- **Vibe Score** (0-100) der viser din overordnede sikkerhed
- **Detaljeret rapport** med fundne sårbarheder
- **Prioriterede anbefalinger** (kritisk → info)
- **Konkrete løsninger** til hvert problem

---

## 💡 Hvorfor Safevibe?

### 🇩🇰 **DANSK**
- Dokumentation og output på dansk
- Skabt af og til danske udviklere
- Forstår den danske vibecoding kultur

### ✨ **NEMT**
- 3 kommandoer og du er i gang
- Ingen kompleks opsætning
- Fungerer out-of-the-box

### 🔒 **VIGTIGT**
- 64+ danske projekter fundet med kritiske sårbarheder i 2026
- Beskytter mod de 10 mest almindelige sikkerhedsfejl
- Fanger problemer før de når produktion

### 🏠 **LOKALT**
- Kører 100% på din maskine
- Ingen data sendes til skyen
- Ingen tracking eller telemetri

### 🔍 **DYBDEGÅENDE**
- Kombinerer statisk + dynamisk analyse
- Scanner både kildekode og kørende app
- Tester aktivt for RLS-problemer i Supabase

### 🤝 **MIT BIDRAG**
- Open source værktøj til fællesskabet
- Hjælper med at hæve sikkerhedsniveauet
- Del af en større mission om sikker vibecoding

---

## 📋 Hvad scanner Safevibe?

Safevibe kører i **3 faser** og kombinerer **statisk** og **dynamisk** analyse for maksimal dækning.

### 📡 Fase 1: Detektion

Safevibe analyserer dit projekt og identificerer:

| Hvad detekteres | Eksempler |
|-----------------|-----------|
| **Tech Stack** | Next.js, Vite, React, Vue, Django, Flask, osv. |
| **Kørende Server** | Finder automatisk din dev-server på localhost |
| **Database** | Supabase, Firebase, PostgreSQL, MongoDB, osv. |
| **Frameworks** | 15+ frameworks understøttes |

**Hvordan?** Safevibe læser `package.json`, `requirements.txt`, `composer.json`, osv. og scanner aktive porte (3000, 5173, 8000, osv.).

---

### 🔍 Fase 2: Statisk Analyse (Kildekode)

Safevibe scanner din kodebase **uden at køre den**.

#### 📁 .env Scanner
Finder eksponerede secrets i `.env` filer:

| Hvad findes | Eksempler |
|-------------|-----------|
| **API-nøgler** | OpenAI (sk-), Anthropic (sk-ant-), GitHub (ghp_) |
| **Database credentials** | Connection strings med brugernavn/password |
| **JWT tokens** | Supabase anon keys, service_role keys |
| **Payment keys** | Stripe LIVE keys (sk_live_), webhook secrets |
| **Email services** | SendGrid, Mailgun, Resend tokens |
| **Auth tokens** | Clerk, NextAuth secrets |
| **Cloud services** | AWS keys (AKIA...), Firebase, Vercel tokens |
| **40+ mønstre** | Dækker alle store platforme |

**Bonus:** Tjekker om `.env.example` findes og om `.env.vault` (Dotenv Vault) er korrekt konfigureret.

#### 💻 Kode Scanner
Finder farlige mønstre i JavaScript, TypeScript, Python, PHP:

| Kategori | Eksempler |
|----------|-----------|
| **XSS-risici** | `dangerouslySetInnerHTML`, `innerHTML`, `eval()` |
| **SQL Injection** | String concatenation i SQL queries |
| **Command Injection** | `exec()` med user input |
| **Path Traversal** | `fs.readFile()` med request params |
| **Hardcoded secrets** | API-nøgler direkte i koden |
| **Svag kryptografi** | `Math.random()` til tokens, MD5/SHA1 |
| **JWT problemer** | Tokens uden `expiresIn`, `algorithm: "none"` |
| **CORS wildcards** | `Access-Control-Allow-Origin: *` |
| **SSL-deaktivering** | `rejectUnauthorized: false` |
| **50+ checks** | Dækker OWASP Top 10 |

#### 🗂️ Git Scanner
Analyserer git-konfiguration og historik:

| Hvad tjekkes | Hvorfor |
|--------------|---------|
| **.gitignore dækning** | Sikrer at `.env`, `*.pem`, osv. er ignoreret |
| **Git historik** | Scanner seneste 50 commits for secrets |
| **Tracked .env files** | Finder `.env` filer der allerede er committed |
| **Anbefalinger** | Foreslår `git filter-repo` hvis nødvendigt |

#### 🔐 Hardcoded Secret Scanner
**Ny feature!** Sammenligner alle værdier fra dine `.env` filer med din kildekode:

```javascript
// ❌ BAD: Hardcoded secret fra .env
const client = createClient("https://xyz.supabase.co", "eyJhbGci...")
                                                        ↑ denne værdi kommer fra .env!

// ✅ GOOD: Brug env-variabel
const client = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
)
```

Scanner **alle filtyper** inkl. `.json`, `.toml`, `.yaml`, `docker-compose.yml`, osv.

---

### ⚡ Fase 3: Dynamisk Analyse (Live)

Safevibe analyserer din **kørende applikation** på localhost.

#### 🌐 HTTP Header Analyse
Tjekker vigtige sikkerhedsheaders:

| Header | Beskyttelse |
|--------|-------------|
| **Content-Security-Policy** | XSS-beskyttelse |
| **X-Frame-Options** | Clickjacking-beskyttelse |
| **Strict-Transport-Security** | HTTPS enforcement |
| **Access-Control-Allow-Origin** | CORS konfiguration |
| **X-Content-Type-Options** | MIME-sniffing beskyttelse |
| **Cross-Origin-* policies** | Spectre-angreb beskyttelse |
| **Cookie security** | HttpOnly, Secure, SameSite |
| **Info-lækage** | Server, X-Powered-By headers |

**Bonus:** Identificerer automatisk Supabase, Firebase, Vercel, Netlify via headers.

#### 🗄️ Database Detektion (4-lags hybrid)

Safevibe bruger en **avanceret 4-lags detektor** til at finde databaser:

1. **Header-First scanning** - Analyserer HTTP headers fra live server
2. **Prisma/Drizzle parsing** - Læser `schema.prisma` og drizzle config
3. **Env var NAVNE** - Matcher variabelnavne (f.eks. `SUPABASE_URL`)
4. **Env var VÆRDIER** - Regex på connection strings

**Understøtter 20+ databaser:**
- **Cloud:** Supabase, Firebase, Neon, PlanetScale, Turso, Upstash, Convex, Xata
- **Traditionelle:** PostgreSQL, MySQL, MongoDB, Redis, SQLite, MS SQL
- **ORMs:** Prisma, Drizzle, TypeORM, Sequelize
- **Backend-as-a-Service:** Hasura, Appwrite, PocketBase, Fauna

#### 🚨 RLS Probe (Supabase)

**Den mest kraftfulde feature!** Safevibe tester aktivt om Row Level Security (RLS) er aktiveret på dine Supabase-tabeller.

**Hvordan virker det?**

1. **Finder alle nøgler** i dine `.env` filer (anon, service_role, osv.)
2. **Identificerer tabeller** fra din kildekode (`.from('users')`, `prisma.profiles`, osv.)
3. **Tester 4 auth-kombinationer** per tabel:
   - `apikey + Authorization: Bearer` (standard)
   - `apikey` alene
   - `Authorization: Bearer` alene  
   - Ingen auth (worst case)
4. **Rapporterer kritiske fund** hvis data er tilgængelig uden RLS

```
🚨 KRITISK: Tabel 'users' ÅBEN UDEN AUTH
→ Tabellen returnerer data UDEN nogen form for autentificering
→ Alle på internettet kan læse dine brugere
→ Aktiver RLS i Supabase Dashboard → Authentication → Policies
```

**Understøtter:**
- ✅ Supabase Cloud (`*.supabase.co`)
- ✅ Self-hosted Supabase
- ✅ Anon keys, service_role keys, custom JWTs
- ✅ Automatisk JWT role-detection via base64 decode

**Kritiske tabeller testet automatisk:**
`users`, `profiles`, `accounts`, `orders`, `payments`, `messages`, `admin`, `sessions`, `api_keys`, osv.

#### 🌐 Browser Probe (Playwright)

**Avanceret network + DOM scanning** med headless Chrome:

**Hvad scannes:**

| Sted | Hvad findes |
|------|-------------|
| **Network requests** | API-nøgler i headers, query strings, request bodies |
| **Response bodies** | Secrets i JSON/JavaScript responses |
| **Inline scripts** | Hardcoded secrets i `<script>` tags |
| **Meta tags** | API-nøgler i meta-attributter |
| **Data-attributes** | `data-key`, `data-token`, osv. |
| **Global state** | `window.__NEXT_DATA__`, `window.__NUXT__` |
| **window.ENV** | Eksponerede env-variabler i frontend |

**Dynamisk .env-matching:**
Browser-proben bruger **alle dine .env-værdier** til at scanne netværkstrafik og DOM dynamisk:

```
✅ Browser-probe: 47 .env-værdier matchet mod netværkstrafik
🔴 KRITISK: SUPABASE_SERVICE_ROLE_KEY eksponeret i response body
```

---

## 🎨 Vibe Score System

Efter scanning får du en **Vibe Score** (0-100) baseret på fundne problemer:

| Score | Vurdering | Betydning |
|-------|-----------|-----------|
| **80–100** | ✅ **Good Vibes** | Godt sikkerhedsniveau - mindre justeringer |
| **50–79** | ⚠️ **Sus Vibes** | Nogle bekymringer - bør fixes |
| **25–49** | 😬 **Bad Vibes** | Alvorlige problemer - fix ASAP |
| **0–24** | 💀 **Toxic Vibes** | Kritisk usikker - må ikke i produktion |

### Hvordan beregnes scoren?

```
Start: 100 point
- 15 point per KRITISK problem (API-nøgler, åbne databaser, osv.)
-  5 point per ADVARSEL (manglende headers, svage mønstre)
-  1 point per INFO (mindre anbefalinger)

Minimum: 0 point
```

**Eksempel:**
```
3 kritiske problemer: 100 - (3 × 15) = 55 point (Sus Vibes)
5 advarsler:          55 - (5 × 5) = 30 point (Bad Vibes)
```

---

## 🎛️ Advanced Usage

### Kommandolinje Flags

```bash
# Scan specifik mappe
python safevibe /sti/til/projekt

# Angiv URL manuelt (hvis auto-detection fejler)
python safevibe --url http://localhost:4000

# Spring dynamisk analyse over (kun statisk)
python safevibe --no-dynamic

# Spring RLS-probe over
python safevibe --no-rls

# Spring browser-probe over
python safevibe --no-browser

# Kombiner flags
python safevibe /min/app --url http://localhost:3001 --no-browser

# Vis hjælp
python safevibe --help
```

### Use Cases

#### 1. Full Scan (anbefalet)
```bash
# Start din app først
npm run dev

# Kør fuld scanning
python safevibe
```

#### 2. Kun Statisk Analyse
```bash
# Ingen server nødvendig
python safevibe --no-dynamic
```

#### 3. CI/CD Integration
```bash
# Exit code 1 hvis kritiske problemer findes
python safevibe /project --no-browser
```

#### 4. Custom Port
```bash
# Din app kører på port 4321
python safevibe --url http://localhost:4321
```

#### 5. Scan Produktionsbranch
```bash
git checkout production
python safevibe --no-dynamic  # Statisk scan kun
```

---

## 🛠️ Understøttede Teknologier

### Frameworks (15+)

| Frontend | Backend | Full-Stack |
|----------|---------|------------|
| React | Express | Next.js |
| Vue | Flask | Nuxt |
| Svelte | FastAPI | SvelteKit |
| Angular | Django | Remix |
| Solid | Nest.js | Astro |
| Qwik | Sails.js | T3 Stack |

### Databaser (20+)

| Type | Teknologier |
|------|-------------|
| **Cloud Postgres** | Supabase, Neon, PlanetScale, CockroachDB |
| **Realtime** | Firebase, Convex, Appwrite, PocketBase |
| **Edge/Serverless** | Turso (SQLite), Upstash (Redis), Xata |
| **Traditionel** | PostgreSQL, MySQL, MongoDB, Redis, SQLite |
| **Backend-as-a-Service** | Hasura, Fauna |
| **ORMs** | Prisma, Drizzle, TypeORM, Sequelize |

### Programmeringssprog

| Sprog | Filtyper |
|-------|----------|
| **JavaScript/TypeScript** | `.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs` |
| **Frameworks** | `.vue`, `.svelte` |
| **Python** | `.py` |
| **PHP** | `.php` |

---

## 📁 Projektstruktur

```
safevibe/
├── README.md              # Denne fil
├── __main__.py            # Entry point - bootstrap for lib/
├── install.py             # Dependency installer (zero-footprint)
├── lib/                   # Vendored dependencies (auto-genereret)
│   ├── requests/
│   ├── rich/
│   ├── beautifulsoup4/
│   ├── playwright/
│   └── browsers/          # Chromium (headless)
└── engine/                # Core scanning engine
    ├── __init__.py
    ├── cli.py             # Hoved-CLI og rapport generator
    ├── detector.py        # Port & tech-stack detektion
    ├── static/            # Statisk analyse
    │   ├── __init__.py
    │   ├── env_scanner.py    # .env secret detection (40+ mønstre)
    │   ├── code_scanner.py   # Kildekode analyse (50+ checks)
    │   └── git_scanner.py    # Git historik + .gitignore
    └── dynamic/           # Dynamisk analyse
        ├── __init__.py
        ├── header_analyzer.py  # HTTP header checks
        ├── db_detector.py      # 4-lags database detektion
        ├── rls_prober.py       # Supabase RLS probe
        └── browser_probe.py    # Playwright network interception
```

### Hvordan virker arkitekturen?

1. **`__main__.py`** - Bootstrap script der:
   - Tilføjer `/lib/` til Python path
   - Sætter Playwright browser path
   - Kalder `engine.cli.run()`

2. **`install.py`** - Installerer alt til `/lib/`:
   - Core dependencies (requests, rich, beautifulsoup4, playwright)
   - Chromium browser (~200MB) til `/lib/browsers/`
   - Zero-footprint - ingen global pip install

3. **`engine/`** - Scanning engine:
   - **`cli.py`** - Orkestrerer alle scannere, viser rapport
   - **`detector.py`** - Smart port/stack detektion
   - **`static/`** - Statiske scannere (kode, env, git)
   - **`dynamic/`** - Dynamiske analysers (headers, DB, RLS, browser)

---

## ⚠️ False Positives

Safevibe er designet til at være præcis, men false positives kan forekomme.

### Almindelige False Positives

#### 1. `.env` Findings
**Problem:** Safevibe rapporterer secrets i `.env` filer  
**Hvorfor:** `.env` filer **skal** indeholde secrets - det er deres formål  
**Løsning:** Dette er markeret som `INFO` (ikke kritisk). Fokuser på:
- Er `.env` i `.gitignore`? ✅
- Er secrets hardcoded i kildekode? ❌

#### 2. Public API-nøgler
**Problem:** `NEXT_PUBLIC_SUPABASE_ANON_KEY` flagges  
**Hvorfor:** Anon keys **må** være i frontend - det er designet sådan  
**Løsning:** Tjek at:
- RLS er aktiveret ✅
- Service_role key IKKE er i frontend ❌

#### 3. Development URLs
**Problem:** `http://localhost:3000` flagges som ukrypteret  
**Hvorfor:** Localhost HTTP er OK under udvikling  
**Løsning:** Ignorer for development - fix i produktion

#### 4. Eksempel-kode i kommentarer
**Problem:** Kommentarer med `eval()` eksempler flagges  
**Hvorfor:** Static analyse ser ikke forskel på kode og kommentarer  
**Løsning:** Flyt eksempler til dokumentation

### Hvordan håndteres False Positives?

1. **Læs severity-niveauet:**
   - `KRITISK` (🔴) - skal fixes
   - `ADVARSEL` (🟡) - bør fixes
   - `INFO` (🔵) - FYI / context

2. **Tjek kontekst:**
   - Er det i `.env` (OK) eller kildekode (BAD)?
   - Er det development (OK) eller production (BAD)?
   - Er det public key (OK) eller secret key (BAD)?

3. **Brug `--no-*` flags:**
   ```bash
   # Spring specifikke checks over
   python safevibe --no-rls --no-browser
   ```

4. **Rapporter hvis det er en reel bug:**
   - Åbn en issue på GitHub
   - Inkluder context og kodeeksempel

---

## 🤝 Contributing

Safevibe er open source og modtager gerne bidrag!

### Hvordan bidrager du?

#### 1. Rapporter Bugs
- Åbn en **GitHub Issue**
- Beskriv problemet (hvilken scanning-fase, output, osv.)
- Inkluder (anonymiseret) kode hvis muligt

#### 2. Foreslå Features
- Åbn en **Feature Request** issue
- Forklar use case og hvorfor det er vigtigt
- Link til dokumentation hvis relevant

#### 3. Tilføj Nye Secret-mønstre
Safevibe bruger regex til at finde secrets. Tilføj til `engine/static/env_scanner.py`:

```python
# FORMAT_PATTERNS - matcher værdier
(r"ditt_regex_pattern", "Beskrivelse", "critical"),

# KEY_PATTERNS - matcher nøglenavne
(r"(?i)^DITT_PATTERN\s*=\s*.{8,}", "Beskrivelse", "critical"),
```

#### 4. Tilføj Nye Kode-checks
Tilføj til `engine/static/code_scanner.py`:

```python
(r"farligt_mønster", "Beskrivelse", "critical", None),  # Alle sprog
(r"react_mønster", "Beskrivelse", "critical", "React"),  # Kun React
```

#### 5. Udvid Database-detektion
Tilføj til `engine/dynamic/db_detector.py`:

```python
# ENV_KEY_DB_PATTERNS - nøglenavne
(re.compile(r"(?i)ditdb.*url", re.I), "DitDB"),

# ENV_VALUE_PATTERNS - connection strings
(re.compile(r"ditdb://[^\s\"']+", re.I), "DitDB", "url"),
```

### Development Setup

```bash
# Clone repository
git clone https://github.com/ChristofferOhlsen/Safevibe.git
cd Safevibe

# Installer dependencies
python install.py

# Test ændringer
python safevibe /test/projekt

# Kør mod Safevibe selv (self-scan)
python safevibe .
```

### Code Style
- Python 3.8+ kompatibel
- Docstrings på dansk
- Kommentarer på dansk
- Følg eksisterende struktur

---

## 🔒 Privatliv & Sikkerhed

### Privacy-garantier

✅ **100% Lokalt** - Alt kører på din maskine  
✅ **Ingen Telemetri** - Ingen tracking eller analytics  
✅ **Ingen Cloud Upload** - Ingen kode/data sendes væk  
✅ **Zero-footprint** - Dependencies installeres kun i `/lib/`  
✅ **Åben Kildekode** - Du kan verificere alt  

### Hvad ser Safevibe?

| Data | Hvor | Hvad sker |
|------|------|-----------|
| **Kildekode** | Lokale filer | Scannes for mønstre - gemmes ikke |
| **.env filer** | Lokale filer | Scannes - værdier maskeres i output |
| **Git historik** | `.git/` folder | Scannes lokalt - sendes ikke væk |
| **HTTP traffic** | Localhost | Interceptes - kun metadata gemmes |
| **Database** | Localhost/cloud | Testes med READ-only queries |

### Hvordan maskeres secrets?

```
❌ Output UDEN maskering:
SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS...

✅ Output MED maskering:
SUPABASE_KEY=***
Nøgle: eyJhbGci... (første 20 tegn)
```

### Sikkerhed i RLS Probe

RLS-proben tester **kun med READ queries** (`GET /rest/v1/table?limit=1`):

- ❌ Ingen writes (`INSERT`, `UPDATE`, `DELETE`)
- ❌ Ingen schema-ændringer (`ALTER`, `DROP`)
- ✅ Kun `SELECT` med `limit=1`
- ✅ Stopper ved første fund

---

## 📊 Sammenligning med Andre Værktøjer

| Feature | Safevibe | Snyk | GitGuardian | Semgrep |
|---------|----------|------|-------------|---------|
| **Dansk** | ✅ | ❌ | ❌ | ❌ |
| **Gratis** | ✅ | Begrænset | Begrænset | ✅ |
| **100% Lokalt** | ✅ | ❌ | ❌ | ✅ |
| **Dynamisk Analyse** | ✅ | ❌ | ❌ | ❌ |
| **RLS Probe** | ✅ | ❌ | ❌ | ❌ |
| **Browser Probe** | ✅ | ❌ | ❌ | ❌ |
| **Database Detektion** | ✅ (20+) | Begrænset | ❌ | ❌ |
| **Git Historik** | ✅ | ✅ | ✅ | ❌ |
| **Zero Setup** | ✅ | ❌ | ❌ | Delvist |

**Safevibe's unikke værdi:**
- 🇩🇰 Eneste danske sikkerhedsværktøj
- 🔍 Kombinerer statisk + dynamisk analyse
- 🚨 Aktivt tester Supabase RLS
- 🌐 Browser network interception
- 🏠 100% privatliv - ingen cloud

---

## 📜 License & Support

### License
MIT License - fri til kommerciel og privat brug.

Se [LICENSE](LICENSE) for detaljer.

### Support
- **GitHub Issues** - Bug reports og feature requests
- **Dokumentation** - Denne README
- **Email** - [dit-email@example.com] (opdater dette)

### Roadmap
- [ ] GitHub Actions integration
- [ ] JSON/SARIF output format
- [ ] VSCode extension
- [ ] Firebase Rules validation
- [ ] Custom regex patterns via config
- [ ] HTML rapport-generator

---

## 🙏 Tak til

- Alle danske udviklere der vibecoder sikkert
- Open source biblioteker: `requests`, `rich`, `playwright`, `beautifulsoup4`
- Supabase for fantastisk dokumentation om RLS

---

## 📈 Stats

```
🔍 40+ secret-mønstre (statisk)
💻 50+ kode-checks (OWASP Top 10)
🗄️ 20+ database-teknologier
⚡ 4-lags hybrid database-detektion
🚨 RLS probe (4 auth-kombinationer × N tabeller)
🌐 Browser probe (network + DOM + .env-matching)
🇩🇰 100% dansk udviklet
```

---

<div align="center">

**Vibecode sikkert. 🛡️**

Made with ❤️ in Denmark 🇩🇰

[GitHub](https://github.com/ChristofferOhlsen/Safevibe) • [Issues](https://github.com/ChristofferOhlsen/Safevibe/issues) • [Contributing](#-contributing)

</div>
