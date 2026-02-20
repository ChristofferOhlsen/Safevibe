"""
report.py – Comprehensive HTML Rapport Generator til Safevibe v2.
Genererer en detaljeret, professionel HTML-rapport efter hver scan.
"""

import os
import re
import math
from datetime import datetime
from pathlib import Path


# ─── Fix-guidance bibliotek ───────────────────────────────────────────────────
# Liste af (søge-nøgleord, forklaring, løsning) tupler.
# Nøgleordet matches mod finding-beskrivelsen (case-insensitive delstreng).

FIX_GUIDANCE: list[tuple[str, str, str]] = [
    # ── .env / Secrets ────────────────────────────────────────────────────────
    (
        "secret",
        "En hemmelig nøgle eller adgangskode er eksponeret i kildekoden eller i en fil der er tilgængelig udefra. "
        "Angribere kan bruge denne nøgle til at få fuld adgang til din database, API eller tjeneste. "
        "Hemmeligheder i git-historikken forbliver synlige selv efter sletning af filen.",
        "1. Flyt nøglen til en .env-fil.\n"
        "2. Tilføj .env til .gitignore så den aldrig committes.\n"
        "3. Brug aldrig hemmelige nøgler i frontend/klientkode – kun i server-side kode.\n"
        "4. Revoker og regenerer nøglen hos udbyderen (Supabase, Firebase, osv.) straks.\n"
        "5. Kør 'git log -p | grep <nøgle>' for at tjekke om den er i historikken.",
    ),
    (
        "hardcodet",
        "En .env-variabelværdi er fundet direkte i kildekoden. Det betyder at hemmeligheder er bagt ind i "
        "applikationskoden og vil blive synlige for alle der kan se koden – inkl. i git-historikken. "
        "Selv efter fjernelse af værdien fra koden kan den stadig hentes frem via git log.",
        "1. Erstat den hardcodede værdi med en reference til environment-variablen (f.eks. process.env.VAR_NAME).\n"
        "2. Sørg for at .env er i .gitignore.\n"
        "3. Tjek git-loggen med 'git log -p' – hvis værdien er committed, skal historikken renses.\n"
        "4. Brug 'git filter-repo' eller BFG Repo Cleaner til at rense historikken.",
    ),
    (
        "hardcoded",
        "En .env-variabelværdi er fundet direkte i kildekoden. Hemmeligheder bagt ind i koden er synlige "
        "for alle med adgang til repositoriet og forbliver i git-historikken selv efter fjernelse. "
        "Dette er en af de mest udbredte og farlige sikkerhedsfejl i webapplikationer.",
        "1. Erstat den hardcodede værdi med en environment-variabel-reference.\n"
        "2. Sørg for at .env er i .gitignore.\n"
        "3. Rens git-historikken med 'git filter-repo --path .env --invert-paths'.\n"
        "4. Force-push til remote: git push --force --all\n"
        "5. Regenerer alle kompromitterede nøgler.",
    ),
    (
        "api key",
        "En API-nøgle er eksponeret. API-nøgler bruges til at autentificere din applikation mod en ekstern tjeneste. "
        "Hvis den lækkes, kan nogen bruge din konto til at generere omkostninger, tilgå dine data eller misbruge tjenesten. "
        "Mange API-udbydere tilbyder adgangslogge der kan afsløre uautoriseret brug.",
        "1. Flyt nøglen til .env og brug den kun på server-siden.\n"
        "2. Sæt IP-restriktioner eller scope-begrænsninger hos API-udbyderen.\n"
        "3. Regenerer nøglen straks og revider adgangsloggen.\n"
        "4. Overvej at bruge et secrets management system som Vault eller AWS Secrets Manager.",
    ),
    (
        "token",
        "Et adgangstoken er eksponeret. Tokens fungerer som adgangskoder og giver adgang til ressourcer "
        "eller tjenester på dine vegne. Eksponerede tokens kan bruges øjeblikkeligt af angribere "
        "uden nogen yderligere autentificering.",
        "1. Opbevar tokens i miljøvariabler på serveren – aldrig i klientkode.\n"
        "2. Sæt en udløbsdato (expiry) på tokenet hvis muligt.\n"
        "3. Regenerer tokenet og tjek om det har været misbrugt i loggen.\n"
        "4. Implementér token rotation for langlivet adgang.",
    ),
    (
        "anon",
        "Supabase anon-nøglen er eksponeret. Anon-nøglen er den offentlige nøgle til din Supabase-instans og "
        "er beregnet til klientkode. MEN uden korrekte RLS-regler (Row Level Security) giver den fri adgang "
        "til ALLE tabeller og data. Mange Supabase-projekter har desværre RLS deaktiveret.",
        "1. Gå til Supabase Dashboard → Authentication → Policies.\n"
        "2. Aktiver RLS på ALLE tabeller: ALTER TABLE <tabel> ENABLE ROW LEVEL SECURITY;\n"
        "3. Opret passende policies der begrænser adgang til autentificerede brugere.\n"
        "4. Anon-nøglen kan godt være i klientkode, men KUN hvis RLS er korrekt konfigureret.\n"
        "5. Test dine RLS-policies med Supabase SQL-editoren som anonym bruger.",
    ),
    (
        "service_role",
        "Supabase service_role-nøglen er eksponeret! Denne nøgle omgår ALLE Row Level Security regler og "
        "giver fuld administrativ adgang til din database. Det er den farligste nøgle du har – "
        "med den kan enhver læse, skrive og slette ALT data i din database.",
        "1. Fjern service_role-nøglen fra al klientkode STRAKS.\n"
        "2. Brug den KUN i server-side kode (API routes, serverless functions) i et sikkert miljø.\n"
        "3. Regenerer nøglen i Supabase Dashboard → Settings → API.\n"
        "4. Revider loggen for mistænkelig aktivitet i Supabase Dashboard → Logs.",
    ),
    (
        "service key",
        "En service-nøgle med forhøjede rettigheder er eksponeret. Denne type nøgle omgår typisk "
        "sikkerhedsregler og giver fuld adgang til systemet. Eksponeringen kan give angribere "
        "komplet kontrol over din data og infrastruktur.",
        "1. Fjern nøglen fra klientkode og frontend øjeblikkeligt.\n"
        "2. Brug kun service-nøgler i sikre server-side miljøer.\n"
        "3. Regenerer nøglen hos udbyderen straks.\n"
        "4. Implementér mindste-privilegie-princippet – brug scoped nøgler med begrænset adgang.",
    ),
    # ── Firebase ──────────────────────────────────────────────────────────────
    (
        "firebase",
        "En Firebase-konfigurationsnøgle er eksponeret. Firebase API-nøgler er delvist offentlige af design, "
        "men uden korrekte Firestore Security Rules og Firebase Storage Rules kan alle læse og skrive alle data. "
        "Mange Firebase-projekter stjæles netop på grund af åbne rules kombineret med en eksponeret nøgle.",
        "1. Sæt Firestore Security Rules til at kræve autentificering:\n"
        "   allow read, write: if request.auth != null;\n"
        "2. Sæt Firebase Storage Rules tilsvarende.\n"
        "3. Aktiver App Check for at begrænse adgang til kun din app.\n"
        "4. Gå til Firebase Console → Firestore → Rules og gennemgå dem nøje.\n"
        "5. Overvej at bruge Firebase Auth med passende brugerpermissioner.",
    ),
    # ── Database sikkerhed ────────────────────────────────────────────────────
    (
        "rls",
        "Row Level Security (RLS) er ikke aktiveret eller har utilstrækkelige policies. RLS er det primære "
        "forsvar i PostgreSQL/Supabase mod at brugere tilgår hinandens data. Uden RLS kan enhver "
        "autentificeret bruger potentielt læse og ændre alle rækker i databasen.",
        "1. Aktiver RLS på tabellen: ALTER TABLE <tabel> ENABLE ROW LEVEL SECURITY;\n"
        "2. Opret mindst én SELECT-policy: CREATE POLICY <navn> ON <tabel> FOR SELECT USING (auth.uid() = user_id);\n"
        "3. Test policies med Supabase SQL-editor som anonym bruger.\n"
        "4. Kør: SELECT tablename FROM pg_tables WHERE schemaname='public' for at finde alle tabeller.\n"
        "5. Brug Supabase's Policy Editor til at verificere dækning.",
    ),
    (
        "sql",
        "Potentiel SQL-injektion er fundet. Direkte sammensætning af brugerinput i SQL-forespørgsler "
        "kan give angribere mulighed for at læse, ændre eller slette data i databasen. "
        "SQL-injektion er rangeret som #1 på OWASP Top 10 og er stadig en hyppig angrebsvektor.",
        "1. Brug altid parameteriserede queries / prepared statements.\n"
        "2. Brug et ORM (Prisma, Drizzle, Sequelize) der håndterer escaping automatisk.\n"
        "3. Valider og sanitér alt brugerinput server-side.\n"
        "4. Implementér input validation med et schema-bibliotek (Zod, Joi, yup).\n"
        "5. Aldrig: `SELECT * FROM users WHERE id = '${userId}'` – brug altid bindingsparametre.",
    ),
    (
        "redis",
        "Redis er fundet uden adgangskode (requirepass) eller eksponeret uden for localhost. "
        "En ubeskyttet Redis-instans giver fuld læse/skrive-adgang til alle data og kan bruges til "
        "Remote Code Execution via Lua-scripting eller konfigurationsmanipulation.",
        "1. Sæt requirepass i redis.conf: requirepass <stærk-adgangskode>\n"
        "2. Bind Redis kun til localhost: bind 127.0.0.1\n"
        "3. Brug TLS hvis Redis kommunikerer over netværket.\n"
        "4. Kald aldrig Redis eksponeret direkte på internet.\n"
        "5. Overvej Redis ACLs for finkornet adgangsstyring.",
    ),
    (
        "mongodb",
        "MongoDB er fundet – tjek at autentificering er aktiveret. En MongoDB-instans uden --auth "
        "flag er fuldstændig åben og har historisk ført til massedatatyveri af millioner af records. "
        "MongoDB-databaser uden auth er regelmæssigt skannet af bots og tømt for data.",
        "1. Start mongod med --auth flag.\n"
        "2. Opret admin-bruger: db.createUser({user:'admin', pwd:'<stærkt-kodeord>', roles:['root']})\n"
        "3. Bind til localhost: net.bindIp: 127.0.0.1 i mongod.conf\n"
        "4. Aktiver TLS/SSL med --tlsMode requireTLS.\n"
        "5. Brug mindste-privilegie: opret separate brugere pr. applikation med begrænset adgang.",
    ),
    (
        "sqlite",
        "SQLite bruges som database med Prisma. SQLite er ikke egnet til produktionsbrug da den ikke "
        "understøtter concurrent writes, skalering eller cloud-deployments. "
        "I produktion kan SQLite medføre datalåsning og tab.",
        "1. Skift til PostgreSQL (anbefalet) eller MySQL til produktionsbrug.\n"
        "2. Opdater schema.prisma: provider = \"postgresql\"\n"
        "3. Sæt DATABASE_URL til en PostgreSQL connection string i .env.\n"
        "4. Kør 'npx prisma migrate deploy' efter skiftet.",
    ),
    (
        "prisma",
        "Prisma er fundet med en potentiel konfigurationsfejl. Databaseforbindelsesstrengen indeholder "
        "muligvis credentials der ikke er tilstrækkeligt beskyttet. "
        "En eksponeret DATABASE_URL giver komplet adgang til databasen.",
        "1. Sørg for at DATABASE_URL kun er defineret i .env og aldrig hardcodet.\n"
        "2. Tilføj .env til .gitignore.\n"
        "3. Brug connection pooling (PgBouncer/Prisma Accelerate) i produktion.\n"
        "4. Gennemse Prisma query logs for potentielle N+1 og injection-problemer.",
    ),
    (
        "hasura",
        "Hasura er fundet – tjek at HASURA_GRAPHQL_ADMIN_SECRET er sat og ikke eksponeret. "
        "Uden admin secret er Hasura's GraphQL API fuldstændig åben og alle kan forespørge, "
        "mutere og abonnere på alle data.",
        "1. Sæt HASURA_GRAPHQL_ADMIN_SECRET til en stærk hemmelig værdi (min. 32 tegn).\n"
        "2. Brug aldrig admin secret i klientkode.\n"
        "3. Konfigurer Authorization headers og role-based permissions i Hasura Console.\n"
        "4. Aktiver 'Allow List' for at begrænse hvilke queries der må udføres.",
    ),
    # ── Git / Versionsstyring ─────────────────────────────────────────────────
    (
        "gitignore",
        ".gitignore er ikke konfigureret til at ekskludere følsomme filer. Det betyder at .env-filer, "
        "certifikater og andre hemmeligheder kan blive committet til git-repositoriet ved en fejl. "
        "En manglende .gitignore er en af de hyppigste årsager til utilsigtet lækage af secrets.",
        "1. Tilføj disse linjer til .gitignore:\n"
        "   .env\n   .env.local\n   .env.*.local\n   *.key\n   *.pem\n   /secrets/\n   .env.production\n"
        "2. Kør 'git rm --cached .env' hvis .env allerede er tracked.\n"
        "3. Brug 'git status' før hvert commit for at kontrollere hvad der tilføjes.\n"
        "4. Overvej at bruge pre-commit hooks til automatisk at afvise commits med secrets.",
    ),
    (
        "git historik",
        "En hemmelig nøgle eller adgangskode er fundet i git-historikken. Selvom filen er slettet, "
        "forbliver indholdet tilgængeligt via 'git log' og er synligt for alle med adgang til repositoriet – "
        "inkl. ved public GitHub repos. Secrets i historikken betragtes som permanent kompromitterede.",
        "1. Brug 'git filter-repo' til at fjerne data fra historikken:\n"
        "   pip install git-filter-repo\n"
        "   git filter-repo --path .env --invert-paths\n"
        "2. Force-push til remote: git push --force --all\n"
        "3. Regenerer ALLE kompromitterede nøgler – de er permanent eksponerede.\n"
        "4. Varsle evt. berørte brugere eller tjenester.",
    ),
    # ── HTTP Headers ──────────────────────────────────────────────────────────
    (
        "content-security-policy",
        "Content-Security-Policy (CSP) headeren mangler. CSP er en vigtig forsvarsmekanisme mod "
        "Cross-Site Scripting (XSS) angreb der tillader angribere at injicere ondsindet JavaScript. "
        "Uden CSP kan en XSS-sårbarhed give fuldstændig kontrol over brugerens session.",
        "1. Tilføj CSP-headeren til din server/middleware:\n"
        "   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';\n"
        "2. For Next.js: tilføj i next.config.js under headers().\n"
        "3. Brug 'report-uri' eller 'report-to' til at logge overtrædelserf i starten.\n"
        "4. Start med report-only tilstand: Content-Security-Policy-Report-Only\n"
        "5. Undgå 'unsafe-inline' og 'unsafe-eval' – brug nonces i stedet.",
    ),
    (
        "strict-transport-security",
        "HTTP Strict Transport Security (HSTS) headeren mangler. Uden HSTS kan angribere nedgradere "
        "HTTPS-forbindelser til HTTP og udføre man-in-the-middle angreb der opsnapper al kommunikation. "
        "HSTS sikrer at browsere altid bruger krypteret forbindelse til dit domæne.",
        "1. Tilføj headeren: Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
        "2. Overvej at tilføje 'preload' og registrere domænet på hstspreload.org.\n"
        "3. Sørg for at din app altid redirecter HTTP → HTTPS (301 redirect).\n"
        "4. Sæt max-age til minimum 1 år (31536000 sekunder) for fuld beskyttelse.",
    ),
    (
        "x-frame-options",
        "X-Frame-Options headeren mangler. Uden denne header kan din side loades i en iframe på en "
        "ondsindet hjemmeside (clickjacking), der kan narre brugere til at klikke på skjulte knapper "
        "og f.eks. udføre handlinger uden deres samtykke.",
        "1. Tilføj headeren: X-Frame-Options: DENY (eller SAMEORIGIN).\n"
        "2. Moderne alternativ: brug CSP med frame-ancestors: 'none' (mere fleksibelt).\n"
        "3. Begge metoder kan sættes: de er komplementære.",
    ),
    (
        "x-content-type",
        "X-Content-Type-Options headeren mangler. Uden den kan browsere 'gætte' filtypen og f.eks. "
        "fortolke en uploadet tekstfil som JavaScript (MIME-sniffing angreb). "
        "Dette kan bruges til at omgå upload-filtre og køre ondsindet kode.",
        "1. Tilføj headeren: X-Content-Type-Options: nosniff\n"
        "2. Sørg for altid at sætte korrekt Content-Type på alle responses.\n"
        "3. Validér filtype server-side ved upload – stol ikke på klientens Content-Type.",
    ),
    (
        "referrer-policy",
        "Referrer-Policy headeren mangler. Uden den sender browseren fuld URL (inkl. tokens i query strings) "
        "til tredjepartstjenester, hvilket kan lække følsomme parametre til eksterne parter. "
        "Dette er særligt problematisk ved API-nøgler eller session-tokens i URLs.",
        "1. Tilføj headeren: Referrer-Policy: strict-origin-when-cross-origin\n"
        "2. Undgå at sende følsomme data i URL-parametre (brug POST/body i stedet).\n"
        "3. For fuldstændig privatliv: Referrer-Policy: no-referrer",
    ),
    (
        "permissions-policy",
        "Permissions-Policy headeren (tidligere Feature-Policy) mangler. Headeren begrænser adgang til "
        "browser-APIs som kamera, mikrofon og geolocation for at reducere angrebsfladen. "
        "Uden denne header kan XSS-angreb udnytte alle browser-features.",
        "1. Tilføj headeren: Permissions-Policy: camera=(), microphone=(), geolocation=()\n"
        "2. Tillad kun de funktioner din app faktisk bruger.\n"
        "3. Gennemgå listen af tilgængelige features på developer.mozilla.org.",
    ),
    (
        "server-version",
        "Server-softwareversion eksponeres i HTTP-headers (f.eks. Server: nginx/1.18.0). Dette giver "
        "angribere information om hvilke kendte sårbarheder der kan udnyttes mod din specifikke version. "
        "Dette er et 'fingerprinting' problem der øger angrebsfladen.",
        "1. Skjul versionsinfo i nginx: server_tokens off; i nginx.conf\n"
        "2. Skjul versionsinfo i Apache: ServerTokens Prod og ServerSignature Off i httpd.conf.\n"
        "3. Fjern X-Powered-By headeren: app.disable('x-powered-by') i Express.\n"
        "4. Fjern X-AspNet-Version og X-AspNetMvc-Version i .NET apps.",
    ),
    # ── CORS ──────────────────────────────────────────────────────────────────
    (
        "cors",
        "CORS-konfigurationen tillader for brede origins (f.eks. wildcard *). Det betyder at enhver "
        "hjemmeside kan sende autentificerede requests til din API og potentielt udføre handlinger "
        "på vegne af dine brugere (CSRF-lignende angreb).",
        "1. Sæt Access-Control-Allow-Origin til kun de specifikke domæner du tillader.\n"
        "2. Brug aldrig '*' kombineret med credentials (cookies/auth-headers).\n"
        "3. Valider Origin-headeren server-side mod en whitelist.\n"
        "4. Sæt Access-Control-Allow-Methods til kun de HTTP-metoder du faktisk bruger.",
    ),
    # ── Kode-sikkerheds problemer ─────────────────────────────────────────────
    (
        "debug",
        "Debug-mode eller verbose fejlvisning er aktiveret i produktion. Det kan eksponere stack traces, "
        "filstier, databaseforespørgsler og intern applikationslogik for brugere. "
        "Angribere kan bruge denne information til at kortlægge systemer og finde sårbarheder.",
        "1. Sæt NODE_ENV=production (eller DEBUG=false) i produktionsmiljøet.\n"
        "2. Brug generiske fejlbeskeder til brugere, log detaljer kun server-side.\n"
        "3. For Next.js: sørg for at NEXT_PUBLIC_DEBUG ikke er sat til true.\n"
        "4. Implementér et centraliseret logging-system (f.eks. Sentry) til fejlsporing.",
    ),
    (
        "eval",
        "Brug af eval() er fundet i kildekoden. eval() eksekverer en streng som JavaScript-kode og er "
        "en kritisk sikkerhedsrisiko hvis strengen kan påvirkes af brugerinput (Remote Code Execution). "
        "eval() omgår enhver form for sikkerhedskontrol og kan køre vilkårlig kode.",
        "1. Erstat eval() med sikre alternativer (JSON.parse til JSON, Function-konstruktøren med validering).\n"
        "2. Aktiver 'no-eval' ESLint-reglen for at forhindre fremtidig brug.\n"
        "3. Gennemgå alle steder der bruger new Function() – de har lignende risici.\n"
        "4. Aktiver CSP med 'unsafe-eval' deaktiveret for at blokere eval i browseren.",
    ),
    (
        "innerHTML",
        "Brug af innerHTML med dynamisk indhold er fundet. Hvis brugerinput sættes direkte via innerHTML "
        "kan angribere injicere ondsindet HTML/JavaScript (DOM-baseret XSS). "
        "DOM XSS er svær at opdage og kan stjæle sessions eller omdirigere brugere.",
        "1. Brug textContent i stedet for innerHTML til at sætte tekst uden HTML-parsing.\n"
        "2. Brug DOMPurify til at sanitere HTML hvis du skal bruge innerHTML med dynamisk indhold.\n"
        "3. I React: undgå dangerouslySetInnerHTML medmindre indholdet er saniteret med DOMPurify.\n"
        "4. Aktiver CSP for at reducere skadesomfang ved XSS.",
    ),
    (
        "innerhtml",
        "Brug af innerHTML med dynamisk indhold er fundet. Hvis brugerinput sættes direkte via innerHTML "
        "kan angribere injicere ondsindet HTML/JavaScript (DOM-baseret XSS). "
        "DOM XSS er svær at opdage og kan stjæle sessions eller omdirigere brugere.",
        "1. Brug textContent i stedet for innerHTML til at sætte tekst.\n"
        "2. Brug DOMPurify til at sanitere HTML ved brug af innerHTML med dynamisk indhold.\n"
        "3. I React: undgå dangerouslySetInnerHTML medmindre DOMPurify bruges.\n"
        "4. Aktiver CSP for at reducere skadesomfang ved XSS.",
    ),
    # ── XSS og Injection ─────────────────────────────────────────────────────
    (
        "xss",
        "Cross-Site Scripting (XSS) sårbarhed er fundet. XSS giver angribere mulighed for at injicere "
        "og køre ondsindet JavaScript i din applikations kontekst. Dette kan bruges til at stjæle "
        "sessions, omdirigere brugere til phishing-sider eller udnytte brugerens browser.",
        "1. Sanitér ALT brugerinput før det vises i HTML – brug et bevist bibliotek (DOMPurify).\n"
        "2. Aktiver Content-Security-Policy for at begrænse script-eksekvering.\n"
        "3. Brug template engines der automatisk HTML-escaper output (React, Vue, Angular).\n"
        "4. Aldrig sæt brugerinput direkte i DOM via innerHTML, document.write() eller eval().\n"
        "5. Aktiver HTTPOnly og Secure flags på alle session-cookies.",
    ),
    (
        "injection",
        "En mulig code injection-sårbarhed er fundet. Injection angreb opstår når upålidelige data "
        "sendes til en interpreter som en del af en kommando eller query. Dette kan resultere i "
        "datavomskrivning, datalækage, eller fuldstændig systemkompromittering.",
        "1. Valider og sanitér ALT input fra brugere og eksterne kilder.\n"
        "2. Brug parameteriserede queries til alle databaseoperationer.\n"
        "3. Undgå at eksekvere shell-kommandoer baseret på brugerinput.\n"
        "4. Implementér input whitelist-validering (tillad kun kendte gyldige værdier).\n"
        "5. Kør din applikation med mindste-privilegier.",
    ),
    (
        "path traversal",
        "En path traversal-sårbarhed er fundet. Angribere kan bruge '../' sekvenser til at navigere "
        "ud af den tilsigtede mappe og tilgå følsomme filer på serveren som /etc/passwd eller "
        "applikationens konfigurationsfiler med hemmeligheder.",
        "1. Normaliser alle filstier med path.resolve() og kontrollér de starter i den tilladte rod.\n"
        "2. Brug en whitelist af tilladte filnavne/mapper frem for blacklist.\n"
        "3. Kør applikationen i en chroot jail eller container for at begrænse filsystemadgang.\n"
        "4. Tillad aldrig brugerinput direkte i filsti-operationer.\n"
        "5. Valider at den normaliserede sti starter med den tilladte base-sti.",
    ),
    # ── CSRF / Session ────────────────────────────────────────────────────────
    (
        "csrf",
        "Cross-Site Request Forgery (CSRF) beskyttelse mangler eller er utilstrækkelig. CSRF angreb "
        "narrer autentificerede brugere til ubevidst at udføre handlinger på din hjemmeside "
        "ved at besøge en ondsindet hjemmeside der sender requests til din API.",
        "1. Implementér CSRF-tokens for alle state-ændrede operationer (POST, PUT, DELETE).\n"
        "2. Brug SameSite=Strict eller SameSite=Lax cookies for at begrænse cross-site requests.\n"
        "3. Valider Origin og Referer headers server-side.\n"
        "4. I Next.js: brug next-auth med built-in CSRF-beskyttelse.\n"
        "5. For REST APIs: konfigurer CORS korrekt til at afvise uautoriserede origins.",
    ),
    (
        "session",
        "Et sessionshåndteringsproblem er fundet. Svage session-tokens eller manglende session-sikkerhed "
        "kan give angribere mulighed for at overtage brugersessioner (session hijacking). "
        "Sessions er nøglen til al autentificering og skal beskyttes omhyggeligt.",
        "1. Brug kryptografisk sikre, tilfældige session-IDs (min. 128 bit entropi).\n"
        "2. Sæt Secure, HttpOnly og SameSite=Strict på session-cookies.\n"
        "3. Regenerer session-ID efter login (session fixation beskyttelse).\n"
        "4. Implementér session-udløb og logout der invaliderer server-side sessions.\n"
        "5. Overvej at bruge et etableret auth-bibliotek (next-auth, passport.js).",
    ),
    # ── Prototype / Deserialization ───────────────────────────────────────────
    (
        "prototype",
        "Prototype pollution er fundet. Denne sårbarhed tillader angribere at ændre JavaScript Object "
        "prototypen, hvilket kan påvirke alle objekter i applikationen og potentielt føre til "
        "Remote Code Execution, authentication bypass eller denial of service.",
        "1. Valider og sanitér alle JSON-input mod prototype-forurening.\n"
        "2. Brug Object.create(null) for objekter der bruges som hash maps.\n"
        "3. Undgå dynamisk objektmapping baseret på brugerinput (f.eks. obj[key] = value).\n"
        "4. Brug biblioteker som lodash (opdateret version) der er patched mod prototype pollution.\n"
        "5. Aktiver Object.freeze(Object.prototype) i mere sikkerhedskritiske kontekster.",
    ),
    (
        "deserialization",
        "Usikker deserialisering er fundet. Angribere kan manipulere serialiserede objekter for at "
        "opnå Remote Code Execution, authentication bypass eller privilegieeskalering. "
        "Dette er en af de mest farlige sårbarheder (OWASP Top 10 A08).",
        "1. Deserialiser aldrig data fra upålidelige kilder uden validation.\n"
        "2. Brug JSON.parse() frem for eval() eller andre unsafe parsere.\n"
        "3. Implementér integritetskontrol (HMAC signatur) på serialiserede data.\n"
        "4. Kør deserialisering i et sandboxet miljø.\n"
        "5. Opdater alle serialiseringsbiblioteker til seneste version.",
    ),
    # ── Rate limiting / Mass assignment ──────────────────────────────────────
    (
        "rate limit",
        "Rate limiting mangler eller er utilstrækkelig. Uden rate limiting kan angribere udføre "
        "brute force angreb på passwords, token enumeration, eller overbelaste din API "
        "med denial-of-service angreb.",
        "1. Implementér rate limiting på alle autentifieringsendpoints.\n"
        "2. Brug et bibliotek som express-rate-limit eller Upstash Ratelimit.\n"
        "3. Sæt strenge limits på password reset, login og signup endpoints.\n"
        "4. Overvej gradvist stigende forsinkelser (exponential backoff) ved gentagne fejl.\n"
        "5. Implementér account lockout efter N forkerte forsøg.",
    ),
    (
        "mass assignment",
        "Mass assignment sårbarhed er fundet. Angribere kan sende ekstra felter i requests "
        "der utilsigtet overskriver privilegerede felter som 'isAdmin', 'role' eller 'credit'. "
        "Dette er en kritisk autorisationsfejl.",
        "1. Brug en eksplicit whitelist af tilladte felter ved objektopdatering.\n"
        "2. Valider input med et schema (Zod, Joi) der kun tillader kendte felter.\n"
        "3. I ORMs: brug 'select' til at specificere hvilke felter der returneres.\n"
        "4. Adskil interne modeller fra offentlige API-modeller (DTOs).\n"
        "5. Strip ukendte felter server-side inden databaseskrivning.",
    ),
    # ── Upload / GraphQL ──────────────────────────────────────────────────────
    (
        "upload",
        "Usikker filupload er fundet. Uden korrekt validering kan angribere uploade ondsindede filer "
        "som webshells der tillader server-side kodeeksekvering, eller XSS-filer der angriber andre brugere. "
        "Usikre uploads er en hyppig angrebsvektor i webapplikationer.",
        "1. Valider filtype server-side via magic bytes – stol ikke på Content-Type eller filendelse.\n"
        "2. Gem uploadede filer udenfor web root med et genereret filnavn.\n"
        "3. Brug en CDN/blob storage (S3, Cloudflare R2) frem for lokal opbevaring.\n"
        "4. Begræns tilladte filtyper og maksimal filstørrelse.\n"
        "5. Scan uploadede filer for malware inden de behandles.",
    ),
    (
        "graphql",
        "GraphQL er fundet – tjek at introspection er deaktiveret i produktion og at der er "
        "implementeret query depth limiting og rate limiting. Uden disse begrænsninger er en "
        "GraphQL API sårbar over for DoS-angreb og information disclosure.",
        "1. Deaktiver introspection i produktion: {introspection: false}\n"
        "2. Implementér query depth limiting for at forhindre dybe nested queries.\n"
        "3. Begræns query complexity (cost limiting).\n"
        "4. Autentificer og autoriser alle sensitiva queries.\n"
        "5. Brug persisted queries i produktion for at begrænse hvilke queries der accepteres.",
    ),
    # ── Log injection / Regex / Race condition ────────────────────────────────
    (
        "log injection",
        "Log injection sårbarhed er fundet. Angribere kan injicere newlines og kontroltegn i logbeskeder "
        "for at forfalske logposter, skjule angreb, eller manipulere log-parsere. "
        "Forfalskning af logs besværliggør hændelsesanalyse og forensics.",
        "1. Sanitér alle brugerinput inden logning – fjern newlines og kontroltegn.\n"
        "2. Brug et struktureret logging-bibliotek (Winston, Pino) der automatisk escaper logs.\n"
        "3. Inkluder aldrig rå brugerinput direkte i logbeskeder.\n"
        "4. Implementér log-integritetskontrol og overvågning for unormale logmønstre.",
    ),
    (
        "regex",
        "Potentiel ReDoS (Regular Expression Denial of Service) sårbarhed er fundet. Katastrofale "
        "backtracking i regex-mønstre kan medføre at serveren bruger eksponentiel tid på at evaluere "
        "et ondsindet input, hvilket fører til denial of service.",
        "1. Undgå nested quantifiers i regex (f.eks. (a+)+, (a|a?)+).\n"
        "2. Brug et safe regex-bibliotek som 're2' der garanterer lineær eksekvering.\n"
        "3. Sæt timeout på regex-evaluering.\n"
        "4. Test alle regex-mønstre med redos-checker.vercel.app.\n"
        "5. Begræns input-længde inden regex-anvendelse.",
    ),
    (
        "race condition",
        "Race condition sårbarhed er fundet. Concurrent operationer på delte ressourcer uden korrekt "
        "låsning kan resultere i inkonsistent data, timeof-check-time-of-use (TOCTOU) fejl, "
        "eller mulighed for at udnytte et kort vindue for privilegiet eskalering.",
        "1. Brug atomiske databaseoperationer til kritiske opdateringer.\n"
        "2. Implementér optimistisk låsning med version/timestamp-felter.\n"
        "3. Brug transactions for operationer der kræver multiple trin.\n"
        "4. I distribuerede systemer: brug distributed locking (Redis SETNX, database advisory locks).\n"
        "5. Design idempotente operationer der kan gentages sikkert.",
    ),
    # ── Autentificering / JWT ─────────────────────────────────────────────────
    (
        "jwt",
        "En JWT-secret eller privat nøgle er eksponeret. JWT-secrets bruges til at signere tokens – "
        "med secret'en kan angribere forge tokens og udgive sig for enhver bruger inkl. admins. "
        "Dette er en kritisk autentificeringsfejl.",
        "1. Brug en lang, tilfældig secret (min. 256 bit): openssl rand -base64 32\n"
        "2. Opbevar secret kun i miljøvariabler server-side – aldrig i klientkode.\n"
        "3. Overvej asymmetrisk signering (RS256) fremfor symmetrisk (HS256).\n"
        "4. Sæt kort udløbstid på tokens og implementér refresh token flow.\n"
        "5. Regenerer secret-en straks og invalider alle eksisterende tokens.",
    ),
    (
        "nextauth",
        "NEXTAUTH_SECRET eller en NextAuth-konfigurationsfejl er fundet. NextAuth secret bruges til "
        "at signere og kryptere session-tokens – svag eller eksponeret secret kompromitterer alle sessions. "
        "Alle eksisterende sessioner er potentielt kompromitterede.",
        "1. Generer en stærk secret: openssl rand -base64 32\n"
        "2. Sæt NEXTAUTH_SECRET i .env (aldrig i klientkode eller kildekode).\n"
        "3. Sæt NEXTAUTH_URL til din produktions-URL.\n"
        "4. Invalidér alle aktive sessions ved at skifte secret.",
    ),
    # ── Betalingsintegration ──────────────────────────────────────────────────
    (
        "stripe",
        "En Stripe API-nøgle er eksponeret. Stripe secret keys giver fuld adgang til din betalingskonto "
        "inkl. mulighed for at opkræve kunder, refundere betalinger og tilgå betalingsdata. "
        "En kompromitteret Stripe secret key kan medføre store finansielle tab.",
        "1. Fjern Stripe secret key fra al klientkode øjeblikkeligt.\n"
        "2. Brug KUN Stripe publishable key (pk_...) i frontend.\n"
        "3. Alle Stripe-operationer med secret key (sk_...) skal ske eksklusivt server-side.\n"
        "4. Regenerer nøglen i Stripe Dashboard → Developers → API keys straks.\n"
        "5. Gennemgå Stripe Dashboard for uautoriserede transaktioner.",
    ),
    # ── AI / Cloud tjenester ──────────────────────────────────────────────────
    (
        "openai",
        "En OpenAI API-nøgle er eksponeret. Eksponerede OpenAI-nøgler kan misbruges til at generere "
        "enorme omkostninger på din konto eller bruges til at tilgå Fine-tuned models eller Assistants. "
        "OpenAI-nøgler stjæles og misbruges aktivt af automatiserede bots.",
        "1. Flyt nøglen til en server-side miljøvariabel straks.\n"
        "2. Alle OpenAI-kald skal proxies igennem din server – aldrig direkte fra klienten.\n"
        "3. Regenerer nøglen på platform.openai.com → API keys.\n"
        "4. Sæt udgiftslimits på din OpenAI konto for at begrænse potentielle skader.",
    ),
    (
        "aws",
        "AWS-credentials (Access Key ID / Secret Access Key) er eksponeret. Dette er ekstremt kritisk – "
        "kompromitterede AWS-nøgler bruges hyppigt til at mine kryptovaluta på din regning, "
        "exfiltrere S3-data, oprette bagdøre og generere fakturaer på tusindvis af dollars.",
        "1. Regenerer nøglerne i AWS IAM Console STRAKS og slet de kompromitterede.\n"
        "2. Brug IAM Roles i stedet for access keys på EC2/Lambda/ECS.\n"
        "3. Aktiver AWS CloudTrail for at auditere hvad nøglerne har adgang til.\n"
        "4. Konfigurer AWS Budgets alerts for uventede omkostninger.\n"
        "5. Rapportér kompromitterede nøgler til AWS security: aws-security@amazon.com",
    ),
    (
        "private key",
        "En privat nøgle (RSA/EC/SSH) er eksponeret i kildekoden. Private nøgler bruges til kryptografi "
        "og autentificering – eksponering kompromitterer al krypteret kommunikation og muliggør "
        "impersonering af serveren.",
        "1. Fjern nøglen fra kodebasen straks og rens git-historikken.\n"
        "2. Tilbagekald/regenerer certifikatet hos den relevante CA (Certificate Authority).\n"
        "3. Opbevar private nøgler i et secrets management system (Vault, AWS Secrets Manager).\n"
        "4. Brug hardware security modules (HSM) til kritisk nøgleopbevaring.",
    ),
    # ── Andre tjenester ───────────────────────────────────────────────────────
    (
        "sendgrid",
        "En SendGrid API-nøgle er eksponeret. Angribere kan bruge den til at sende spam og phishing-mails "
        "fra dit domæne, ødelægge dit afsender-omdømme og potentielt blackliste dit domæne. "
        "Misbrug af SendGrid kan medføre suspenderet konto og store omkostninger.",
        "1. Flyt nøglen til .env server-side.\n"
        "2. Brug scoped API keys med kun de nødvendige rettigheder (Mail Send).\n"
        "3. Regenerer nøglen i SendGrid Dashboard → Settings → API Keys.",
    ),
    (
        "twilio",
        "Twilio-credentials er eksponeret. Disse kan misbruges til at sende SMS og foretage opkald "
        "på din regning, implementere SMS-baseret phishing, eller udtømme din Twilio-konto. "
        "Twilio-misbrug opdages ofte først på fakturaen.",
        "1. Flyt Account SID og Auth Token til server-side .env.\n"
        "2. Brug Twilio API Keys i stedet for Master Auth Token når muligt.\n"
        "3. Regenerer Auth Token i Twilio Console → Account → Auth Tokens.",
    ),
    (
        ".env.example",
        ".env.example-filen mangler. Dette er en god praksis der hjælper andre udviklere med at forstå "
        "hvilke miljøvariabler der er nødvendige. Uden .env.example risikeres at produktionsmiljøet "
        "konfigureres forkert pga. manglende dokumentation af nødvendige variable.",
        "1. Opret .env.example med alle nødvendige variable som placeholders:\n"
        "   DATABASE_URL=postgresql://user:password@host:5432/db\n"
        "   NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co\n"
        "2. Commit .env.example til git (den indeholder ingen rigtige værdier).\n"
        "3. Opdater .env.example ved tilføjelse af nye miljøvariabler.",
    ),
    (
        "console.log",
        "console.log med potentielt følsomt indhold er fundet i kildekoden. I produktionsmiljøer "
        "kan disse loglinjer eksponere interne data i browser-konsollen. "
        "Angribere bruger aktivt browser-konsollen til at lede efter lekkede hemmeligheder.",
        "1. Fjern eller erstat console.log med et logging-bibliotek der kan slukkes i produktion.\n"
        "2. Brug aldrig console.log til at logge brugerdata, tokens eller passwords.\n"
        "3. Sæt NODE_ENV=production for automatisk at slå mange logs fra.",
    ),
    (
        "password",
        "En adgangskode er eksponeret i kildekode eller konfiguration. Kompromitterede adgangskoder "
        "giver direkte adgang til systemer og databaser. "
        "Hardcodede adgangskoder kan ikke roteres uden kodeændring.",
        "1. Flyt adgangskoden til en miljøvariabel i .env.\n"
        "2. Regenerer adgangskoden straks.\n"
        "3. Tjek om adgangskoden er brugt andre steder og skift den der også.",
    ),
    (
        "webhook",
        "En webhook-hemmelighed eller URL er eksponeret. Webhook-secrets bruges til at verificere "
        "at indgående beskeder er ægte – eksponering gør det muligt at forfalske dem "
        "og trigge uautoriserede handlinger i din applikation.",
        "1. Flyt webhook secret til .env.\n"
        "2. Valider altid webhook-signaturen server-side inden behandling.\n"
        "3. Brug HTTPS-endpoints til webhooks.\n"
        "4. Implementér idempotency keys for at forhindre replay-angreb.",
    ),
]


# ─── CSS Konstant ─────────────────────────────────────────────────────────────

_REPORT_CSS = """\
:root {
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --bg-card: #1e293b;
    --bg-card-hover: #263548;
    --border: #334155;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --critical: #ef4444;
    --critical-bg: rgba(239,68,68,0.1);
    --critical-border: #7f1d1d;
    --warning: #f59e0b;
    --warning-bg: rgba(245,158,11,0.1);
    --warning-border: #78350f;
    --info: #3b82f6;
    --info-bg: rgba(59,130,246,0.1);
    --info-border: #1e3a5f;
    --ok: #22c55e;
    --ok-bg: rgba(34,197,94,0.1);
    --ok-border: #14532d;
    --nav-bg: rgba(15,23,42,0.95);
    --shadow: 0 4px 6px -1px rgba(0,0,0,0.4), 0 2px 4px -1px rgba(0,0,0,0.3);
    --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.5), 0 4px 6px -2px rgba(0,0,0,0.4);
    --code-bg: #0d1117;
    --code-text: #e6edf3;
    --radius: 12px;
    --radius-sm: 8px;
}
[data-theme="light"] {
    --bg-primary: #f8fafc;
    --bg-secondary: #ffffff;
    --bg-card: #ffffff;
    --bg-card-hover: #f1f5f9;
    --border: #e2e8f0;
    --text-primary: #0f172a;
    --text-secondary: #475569;
    --text-muted: #94a3b8;
    --critical: #dc2626;
    --critical-bg: #fef2f2;
    --critical-border: #fca5a5;
    --warning: #d97706;
    --warning-bg: #fffbeb;
    --warning-border: #fcd34d;
    --info: #2563eb;
    --info-bg: #eff6ff;
    --info-border: #93c5fd;
    --ok: #16a34a;
    --ok-bg: #f0fdf4;
    --ok-border: #86efac;
    --nav-bg: rgba(30,41,59,0.97);
    --shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -1px rgba(0,0,0,0.06);
    --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05);
    --code-bg: #1e293b;
    --code-text: #e2e8f0;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    font-size: 15px;
    transition: background 0.3s, color 0.3s;
}
/* ── Nav ── */
.nav {
    position: sticky; top: 0; z-index: 100;
    background: var(--nav-bg);
    border-bottom: 1px solid var(--border);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
}
.nav-inner {
    max-width: 1200px; margin: 0 auto; padding: 0 24px;
    display: flex; align-items: center; gap: 4px; height: 56px; flex-wrap: wrap;
}
.nav-brand {
    font-weight: 700; font-size: 16px; color: #38bdf8;
    margin-right: 16px; white-space: nowrap;
}
.nav-link {
    padding: 6px 12px; border-radius: 6px; text-decoration: none;
    color: var(--text-secondary); font-size: 13px; font-weight: 500;
    transition: background 0.15s, color 0.15s; white-space: nowrap; display: flex; align-items: center; gap: 6px;
}
.nav-link:hover { background: rgba(255,255,255,0.08); color: var(--text-primary); }
.nav-badge {
    display: inline-flex; align-items: center; justify-content: center;
    min-width: 20px; height: 20px; padding: 0 6px;
    border-radius: 999px; font-size: 11px; font-weight: 700; line-height: 1;
}
.nav-badge.critical { background: var(--critical); color: #fff; }
.nav-badge.warning { background: var(--warning); color: #000; }
.nav-badge.info { background: var(--info); color: #fff; }
.nav-badge.ok { background: var(--ok); color: #000; }
.nav-right { margin-left: auto; display: flex; align-items: center; gap: 8px; }
.btn-theme {
    background: transparent; border: 1px solid var(--border);
    color: var(--text-secondary); padding: 5px 10px; border-radius: 6px;
    cursor: pointer; font-size: 14px; transition: all 0.15s; line-height: 1;
}
.btn-theme:hover { background: rgba(255,255,255,0.08); color: var(--text-primary); }
/* ── Layout ── */
.main { max-width: 1200px; margin: 0 auto; padding: 32px 24px; }
/* ── Header ── */
.report-header {
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border: 1px solid var(--border); border-radius: var(--radius);
    padding: 32px 36px; margin-bottom: 28px;
    box-shadow: var(--shadow-lg);
}
[data-theme="light"] .report-header {
    background: linear-gradient(135deg, #1e3a5f 0%, #1e293b 100%);
}
.header-top { display: flex; align-items: flex-start; justify-content: space-between; flex-wrap: wrap; gap: 16px; }
.header-logo { display: flex; align-items: center; gap: 12px; }
.header-logo-text { font-size: 26px; font-weight: 800; color: #38bdf8; letter-spacing: -0.5px; }
.header-logo-sub { color: #94a3b8; font-size: 13px; margin-top: 2px; }
.header-meta { display: flex; flex-direction: column; gap: 6px; text-align: right; }
.header-meta-item { font-size: 13px; color: #94a3b8; }
.header-meta-item strong { color: #e2e8f0; }
.header-project {
    margin-top: 20px; padding: 14px 18px;
    background: rgba(255,255,255,0.05); border-radius: var(--radius-sm);
    border: 1px solid rgba(255,255,255,0.08);
    font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
    font-size: 13px; color: #7dd3fc; word-break: break-all;
}
.stack-wrap { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 16px; }
.stack-badge {
    padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 600;
    background: linear-gradient(135deg, #1d4ed8, #3b82f6);
    color: #fff; border: none;
}
/* ── Dashboard ── */
.dashboard {
    display: grid; grid-template-columns: auto 1fr; gap: 28px;
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 32px; margin-bottom: 28px;
    box-shadow: var(--shadow); align-items: center;
}
@media (max-width: 640px) { .dashboard { grid-template-columns: 1fr; } }
.gauge-wrap { display: flex; flex-direction: column; align-items: center; gap: 10px; }
.gauge-svg { filter: drop-shadow(0 0 20px currentColor); opacity: 0.9; }
.verdict-text { font-size: 18px; font-weight: 700; text-align: center; }
.dashboard-right { display: flex; flex-direction: column; gap: 20px; }
.stat-cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }
@media (max-width: 500px) { .stat-cards { grid-template-columns: 1fr; } }
.stat-card {
    padding: 18px; border-radius: var(--radius-sm);
    border: 1px solid; text-align: center;
    transition: transform 0.15s;
}
.stat-card:hover { transform: translateY(-2px); }
.stat-card.critical { background: var(--critical-bg); border-color: var(--critical-border); }
.stat-card.warning { background: var(--warning-bg); border-color: var(--warning-border); }
.stat-card.info { background: var(--info-bg); border-color: var(--info-border); }
.stat-card-num { font-size: 36px; font-weight: 800; line-height: 1; }
.stat-card.critical .stat-card-num { color: var(--critical); }
.stat-card.warning .stat-card-num { color: var(--warning); }
.stat-card.info .stat-card-num { color: var(--info); }
.stat-card-label { font-size: 12px; color: var(--text-muted); margin-top: 4px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
.progress-wrap { width: 100%; }
.progress-label { display: flex; justify-content: space-between; font-size: 13px; color: var(--text-secondary); margin-bottom: 8px; }
.progress-bar-bg {
    width: 100%; height: 10px; background: var(--bg-secondary);
    border-radius: 999px; overflow: hidden; border: 1px solid var(--border);
}
.progress-bar-fill { height: 100%; border-radius: 999px; transition: width 1s ease; }
.elapsed { font-size: 12px; color: var(--text-muted); text-align: right; margin-top: 6px; }
/* ── Filter bar ── */
.filter-bar {
    display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
    margin-bottom: 20px; padding: 14px 18px;
    background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius-sm);
}
.filter-label { font-size: 13px; color: var(--text-muted); font-weight: 600; margin-right: 4px; }
.filter-btn {
    padding: 5px 14px; border-radius: 999px; border: 1px solid var(--border);
    background: transparent; color: var(--text-secondary);
    font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.15s;
}
.filter-btn:hover { background: rgba(255,255,255,0.08); color: var(--text-primary); }
.filter-btn.active { background: #3b82f6; border-color: #3b82f6; color: #fff; }
.filter-btn.active-critical { background: var(--critical); border-color: var(--critical); color: #fff; }
.filter-btn.active-warning { background: var(--warning); border-color: var(--warning); color: #000; }
.filter-btn.active-info { background: var(--info); border-color: var(--info); color: #fff; }
/* ── Section ── */
.section { margin-bottom: 32px; }
.section-header {
    display: flex; align-items: center; gap: 12px;
    padding: 14px 20px; border-radius: var(--radius-sm) var(--radius-sm) 0 0;
    border: 1px solid; border-bottom: none;
    font-size: 15px; font-weight: 700;
}
.section-header.critical { background: var(--critical-bg); border-color: var(--critical-border); color: var(--critical); }
.section-header.warning { background: var(--warning-bg); border-color: var(--warning-border); color: var(--warning); }
.section-header.info { background: var(--info-bg); border-color: var(--info-border); color: var(--info); }
.section-header.ok { background: var(--ok-bg); border-color: var(--ok-border); color: var(--ok); }
.section-count { font-size: 12px; font-weight: 600; padding: 2px 10px; border-radius: 999px; background: rgba(255,255,255,0.1); }
/* ── Finding Card ── */
.finding-card {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: 0; border-top: none;
    transition: background 0.15s;
}
.finding-card:last-child { border-radius: 0 0 var(--radius-sm) var(--radius-sm); }
.finding-summary {
    display: flex; align-items: flex-start; gap: 14px;
    padding: 18px 20px; cursor: pointer; list-style: none;
    user-select: none;
}
.finding-summary::-webkit-details-marker { display: none; }
.finding-summary::marker { display: none; }
.finding-summary:hover { background: var(--bg-card-hover); }
.sev-badge {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 700;
    white-space: nowrap; flex-shrink: 0; margin-top: 2px;
    text-transform: uppercase; letter-spacing: 0.5px;
}
.sev-badge.critical { background: var(--critical-bg); border: 1px solid var(--critical-border); color: var(--critical); }
.sev-badge.warning { background: var(--warning-bg); border: 1px solid var(--warning-border); color: var(--warning); }
.sev-badge.info { background: var(--info-bg); border: 1px solid var(--info-border); color: var(--info); }
.sev-badge.ok { background: var(--ok-bg); border: 1px solid var(--ok-border); color: var(--ok); }
.finding-title { font-weight: 600; font-size: 14px; line-height: 1.4; flex: 1; }
.finding-location {
    font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
    font-size: 12px; color: #7dd3fc; white-space: nowrap; overflow: hidden;
    text-overflow: ellipsis; max-width: 260px;
}
.finding-toggle {
    flex-shrink: 0; font-size: 12px; color: var(--text-muted);
    transition: transform 0.2s; margin-top: 2px;
}
details[open] .finding-toggle { transform: rotate(180deg); }
.finding-body { padding: 0 20px 20px 20px; border-top: 1px solid var(--border); }
.finding-section { margin-top: 16px; }
.finding-section-title {
    font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
    color: var(--text-muted); font-weight: 700; margin-bottom: 8px;
}
.detail-block {
    background: var(--code-bg); border-radius: var(--radius-sm);
    padding: 12px 16px; overflow-x: auto;
    font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
    font-size: 12px; line-height: 1.6; color: var(--code-text);
    border: 1px solid rgba(255,255,255,0.06);
    white-space: pre; max-height: 300px;
}
.explanation-text { font-size: 13px; color: var(--text-secondary); line-height: 1.7; }
.fix-steps {
    background: rgba(34,197,94,0.06); border: 1px solid rgba(34,197,94,0.2);
    border-radius: var(--radius-sm); padding: 14px 16px;
    font-size: 13px; color: var(--text-secondary); line-height: 1.8;
    font-family: inherit; white-space: pre-wrap; word-break: break-word;
}
/* ── OK section ── */
.ok-section {
    background: var(--ok-bg); border: 1px solid var(--ok-border);
    border-radius: var(--radius-sm); padding: 20px 24px;
    margin-bottom: 32px;
}
.ok-section-title { color: var(--ok); font-weight: 700; font-size: 15px; margin-bottom: 12px; }
.ok-item { display: flex; align-items: center; gap: 10px; font-size: 13px; color: var(--text-secondary); margin-bottom: 6px; }
.ok-item:last-child { margin-bottom: 0; }
/* ── LLM Block ── */
.llm-section {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 28px 32px; margin-bottom: 32px;
    box-shadow: var(--shadow);
}
.llm-header {
    display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: 12px; margin-bottom: 18px;
}
.llm-title { font-size: 18px; font-weight: 700; }
.btn-copy {
    display: inline-flex; align-items: center; gap: 8px;
    background: linear-gradient(135deg, #1d4ed8, #3b82f6);
    color: #fff; border: none; padding: 9px 18px; border-radius: var(--radius-sm);
    cursor: pointer; font-size: 13px; font-weight: 600; transition: opacity 0.15s;
}
.btn-copy:hover { opacity: 0.85; }
.btn-copy.copied { background: linear-gradient(135deg, #14532d, #16a34a); }
.llm-textarea {
    width: 100%; min-height: 380px; max-height: 600px;
    background: var(--code-bg); color: var(--code-text);
    border: 1px solid rgba(255,255,255,0.08); border-radius: var(--radius-sm);
    padding: 16px 18px; font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
    font-size: 12px; line-height: 1.7; resize: vertical; outline: none;
    transition: border-color 0.15s;
}
.llm-textarea:focus { border-color: #3b82f6; }
/* ── Footer ── */
.report-footer {
    text-align: center; padding: 24px; font-size: 12px; color: var(--text-muted);
    border-top: 1px solid var(--border);
}
.report-footer a { color: #38bdf8; text-decoration: none; }
.report-footer a:hover { text-decoration: underline; }
/* ── Empty state ── */
.empty-state {
    text-align: center; padding: 48px 24px;
    color: var(--text-muted); font-size: 14px;
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius-sm);
}
.empty-state-icon { font-size: 48px; margin-bottom: 12px; }
/* ── Responsive ── */
@media (max-width: 768px) {
    .main { padding: 20px 16px; }
    .report-header { padding: 24px 20px; }
    .dashboard { padding: 24px; gap: 20px; }
    .header-meta { text-align: left; }
    .header-top { flex-direction: column; }
    .stat-cards { grid-template-columns: repeat(3, 1fr); }
    .llm-section { padding: 20px; }
    .finding-location { max-width: 160px; }
    .section-header { flex-wrap: wrap; }
}
"""


# ─── JS Konstant ──────────────────────────────────────────────────────────────

_REPORT_JS = """\
(function() {
    // Theme toggle
    var themeBtn = document.getElementById('themeBtn');
    var html = document.documentElement;
    var saved = localStorage.getItem('sv-theme') || 'dark';
    html.setAttribute('data-theme', saved);
    updateThemeBtn(saved);
    themeBtn.addEventListener('click', function() {
        var current = html.getAttribute('data-theme');
        var next = current === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        localStorage.setItem('sv-theme', next);
        updateThemeBtn(next);
    });
    function updateThemeBtn(theme) {
        themeBtn.textContent = theme === 'dark' ? '☀️ Lys' : '🌙 Mørk';
    }

    // Copy to clipboard
    var copyBtn = document.getElementById('copyBtn');
    var textarea = document.getElementById('llmTextarea');
    if (copyBtn && textarea) {
        copyBtn.addEventListener('click', function() {
            textarea.select();
            var success = false;
            try {
                if (navigator.clipboard && window.isSecureContext) {
                    navigator.clipboard.writeText(textarea.value).then(function() {
                        showCopied();
                    });
                    return;
                }
                success = document.execCommand('copy');
            } catch(e) {}
            if (success) showCopied();
        });
    }
    function showCopied() {
        if (!copyBtn) return;
        copyBtn.classList.add('copied');
        copyBtn.innerHTML = '✅ Kopieret!';
        setTimeout(function() {
            copyBtn.classList.remove('copied');
            copyBtn.innerHTML = '📋 Kopiér til udklipsholder';
        }, 2000);
    }

    // Filter buttons
    var filterBtns = document.querySelectorAll('.filter-btn');
    var cards = document.querySelectorAll('.finding-card');
    var sections = document.querySelectorAll('.section');
    filterBtns.forEach(function(btn) {
        btn.addEventListener('click', function() {
            filterBtns.forEach(function(b) {
                b.className = 'filter-btn';
            });
            var filter = btn.getAttribute('data-filter');
            btn.classList.add('active' + (filter !== 'all' ? '-' + filter : ''));
            btn.classList.add('active');
            applyFilter(filter);
        });
    });
    function applyFilter(filter) {
        // Show/hide individual cards
        cards.forEach(function(card) {
            var sev = card.getAttribute('data-severity');
            card.style.display = (filter === 'all' || sev === filter) ? '' : 'none';
        });
        // Show/hide section headers
        sections.forEach(function(section) {
            var sev = section.getAttribute('data-section');
            if (filter === 'all') {
                section.style.display = '';
            } else {
                section.style.display = (sev === filter) ? '' : 'none';
            }
        });
    }
    // Set "all" as active on load
    var allBtn = document.querySelector('[data-filter="all"]');
    if (allBtn) allBtn.classList.add('active');

    // Animate progress bars on load
    var fills = document.querySelectorAll('.progress-bar-fill');
    fills.forEach(function(fill) {
        var target = fill.getAttribute('data-width');
        setTimeout(function() { fill.style.width = target + '%'; }, 100);
    });

    // Gauge circle animation
    var gauge = document.getElementById('gaugeProgress');
    if (gauge) {
        var targetDash = gauge.getAttribute('data-target-dashoffset');
        setTimeout(function() {
            gauge.style.transition = 'stroke-dashoffset 1.2s cubic-bezier(0.4, 0, 0.2, 1)';
            gauge.setAttribute('stroke-dashoffset', targetDash);
        }, 200);
    }
})();
"""


# ─── Offentlig API ────────────────────────────────────────────────────────────

def generate_report(
    all_findings: list[dict],
    score: int,
    verdict: str,
    project_path: str,
    stack: list[str],
    elapsed: float,
) -> str:
    """Genererer HTML-rapport og gemmer den. Returnerer absolut sti til rapporten."""
    now = datetime.now()
    report_date_file = now.strftime("%Y-%m-%d_%H%M%S")
    report_date_human = now.strftime("%d. %b %Y kl. %H:%M")

    html_content = _build_html(
        all_findings=all_findings,
        score=score,
        verdict=verdict,
        project_path=project_path,
        stack=stack,
        elapsed=elapsed,
        report_date=report_date_human,
    )

    filename = f"safevibe_rapport_{report_date_file}.html"

    try:
        report_path = os.path.join(project_path, filename)
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
    except OSError:
        report_path = os.path.join(os.getcwd(), filename)
        with open(report_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)

    return report_path


# ─── Interne hjælpefunktioner ─────────────────────────────────────────────────

def _is_env_file(file_path: str) -> bool:
    """Returnerer True hvis filen er en .env-fil (f.eks. .env, .env.local, .env.production)."""
    if not file_path:
        return False
    # Normaliser stiseparatorer og tag kun filnavnet
    normalized = file_path.replace("\\", "/")
    filename = normalized.rsplit("/", 1)[-1]
    return bool(re.search(r'^\.env(\..+)?$', filename))


def _get_fix_guidance(description: str) -> tuple[str, str]:
    """Slå forklaring + løsning op baseret på finding-beskrivelse (case-insensitive)."""
    desc_lower = description.lower()
    for keyword, explanation, fix in FIX_GUIDANCE:
        if keyword.lower() in desc_lower:
            return explanation, fix
    return "", ""


def _severity_label(severity: str) -> str:
    return {"critical": "KRITISK", "warning": "ADVARSEL", "info": "INFO", "ok": "OK"}.get(
        severity, severity.upper()
    )


def _severity_icon(severity: str) -> str:
    return {"critical": "🔴", "warning": "🟡", "info": "🔵", "ok": "🟢"}.get(severity, "⚪")


def _score_color(score: int) -> str:
    if score >= 80:
        return "#38a169"
    elif score >= 50:
        return "#d69e2e"
    elif score >= 25:
        return "#e53e3e"
    return "#742a2a"


def _escape_html(text: str) -> str:
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _nl2br(text: str) -> str:
    """Konverter newlines til <br> og præserver indrykning."""
    if not text:
        return ""
    lines = _escape_html(text).split("\n")
    result = []
    for line in lines:
        stripped = line.lstrip()
        spaces = len(line) - len(stripped)
        result.append("&nbsp;" * (spaces * 2) + stripped)
    return "<br>".join(result)


# ─── HTML Bygge-funktioner ────────────────────────────────────────────────────

def _build_nav_html(
    critical_count: int,
    warning_count: int,
    info_count: int,
    ok_count: int,
) -> str:
    def badge(count: int, cls: str) -> str:
        if count == 0:
            return ""
        return f'<span class="nav-badge {cls}">{count}</span>'

    return (
        '<nav class="nav">'
        '<div class="nav-inner">'
        '<span class="nav-brand">🛡️ Safevibe</span>'
        '<a class="nav-link" href="#dashboard">📊 Dashboard</a>'
        f'<a class="nav-link" href="#critical">🔴 Kritisk {badge(critical_count, "critical")}</a>'
        f'<a class="nav-link" href="#warnings">🟡 Advarsler {badge(warning_count, "warning")}</a>'
        f'<a class="nav-link" href="#info">🔵 Info {badge(info_count, "info")}</a>'
        f'<a class="nav-link" href="#ok">🟢 OK {badge(ok_count, "ok")}</a>'
        '<a class="nav-link" href="#ai-block">🤖 AI Prompt</a>'
        '<div class="nav-right">'
        '<button class="btn-theme" id="themeBtn">☀️ Lys</button>'
        "</div>"
        "</div>"
        "</nav>"
    )


def _build_header_html(
    project_path: str,
    stack: list[str],
    report_date: str,
    elapsed: float,
) -> str:
    project_name = os.path.basename(project_path) or project_path
    stack_badges = "".join(
        f'<span class="stack-badge">{_escape_html(s)}</span>' for s in stack
    ) if stack else '<span class="stack-badge">Ikke detekteret</span>'

    return (
        '<div class="report-header">'
        '<div class="header-top">'
        '<div class="header-logo">'
        '<div>'
        '<div class="header-logo-text">🛡️ Safevibe v2</div>'
        '<div class="header-logo-sub">Sikkerhedsscanner til webprojekter</div>'
        "</div>"
        "</div>"
        '<div class="header-meta">'
        f'<div class="header-meta-item"><strong>Rapport dato:</strong> {_escape_html(report_date)}</div>'
        f'<div class="header-meta-item"><strong>Scannings tid:</strong> {elapsed:.1f}s</div>'
        f'<div class="header-meta-item"><strong>Projekt:</strong> {_escape_html(project_name)}</div>'
        "</div>"
        "</div>"
        f'<div class="header-project">📁 {_escape_html(project_path)}</div>'
        f'<div class="stack-wrap">{stack_badges}</div>'
        "</div>"
    )


def _build_dashboard_html(
    score: int,
    verdict: str,
    critical_count: int,
    warning_count: int,
    info_count: int,
    elapsed: float,
) -> str:
    # SVG gauge
    radius = 70
    circumference = 2 * math.pi * radius
    initial_offset = circumference  # start fully hidden
    target_offset = circumference * (1 - max(0, min(100, score)) / 100)
    sc = _score_color(score)

    gauge_svg = (
        '<svg class="gauge-svg" viewBox="0 0 180 180" width="180" height="180">'
        # Track circle
        f'<circle cx="90" cy="90" r="{radius}" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="14"/>'
        # Progress circle
        f'<circle id="gaugeProgress" cx="90" cy="90" r="{radius}" fill="none"'
        f' stroke="{sc}" stroke-width="14"'
        f' stroke-dasharray="{circumference:.2f}"'
        f' stroke-dashoffset="{initial_offset:.2f}"'
        f' stroke-linecap="round"'
        f' transform="rotate(-90 90 90)"'
        f' data-target-dashoffset="{target_offset:.2f}"/>'
        # Score text
        f'<text x="90" y="84" text-anchor="middle" font-size="38" font-weight="800" fill="{sc}" font-family="-apple-system,sans-serif">{score}</text>'
        '<text x="90" y="108" text-anchor="middle" font-size="14" fill="#94a3b8" font-family="-apple-system,sans-serif">/100</text>'
        "</svg>"
    )

    # Verdict color
    if score >= 80:
        verdict_style = "color: #38a169;"
    elif score >= 50:
        verdict_style = "color: #d69e2e;"
    elif score >= 25:
        verdict_style = "color: #e53e3e;"
    else:
        verdict_style = "color: #742a2a;"

    stat_cards = (
        '<div class="stat-cards">'
        '<div class="stat-card critical">'
        f'<div class="stat-card-num">{critical_count}</div>'
        '<div class="stat-card-label">🔴 Kritiske</div>'
        "</div>"
        '<div class="stat-card warning">'
        f'<div class="stat-card-num">{warning_count}</div>'
        '<div class="stat-card-label">🟡 Advarsler</div>'
        "</div>"
        '<div class="stat-card info">'
        f'<div class="stat-card-num">{info_count}</div>'
        '<div class="stat-card-label">🔵 Info</div>'
        "</div>"
        "</div>"
    )

    progress_bar = (
        '<div class="progress-wrap">'
        '<div class="progress-label">'
        "<span>Vibe Score</span>"
        f"<span>{score}/100</span>"
        "</div>"
        '<div class="progress-bar-bg">'
        f'<div class="progress-bar-fill" style="width:0%;background:{sc};" data-width="{score}"></div>'
        "</div>"
        f'<div class="elapsed">⏱ Scan afsluttet på {elapsed:.1f}s</div>'
        "</div>"
    )

    return (
        '<section id="dashboard">'
        '<div class="dashboard">'
        '<div class="gauge-wrap">'
        + gauge_svg
        + f'<div class="verdict-text" style="{verdict_style}">{_escape_html(verdict)}</div>'
        "</div>"
        '<div class="dashboard-right">'
        + stat_cards
        + progress_bar
        + "</div>"
        "</div>"
        "</section>"
    )


def _build_finding_card_html(finding: dict, index: int) -> str:
    severity = finding.get("severity", "info")
    description = finding.get("description", "")
    detail = finding.get("detail", "")

    # Location
    location_parts = []
    file_path = finding.get("file", "")
    line_num = finding.get("line", "")
    table = finding.get("table", "")
    header = finding.get("header", "")
    env_var = finding.get("env_var", "")
    env_source = finding.get("env_source_file", "")
    source = finding.get("source", "")

    if file_path and line_num:
        location_parts.append(f"{file_path}:{line_num}")
    elif file_path:
        location_parts.append(file_path)
    if table:
        location_parts.append(f"tabel: {table}")
    if header:
        location_parts.append(f"header: {header}")
    if env_var:
        location_parts.append(env_var)
    if env_source and env_source not in location_parts:
        location_parts.append(env_source)
    if source:
        location_parts.append(source)

    location_str = " · ".join(location_parts)

    explanation, fix_steps = _get_fix_guidance(description)

    # ── .env-fil override ─────────────────────────────────────────────────────
    # Hvis fundet stammer fra en .env-fil, erstat den vildledende "eksponeret"-
    # besked med en korrekt forklaring: .env ER det rigtige sted for secrets –
    # problemet opstår *kun* hvis .env er committet til Git.
    display_description = description
    if _is_env_file(file_path):
        desc_lower = description.lower()
        if any(kw in desc_lower for kw in (
            "eksponeret", "token", "api key", "api-nøgle", "nøgle", "secret",
            "password", "adgangskode", "hardcod",
        )):
            display_description = (
                "API-nøgle/hemmelighed fundet i .env-fil (korrekt placering)"
                " — kontrollér at .env er i .gitignore"
            )
        explanation = (
            "Hemmeligheder i .env-filer er korrekt lagret — problemet opstår kun, "
            "hvis .env-filen bliver committet til Git. Angribere kan finde credentials "
            "i Git-historik, selv efter de er fjernet."
        )
        fix_steps = (
            "1. Bekræft at .env er listet i .gitignore.\n"
            "2. Kør `git ls-files --error-unmatch .env` — "
            "hvis kommandoen ikke fejler, er filen tracked i Git.\n"
            "3. Brug aldrig produktions-secrets i .env-filer der committes"
            " — brug en secrets manager."
        )
    # ─────────────────────────────────────────────────────────────────────────

    sev_label = _severity_label(severity)
    sev_icon = _severity_icon(severity)

    # Summary row
    location_html = (
        f'<span class="finding-location">{_escape_html(location_str)}</span>' if location_str else ""
    )

    summary_html = (
        f'<summary class="finding-summary">'
        f'<span class="sev-badge {severity}">{sev_icon} {sev_label}</span>'
        f'<span class="finding-title">{_escape_html(display_description)}</span>'
        + location_html
        + '<span class="finding-toggle">▼</span>'
        f"</summary>"
    )

    # Body content
    body_parts = []

    if detail:
        body_parts.append(
            '<div class="finding-section">'
            '<div class="finding-section-title">📄 Detalje / Kodeudsnit</div>'
            f'<pre class="detail-block">{_escape_html(detail)}</pre>'
            "</div>"
        )

    if location_str:
        body_parts.append(
            '<div class="finding-section">'
            '<div class="finding-section-title">📍 Placering</div>'
            f'<code style="font-size:12px;color:#7dd3fc;font-family:\'SF Mono\',monospace;">{_escape_html(location_str)}</code>'
            "</div>"
        )

    if explanation:
        body_parts.append(
            '<div class="finding-section">'
            '<div class="finding-section-title">❓ Hvorfor er dette et problem?</div>'
            f'<div class="explanation-text">{_escape_html(explanation)}</div>'
            "</div>"
        )

    if fix_steps:
        body_parts.append(
            '<div class="finding-section">'
            '<div class="finding-section-title">🔧 Sådan fikser du det</div>'
            f'<pre class="fix-steps">{_escape_html(fix_steps)}</pre>'
            "</div>"
        )
    elif not explanation:
        body_parts.append(
            '<div class="finding-section">'
            '<div class="finding-section-title">🔧 Anbefaling</div>'
            '<div class="explanation-text">Gennemgå dette fund og vurder den sikkerhedsmæssige påvirkning for dit projekt.</div>'
            "</div>"
        )

    body_html = '<div class="finding-body">' + "".join(body_parts) + "</div>"

    return (
        f'<details class="finding-card" data-severity="{severity}">'
        + summary_html
        + body_html
        + "</details>"
    )


def _build_findings_section_html(
    findings: list[dict],
    severity: str,
    section_id: str,
    title: str,
) -> str:
    if not findings:
        return ""

    cards = "".join(
        _build_finding_card_html(f, i) for i, f in enumerate(findings, 1)
    )

    return (
        f'<div class="section" data-section="{severity}" id="{section_id}">'
        f'<div class="section-header {severity}">'
        f'{_severity_icon(severity)} {_escape_html(title)}'
        f'<span class="section-count">{len(findings)}</span>'
        "</div>"
        + cards
        + "</div>"
    )


def _build_ok_section_html(ok_findings: list[dict]) -> str:
    if not ok_findings:
        return ""
    items = "".join(
        f'<div class="ok-item">🟢 {_escape_html(f.get("description", ""))}</div>'
        for f in ok_findings
    )
    return (
        '<div id="ok">'
        '<div class="ok-section">'
        '<div class="ok-section-title">✅ OK Checks – Alt i orden</div>'
        + items
        + "</div>"
        "</div>"
    )


def _build_filter_bar_html() -> str:
    return (
        '<div class="filter-bar">'
        '<span class="filter-label">Vis:</span>'
        '<button class="filter-btn" data-filter="all">Alle</button>'
        '<button class="filter-btn" data-filter="critical">🔴 Kritisk</button>'
        '<button class="filter-btn" data-filter="warning">🟡 Advarsler</button>'
        '<button class="filter-btn" data-filter="info">🔵 Info</button>'
        "</div>"
    )


def _build_llm_block_html(
    all_findings: list[dict],
    score: int,
    verdict: str,
    project_path: str,
    stack: list[str],
    report_date: str,
) -> str:
    """Byg LLM copy-block sektionen."""
    prompt_text = _build_llm_prompt(all_findings, score, verdict, project_path, stack, report_date)

    return (
        '<section class="llm-section" id="ai-block">'
        '<div class="llm-header">'
        '<div class="llm-title">🤖 Send til AI-assistent</div>'
        '<button class="btn-copy" id="copyBtn">📋 Kopiér til udklipsholder</button>'
        "</div>"
        '<p style="font-size:13px;color:var(--text-secondary);margin-bottom:14px;">'
        "Kopiér denne prompt og indsæt den i ChatGPT, Claude eller en anden AI-assistent for at få hjælp til at løse sikkerhedsproblemerne."
        "</p>"
        f'<textarea class="llm-textarea" id="llmTextarea" readonly>{_escape_html(prompt_text)}</textarea>'
        "</section>"
    )


def _build_llm_prompt(
    all_findings: list[dict],
    score: int,
    verdict: str,
    project_path: str,
    stack: list[str],
    report_date: str,
) -> str:
    """Byg struktureret tekst til LLM copy-block."""
    project_name = os.path.basename(project_path) or project_path
    stack_str = ", ".join(stack) if stack else "Ikke detekteret"

    critical = [f for f in all_findings if f.get("severity") == "critical"]
    warnings = [f for f in all_findings if f.get("severity") == "warning"]
    infos = [f for f in all_findings if f.get("severity") == "info"]

    lines: list[str] = [
        f"# Safevibe Sikkerhedsanalyse - {project_name}",
        f"Scanningstidspunkt: {report_date}",
        f"Score: {score}/100 - {verdict}",
        f"Stack: {stack_str}",
        "",
    ]

    def format_section(title: str, findings: list[dict]) -> None:
        if not findings:
            return
        lines.append(f"## {title} ({len(findings)}):")
        for f in findings:
            desc = f.get("description", "")
            detail = f.get("detail", "")
            file_path = f.get("file", "")
            line_num = f.get("line", "")
            table = f.get("table", "")
            header = f.get("header", "")

            loc = ""
            if file_path and line_num:
                loc = f"{file_path}:{line_num}"
            elif file_path:
                loc = file_path
            elif table:
                loc = f"tabel: {table}"
            elif header:
                loc = f"header: {header}"

            explanation, fix_text = _get_fix_guidance(desc)

            lines.append(f"### {desc}")
            if loc:
                lines.append(f"- Placering: {loc}")
            if detail:
                detail_short = detail[:200] + ("..." if len(detail) > 200 else "")
                lines.append(f"- Detalje: {detail_short}")
            if explanation:
                lines.append(f"- Problem: {explanation}")
            if fix_text:
                lines.append(f"- Fix:\n{fix_text}")
            lines.append("")

    format_section("Kritiske problemer", critical)
    format_section("Advarsler", warnings)
    format_section("Info", infos)

    lines += [
        "---",
        f"Opgave til AI: Gennemgå venligst disse sikkerhedsproblemer og hjælp mig med:",
        "1. Forklaring af hvert problem på dansk med konkrete kodeeksempler",
        "2. Konkrete fix-implementeringer med kode",
        "3. Prioriteringsrækkefølge for rettelserne",
        f"4. Eventuelle yderligere sikkerhedsanbefalinger baseret på stakken ({stack_str})",
    ]

    return "\n".join(lines)


def _build_footer_html(report_date: str) -> str:
    return (
        '<footer class="report-footer">'
        f"Genereret af <strong>Safevibe v2</strong> · {_escape_html(report_date)} · "
        '<a href="https://github.com/safevibe/safevibe" target="_blank" rel="noopener">safevibe</a>'
        "</footer>"
    )


def _build_html(
    all_findings: list[dict],
    score: int,
    verdict: str,
    project_path: str,
    stack: list[str],
    elapsed: float,
    report_date: str,
) -> str:
    """Byg komplet HTML-rapport som string."""
    project_name = _escape_html(os.path.basename(project_path) or project_path)

    critical = [f for f in all_findings if f.get("severity") == "critical"]
    warnings_ = [f for f in all_findings if f.get("severity") == "warning"]
    infos = [f for f in all_findings if f.get("severity") == "info"]
    oks = [f for f in all_findings if f.get("severity") == "ok"]

    critical_count = len(critical)
    warning_count = len(warnings_)
    info_count = len(infos)
    ok_count = len(oks)

    nav_html = _build_nav_html(critical_count, warning_count, info_count, ok_count)
    header_html = _build_header_html(project_path, stack, report_date, elapsed)
    dashboard_html = _build_dashboard_html(score, verdict, critical_count, warning_count, info_count, elapsed)
    filter_bar_html = _build_filter_bar_html()
    critical_html = _build_findings_section_html(critical, "critical", "critical", "Kritiske Sikkerhedsproblemer")
    warnings_html = _build_findings_section_html(warnings_, "warning", "warnings", "Advarsler")
    info_html = _build_findings_section_html(infos, "info", "info", "Informationer")
    ok_html = _build_ok_section_html(oks)

    total_findings = critical_count + warning_count + info_count
    if total_findings == 0:
        findings_content = (
            '<div class="empty-state">'
            '<div class="empty-state-icon">🎉</div>'
            "<strong>Ingen sikkerhedsproblemer fundet!</strong><br>"
            "Dit projekt ser godt ud sikkerhedsmæssigt."
            "</div>"
        )
    else:
        findings_content = filter_bar_html + critical_html + warnings_html + info_html

    llm_html = _build_llm_block_html(
        all_findings, score, verdict, project_path, stack, report_date
    )
    footer_html = _build_footer_html(report_date)

    return (
        "<!DOCTYPE html>\n"
        '<html lang="da" data-theme="dark">\n'
        "<head>\n"
        '<meta charset="UTF-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        f"<title>Safevibe Rapport – {project_name}</title>\n"
        "<style>\n" + _REPORT_CSS + "\n</style>\n"
        "</head>\n"
        "<body>\n"
        + nav_html
        + '\n<main class="main">\n'
        + header_html
        + "\n"
        + dashboard_html
        + "\n"
        + findings_content
        + "\n"
        + ok_html
        + "\n"
        + llm_html
        + "\n"
        + footer_html
        + "\n</main>\n"
        "<script>\n" + _REPORT_JS + "\n</script>\n"
        "</body>\n"
        "</html>"
    )
