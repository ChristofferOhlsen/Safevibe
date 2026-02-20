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

    # ═══════════════════════════════════════════════════════════════════════════
    # ── UDVIDEDE SIKKERHEDSTJEKS (70+ nye patterns) ──────────────────────────
    # ═══════════════════════════════════════════════════════════════════════════

    # ── NoSQL Injection ───────────────────────────────────────────────────────
    (r"\.find\s*\(\s*\{\s*[^}]*(?:req\.|params\.|query\.|body\.)",
     "NoSQL injection via request object i MongoDB find()",
     "critical", None),

    (r"\.findOne\s*\(\s*\{\s*[^}]*(?:req\.|params\.|query\.|body\.)",
     "NoSQL injection via request object i MongoDB findOne()",
     "critical", None),

    (r"where\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"](?:==|!=|>|<|>=|<=)['\"]\s*,\s*(?:req\.|user|input|params\.|query\.)",
     "NoSQL injection i Firestore where() query med user input",
     "critical", None),

    (r"\.updateOne\s*\(\s*\{\s*[^}]*(?:req\.|params\.|query\.|body\.)",
     "NoSQL injection i MongoDB updateOne() med request data",
     "critical", None),

    (r"\$where\s*:\s*['\"][^'\"]*\$\{",
     "MongoDB $where operator med template literal – farlig query injection",
     "critical", None),

    # ── Server-Side Template Injection (SSTI) ─────────────────────────────────
    (r"\.render\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
     "SSTI: Template render() med user input – potentiel RCE",
     "critical", None),

    (r"ejs\.render\s*\([^)]*\$\{",
     "EJS template injection – user input i template string",
     "critical", None),

    (r"pug\.compile\s*\([^)]*(?:req\.|params\.|query\.)",
     "Pug template injection med user input",
     "critical", None),

    (r"Handlebars\.compile\s*\([^)]*(?:req\.|params\.|query\.)",
     "Handlebars template injection med user input",
     "critical", None),

    (r"Jinja2\.from_string\s*\([^)]*(?:request\.|user|input)",
     "Jinja2 template injection (Python) – potentiel RCE",
     "critical", None),

    (r"Template\s*\([^)]*(?:request\.|user|input)",
     "Python string.Template med user input – SSTI risiko",
     "critical", None),

    # ── Insecure Deserialization ──────────────────────────────────────────────
    (r"pickle\.loads\s*\(",
     "pickle.loads() – Insecure deserialization (Python RCE)",
     "critical", None),

    (r"pickle\.load\s*\(",
     "pickle.load() – Insecure deserialization (Python RCE)",
     "critical", None),

    (r"unserialize\s*\([^)]*\$_",
     "PHP unserialize() med user input – RCE risiko",
     "critical", None),

    (r"yaml\.load\s*\([^)]*(?:req|request|user|input)",
     "YAML unsafe load() med user input – deserialization RCE",
     "critical", None),

    (r"yaml\.unsafe_load\s*\(",
     "yaml.unsafe_load() brugt – potentiel RCE",
     "critical", None),

    (r"JsonConvert\.DeserializeObject\s*<[^>]+>\s*\([^)]*(?:Request|User|Input)",
     "C# JSON deserialization med user input – TypeNameHandling risiko",
     "warning", None),

    # ── XML External Entity (XXE) ─────────────────────────────────────────────
    (r"new\s+DOMParser\s*\(\s*\{\s*[^}]*resolveExternalEntities\s*:\s*true",
     "DOMParser med resolveExternalEntities: true – XXE sårbar",
     "critical", None),

    (r"xml2js\.parseString\s*\([^)]*\{\s*[^}]*xmlExternal\s*:\s*true",
     "xml2js med xmlExternal: true – XXE risiko",
     "critical", None),

    (r"lxml\.etree\.parse\s*\([^)]*resolve_entities\s*=\s*True",
     "lxml.etree.parse med resolve_entities=True – XXE sårbar",
     "critical", None),

    (r"DocumentBuilder(?:Factory)?[^;]*setFeature\s*\([^)]*FEATURE_SECURE_PROCESSING[^)]*false",
     "Java XML parser uden secure processing – XXE risiko",
     "critical", None),

    (r"XmlReader\.Create\s*\([^)]*DtdProcessing\s*=\s*DtdProcessing\.Parse",
     "C# XmlReader med DTD processing – XXE sårbar",
     "critical", None),

    # ── Path Manipulation & Traversal ─────────────────────────────────────────
    (r"path\.join\s*\([^)]*(?:req\.|params\.|query\.|body\.)[^)]*\)",
     "path.join() med request parameter – mulig path traversal hvis ikke valideret",
     "warning", None),

    (r"path\.resolve\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
     "path.resolve() med request parameter – path manipulation risiko",
     "warning", None),

    (r"sendFile\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
     "sendFile() med request parameter – path traversal risiko",
     "critical", None),

    (r"res\.download\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
     "res.download() med request parameter – path traversal risiko",
     "critical", None),

    (r"fs\.(?:readFile|writeFile|unlink|rmdir)\s*\([^)]*(?:req\.|params\.|query\.)",
     "fs operationer med request parameter uden validation",
     "critical", None),

    (r"open\s*\([^)]*(?:request\.|user|input|params|query)",
     "Python open() med user input – path traversal risiko",
     "critical", None),

    (r"File\s*\([^)]*(?:request\.|Request\.|user|input)",
     "File operationer med user input uden validation",
     "warning", None),

    # ── CSRF Token mangler ────────────────────────────────────────────────────
    (r"(?:app|router)\.post\s*\(['\"][^'\"]*(?:/api/)?(?:delete|remove|transfer|payment|withdraw|admin)[^'\"]*['\"]",
     "State-changing POST endpoint – verificer CSRF protection (csrf-token, SameSite cookie)",
     "warning", None),

    (r"(?:app|router)\.delete\s*\(['\"]",
     "DELETE endpoint – verificer CSRF/auth protection",
     "warning", None),

    (r"(?:app|router)\.put\s*\(['\"][^'\"]*(?:update|edit|modify)[^'\"]*['\"]",
     "State-changing PUT endpoint – verificer CSRF protection",
     "warning", None),

    # ── Mass Assignment ───────────────────────────────────────────────────────
    (r"(?:User|Account|Admin)\.create\s*\(\s*req\.body\s*\)",
     "Mass assignment – req.body direkte til model.create() (kan sætte role=admin)",
     "critical", None),

    (r"(?:User|Model)\.update\s*\(\s*req\.body\s*\)",
     "Mass assignment – req.body direkte til model.update()",
     "critical", None),

    (r"new\s+(?:User|Account|Model)\s*\(\s*req\.body\s*\)",
     "Mass assignment via constructor med req.body",
     "warning", None),

    (r"Object\.assign\s*\([^,]+,\s*req\.body\s*\)",
     "Object.assign med req.body – mass assignment + prototype pollution",
     "critical", None),

    (r"\.save\s*\(\s*\{\s*[^}]*req\.body[^}]*\}\s*\)",
     "Mongoose save() med req.body – mass assignment risiko",
     "warning", None),

    # ── Weak Session Management ──────────────────────────────────────────────
    (r"session\s*:\s*\{[^}]*secure\s*:\s*false",
     "Session cookie secure: false – sendes over ukrypteret HTTP",
     "critical", None),

    (r"cookie\s*:\s*\{[^}]*httpOnly\s*:\s*false",
     "Cookie httpOnly: false – sårbar over for XSS stjæler cookies",
     "critical", None),

    (r"sameSite\s*:\s*['\"]none['\"]",
     "sameSite: 'none' – tillader cross-site requests (CSRF risiko)",
     "warning", None),

    (r"session\s*:\s*\{[^}]*cookie\s*:\s*\{[^}]*maxAge\s*:\s*(?:[1-9]\d{9,}|\d{11,})",
     "Session maxAge over 1 år – ekstremt lang session-levetid",
     "warning", None),

    (r"express-session[^}]*secret\s*:\s*['\"][^'\"]{1,7}['\"]",
     "express-session secret under 8 tegn – for svag",
     "warning", None),

    # ── Regular Expression DoS (ReDoS) ────────────────────────────────────────
    (r"new\s+RegExp\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
     "RegExp constructor med user input – ReDoS risiko",
     "critical", None),

    (r"/\([a-zA-Z]+\)\+[^/]*/.test\s*\(",
     "Potentiel ReDoS pattern: (x)+ – catastrophic backtracking",
     "warning", None),

    (r"/\([^)]*\|[^)]*\)\*[^/]*/.test\s*\(",
     "Potentiel ReDoS pattern: (a|b)* – catastrophic backtracking",
     "warning", None),

    (r"re\.compile\s*\([^)]*(?:request\.|user|input)",
     "Python re.compile med user input – ReDoS risiko",
     "warning", None),

    # ── HTTP Response Splitting / Header Injection ────────────────────────────
    (r"res\.setHeader\s*\([^)]*(?:req\.|params\.|query\.|body\.)",
     "res.setHeader() med user input – HTTP response splitting risiko",
     "critical", None),

    (r"res\.writeHead\s*\([^)]*\{[^}]*(?:req\.|params\.|query\.)",
     "res.writeHead() med user-controlled headers – header injection",
     "critical", None),

    (r"response\.headers\[[^\]]*\]\s*=\s*(?:request\.|user|input)",
     "HTTP header sat til user input – header injection risiko",
     "critical", None),

    (r"HttpResponse\s*\([^)]*headers\s*=\s*\{[^}]*(?:request\.|user)",
     "Django HttpResponse med user-controlled headers",
     "critical", None),

    # ── Timing Attacks ────────────────────────────────────────────────────────
    (r"(?:password|token|secret|key|hash)\s*(?:===?|!==?)\s*(?:stored|expected|correct)",
     "Timing attack: string comparison på secrets – brug crypto.timingSafeEqual()",
     "warning", None),

    (r"if\s*\([^)]*(?:password|token)\s*==\s*",
     "Timing attack: == comparison på password/token",
     "warning", None),

    (r"hmac\.compare\s*\(\s*(?:str|String)",
     "HMAC comparison skal bruge timingSafeEqual, ikke string compare",
     "warning", None),

    # ── GraphQL Security ──────────────────────────────────────────────────────
    (r"introspection\s*:\s*true(?![^{]*NODE_ENV)",
     "GraphQL introspection aktiveret – deaktiver i produktion",
     "warning", None),

    (r"graphqlHTTP\s*\(\s*\{[^}]*graphiql\s*:\s*true",
     "GraphiQL UI aktiveret – deaktiver i produktion",
     "warning", None),

    (r"ApolloServer\s*\(\s*\{[^}]*playground\s*:\s*true",
     "GraphQL Playground aktiveret – deaktiver i produktion",
     "info", None),

    (r"(?:query|mutation)\s+\{[^}]*\{[^}]*\{[^}]*\{[^}]*\{",
     "Dybt nested GraphQL query – potentiel depth attack (brug depth limiting)",
     "warning", None),

    # ── File Upload Vulnerabilities ───────────────────────────────────────────
    (r"multer\s*\(\s*\{[^}]*dest\s*:\s*['\"]\.?/?public",
     "File upload til public folder – kan uploade executables",
     "critical", None),

    (r"upload\.(?:single|array|fields)\s*\([^)]*\)(?![^;]*fileFilter)",
     "File upload uden fileFilter – manglende filetype validation",
     "warning", None),

    (r"\.save\s*\([^)]*(?:req\.files|uploadedFile)(?![^;]*(?:mimetype|contentType))",
     "File save uden mimetype check – kan uploade farlige filtyper",
     "warning", None),

    (r"move_uploaded_file\s*\([^)]*\$_FILES",
     "PHP file upload – verificer mime type og destination",
     "warning", None),

    (r"request\.files\[[^\]]+\]\.save\s*\(",
     "Flask file upload – tjek allowed extensions og mime type",
     "warning", None),

    # ── Information Disclosure ────────────────────────────────────────────────
    (r"app\.use\s*\(\s*errorHandler\s*\(\s*\{[^}]*showStack\s*:\s*true",
     "Error handler med showStack: true – læk stack traces til klient",
     "critical", None),

    (r"app\.set\s*\(\s*['\"]env['\"],\s*['\"]development['\"]",
     "app.set('env', 'development') hardcodet – brug process.env.NODE_ENV",
     "warning", None),

    (r"DEBUG\s*=\s*True(?![^#]*#.*test)",
     "Django DEBUG = True – deaktiver i produktion",
     "critical", None),

    (r"\.catch\s*\([^)]*=>\s*\{[^}]*res\.(?:send|json)\s*\([^)]*err(?:or)?\.stack",
     "Error stack trace sendt til klient i catch block",
     "critical", None),

    (r"console\.error\s*\([^)]*\.stack\s*\)",
     "Error stack logged – kan lække i produktion hvis logs er eksponeret",
     "info", None),

    (r"throw\s+new\s+Error\s*\([^)]*(?:password|token|secret|key)",
     "Sensitiv data i Error message – kan logges/eksponeres",
     "warning", None),

    # ── Clickjacking / Frame Protection ───────────────────────────────────────
    (r"helmet\s*\(\s*\{[^}]*frameguard\s*:\s*false",
     "Helmet frameguard deaktiveret – clickjacking risiko",
     "warning", None),

    (r"X-Frame-Options['\"]?\s*:\s*['\"]ALLOW",
     "X-Frame-Options sat til ALLOW – clickjacking risiko",
     "warning", None),

    (r"frame-ancestors\s+[*']",
     "CSP frame-ancestors wildcard – clickjacking risiko",
     "warning", None),

    # ── Next.js Specific ──────────────────────────────────────────────────────
    (r"getServerSideProps[^{]*\{[^}]*query[^}]*\}[^{]*\{[^}]*fetch\s*\([^)]*query\.",
     "Next.js SSRF: fetch() i getServerSideProps med query parameter",
     "critical", "Next.js"),

    (r"getServerSideProps[^{]*\{[^}]*params[^}]*\}[^{]*\{[^}]*import\s*\([^)]*params\.",
     "Next.js dynamic import med params – code injection risiko",
     "critical", "Next.js"),

    (r"export\s+async\s+function\s+GET\s*\([^)]*request[^)]*\)[^{]*\{(?![^}]*auth|[^}]*session)",
     "Next.js API route GET uden auth check (App Router)",
     "info", "Next.js"),

    (r"export\s+async\s+function\s+POST\s*\([^)]*request[^)]*\)[^{]*\{(?![^}]*auth|[^}]*session)",
     "Next.js API route POST uden auth check (App Router)",
     "warning", "Next.js"),

    # ── React Native Specific ─────────────────────────────────────────────────
    (r"<WebView[^>]*source\s*=\s*\{\{[^}]*uri\s*:\s*(?:props\.|route\.|navigation\.)",
     "React Native WebView med dynamic URI – open redirect/XSS risiko",
     "critical", "React Native"),

    (r"Linking\.openURL\s*\([^)]*(?:props\.|route\.|navigation\.)",
     "React Native Linking.openURL med dynamic URL – open redirect",
     "warning", "React Native"),

    (r"Platform\.OS\s*===\s*['\"]android['\"]&&[^;]*allowFileAccess",
     "React Native WebView allowFileAccess på Android – file access risiko",
     "warning", "React Native"),

    # ── Vue.js Specific ───────────────────────────────────────────────────────
    (r"v-html\s*=\s*['\"](?!static)[^'\"]*\$",
     "Vue v-html med dynamic data – XSS risiko hvis ikke sanitized",
     "critical", "Vue"),

    (r"\$options\.template\s*=",
     "Vue $options.template manipulation – template injection",
     "critical", "Vue"),

    (r"Vue\.compile\s*\([^)]*(?:props\.|user|input)",
     "Vue.compile() med user input – template injection",
     "critical", "Vue"),

    # ── Svelte Specific ───────────────────────────────────────────────────────
    (r"\{@html\s+(?!sanitize)[^\}]*\}",
     "Svelte {@html} uden sanitization – XSS risiko",
     "critical", "Svelte"),

    (r"@html\s+(?:props\.|$props\.|\$)",
     "Svelte {@html} med dynamic props – XSS hvis ikke sanitized",
     "critical", "Svelte"),

    # ── Python/Django Specific ────────────────────────────────────────────────
    (r"exec\s*\([^)]*(?:request\.|user|input)",
     "Python exec() med user input – arbitrary code execution",
     "critical", "Django"),

    (r"os\.system\s*\([^)]*(?:request\.|user|input|f['\"])",
     "os.system() med user input – command injection",
     "critical", None),

    (r"subprocess\.(?:call|run|Popen)\s*\([^)]*(?:request\.|user|input|f['\"])(?![^)]*shell\s*=\s*False)",
     "subprocess med user input og mulig shell=True – command injection",
     "critical", None),

    (r"\.raw\s*\([^)]*(?:request\.|user|input|f['\"]|%s)",
     "Django raw SQL query med user input – SQL injection",
     "critical", "Django"),

    (r"\.extra\s*\(\s*where\s*=\s*\[[^]]*(?:request\.|user|input|%)",
     "Django .extra() med user input i where – SQL injection",
     "critical", "Django"),

    (r"cursor\.execute\s*\([^)]*(?:%s|%d|f['\"])",
     "Python DB cursor.execute med string formatting – SQL injection",
     "critical", None),

    # ── Security Headers Mangler ──────────────────────────────────────────────
    (r"app\.use\s*\(\s*helmet\s*\(\s*\{[^}]*contentSecurityPolicy\s*:\s*false",
     "Helmet CSP deaktiveret – XSS beskyttelse fjernet",
     "warning", None),

    (r"app\.use\s*\(\s*helmet\s*\(\s*\{[^}]*hsts\s*:\s*false",
     "Helmet HSTS deaktiveret – mangler HTTPS enforcement",
     "warning", None),

    # ── Ruby/Rails Specific ───────────────────────────────────────────────────
    (r"eval\s*\([^)]*params\[",
     "Ruby eval() med params – code injection",
     "critical", None),

    (r"send\s*\([^)]*params\[",
     "Ruby send() med params – method injection",
     "critical", None),

    (r"constantize[^;]*params",
     "Rails constantize med params – code injection via constant resolution",
     "critical", None),

    (r"where\s*\([^)]*params\[(?![^)]*sanitize)",
     "Rails where() med usanitized params – SQL injection risiko",
     "warning", None),

    # ═══════════════════════════════════════════════════════════════════════════
    # ── OWASP TOP 10 2025 + API SECURITY 2023 CHECKS ─────────────────────────
    # ═══════════════════════════════════════════════════════════════════════════

    # ── LLM / AI Prompt Injection (OWASP LLM Top 10 2025 – LLM01) ────────────
    (r"openai\.chat\.completions\.create\s*\([^)]*(?:req\.|params\.|query\.|body\.|user|input)",
     "LLM Prompt Injection: OpenAI med user input – mangler input sanitering",
     "critical", None),

    (r"anthropic\.messages\.create\s*\([^)]*(?:req\.|params\.|query\.|body\.|user|input)",
     "LLM Prompt Injection: Anthropic/Claude med user input – mangler input sanitering",
     "critical", None),

    (r"(?:LLMChain|ConversationChain|load_qa_chain).*(?:run|call)\s*\([^)]*(?:req\.|user|input)",
     "LLM Prompt Injection: Langchain chain.run() med user input",
     "critical", None),

    (r"openai\.[^.]+\.\w+\s*\(\s*\{[^}]*messages\s*:\s*\[[^\]]*(?:req\.|user|input|params\.)",
     "LLM Prompt Injection: AI messages-array indeholder user input uden sanitering",
     "critical", None),

    (r"(?:system|user|assistant)\s*:\s*['\"`][^'\"`,]*\$\{[^}]*(?:user|input|req|query)",
     "LLM Prompt Injection: Direkte string interpolation i AI prompt",
     "critical", None),

    (r"prompt\s*[:=]\s*['\"`][^'\"`,]*\$\{[^}]*(?:user|input|req|query)",
     "LLM Prompt Injection: User input injiceret i AI prompt-string",
     "critical", None),

    # ── Insecure Output Handling (OWASP LLM02) ────────────────────────────────
    (r"(?:res\.send|res\.json|innerHTML)\s*\([^)]*(?:completion|response|generated|llm|ai)(?:\.(?:content|text|message|output))?",
     "LLM Insecure Output: AI-genereret svar sendes direkte til DOM/klient uden sanitering",
     "warning", None),

    # ── Sensitive Data i AI Prompts (OWASP LLM06) ─────────────────────────────
    (r"(?:messages|prompt|content)\s*:\s*.*(?:password|secret|api_key|token|ssn|credit.card)",
     "LLM Sensitive Data: Sensitiv data sendt i AI prompt",
     "critical", None),

    # ── BOLA / IDOR (OWASP API1:2023) ─────────────────────────────────────────
    (r"\.findById\s*\(\s*req\.params\.\w+\s*\)(?![^;]*userId|[^;]*user\.id|[^;]*where)",
     "BOLA/IDOR: findById() med req.params uden ejerskabs-tjek – Broken Object Level Auth",
     "critical", None),

    (r"\.findOne\s*\(\s*\{\s*_?id\s*:\s*req\.params\.\w+\s*\}(?![^}]*user)",
     "BOLA/IDOR: findOne({id: req.params}) uden user-scope – IDOR risiko",
     "critical", None),

    (r"\.eq\s*\(['\"]id['\"],\s*(?:req\.params\.|params\.|query\.)\w+\s*\)(?![^;]*eq[^;]*user)",
     "BOLA/IDOR: Supabase .eq('id', params.id) uden user-scope filter – IDOR risiko",
     "critical", None),

    (r"GET\s+['\"][^'\"]*/:id['\"].*(?:\n[^\n]*){0,5}(?!.*(?:userId|user_id|owner|req\.user))",
     "BOLA/IDOR: GET /:id endpoint – verificer at ejerskab tjekkes",
     "warning", None),

    (r"db\.\w+\s*\.\s*select\s*\(\s*['\*'\"]['\"]?\s*\)(?![^;]*userId|[^;]*user_id|[^;]*eq)",
     "BOLA/IDOR: Supabase select(*) uden user-scope – potentiel data eksponering",
     "warning", None),

    # ── Broken Function Level Authorization (OWASP API5:2023) ─────────────────
    (r"(?:app|router)\.(?:get|post|put|delete|patch)\s*\(['\"][^'\"]*(?:admin|internal|management|superuser|root)[^'\"]*['\"](?![^{]*(?:isAdmin|requireAdmin|adminOnly|checkRole|authorize|authenticate))",
     "Broken Function Level Auth: Admin/intern endpoint uden synlig rolle-tjek",
     "critical", None),

    (r"(?:app|router)\.delete\s*\(['\"][^'\"]*(?:user|account|data|record)[^'\"]*['\"](?![^{]*(?:auth|admin|role|authorize))",
     "Broken Function Level Auth: DELETE endpoint på brugerdata uden auth-tjek",
     "critical", None),

    # ── Log Injection (OWASP A09:2021) ────────────────────────────────────────
    (r"(?:logger|log)\.\w+\s*\([^)]*(?:req\.|params\.|query\.|body\.)\w+(?!\s*\|\s*sanitize)",
     "Log Injection: User input logges direkte – kan injecte falske log entries",
     "warning", None),

    (r"console\.(?:log|info|warn|error)\s*\([^)]*(?:req\.body|req\.query|req\.params|params\.\w|query\.\w)",
     "Log Injection: Request data logges direkte – log injection + data lækage",
     "warning", None),

    (r"(?:winston|bunyan|pino|morgan)\.[^(]+\([^)]*\$\{[^}]*(?:req\.|user|input)",
     "Log Injection: Logger med template literal fra user input",
     "warning", None),

    (r"logging\.(?:info|warning|error|debug)\s*\([^)]*(?:request\.|user|input)",
     "Log Injection: Python logging med user input – kan injecte falske log entries",
     "warning", None),

    # ── Race Conditions / TOCTOU (OWASP A04:2021 Insecure Design) ─────────────
    (r"(?:const|let|var)\s+\w+\s*=\s*await\s+.*balance.*\n[^;]*if\s*\([^)]*\w+\s*[><=]+[^)]*\)\s*\{[^}]*await[^}]*(?:withdraw|transfer|deduct|charge)",
     "Race Condition: Balance check → withdraw pattern – TOCTOU sårbarhed",
     "critical", None),

    (r"(?:const|let|var)\s+\w+\s*=\s*await\s+\w+\.(?:count|findAll)\s*\(.*\n(?:[^\n]*\n){0,3}[^\n]*await[^\n]*(?:create|insert|save)",
     "Race Condition: Count check → create pattern – mulig race condition",
     "warning", None),

    # ── JWT Advanced Security (OWASP A02:2025) ────────────────────────────────
    (r"jwt\.verify\s*\([^,]+,\s*(?:function|async|\([^)]*\)\s*=>)[^{]*\{[^}]*(?:kid|jku|x5u)[^}]*header",
     "JWT Kid/jku: Dynamisk key lookup via JWT header – kid injection risiko",
     "critical", None),

    (r"algorithms\s*:\s*\[[^\]]*(?:['\"]RS256['\"]|['\"]HS256['\"])[^\]]*\]",
     "JWT algorithms whitelist – verificer at 'none' er ekskluderet",
     "info", None),

    (r"jwt\.decode\s*\([^,]+(?!\s*,\s*\{[^}]*complete)(?!\s*,\s*['\"][A-Za-z0-9])",
     "JWT decode() uden verify – token verificeres IKKE (brug jwt.verify())",
     "critical", None),

    # ── Resource Exhaustion / API Rate (OWASP API4:2023) ──────────────────────
    (r"\.find\s*\(\s*\{[^}]*\}\s*\)(?![^;]*(?:limit|skip|lean|select|maxTime))",
     "Resource Exhaustion: MongoDB find() uden limit – kan returnere alle records",
     "warning", None),

    (r"\.findAll\s*\(\s*\{[^}]*where[^}]*\}(?![^)]*limit)",
     "Resource Exhaustion: Sequelize findAll() uden limit – kan hente alle records",
     "warning", None),

    (r"SELECT\s+\*\s+FROM\s+\w+(?![^;]*(?:LIMIT|WHERE))",
     "Resource Exhaustion: SELECT * uden LIMIT/WHERE – kan hente al data",
     "warning", None),

    (r"db\.from\s*\(['\"][^'\"]+['\"]\s*\)\.select\s*\(\s*['\*'\"]\s*\)(?![^;]*limit\s*\()",
     "Resource Exhaustion: Supabase select(*) uden .limit() – potentiel data dump",
     "warning", None),

    # ── Supply Chain Security (OWASP A06:2025) ────────────────────────────────
    (r"require\s*\(\s*['\"][^./][^'\"]*['\"\s*\])\s*(?:\/\/[^\n]*internal|\/\/[^\n]*private)",
     "Supply Chain: intern npm-pakke importeret – verificer registry og scope",
     "info", None),

    (r"\"scripts\"\s*:[^}]*\"postinstall\"\s*:\s*\"(?!node |npm |yarn )",
     "Supply Chain: postinstall script med custom kommando – verificer indhold",
     "warning", None),

    # ── Unsafe Consumption of External APIs (OWASP API10:2023) ────────────────
    (r"fetch\s*\([^)]*(?:https?://[^/'\")]+)[^)]*\)(?![^;]*(?:timeout|AbortController|signal))",
     "Unsafe API Consumption: fetch() uden timeout – kan hænge indefinitely (DoS)",
     "warning", None),

    (r"axios\.(?:get|post|put|delete)\s*\([^)]*(?:https?://)[^)]*\)(?![^;]*timeout)",
     "Unsafe API Consumption: axios request uden timeout – kan hænge (DoS)",
     "warning", None),

    (r"(?:const|let|var)\s+\w+\s*=\s*await\s+fetch\s*\([^)]*\)[^;]*;\s*(?:const|let|var)\s+\w+\s*=\s*await\s+\w+\.json\s*\(\s*\)(?![^;]*(?:schema|validate|zod|joi|yup))",
     "Unsafe API Consumption: Eksternt API-svar bruges uden validering/schema check",
     "warning", None),

    # ── Prototype Pollution via Object Spread (udvidelse) ─────────────────────
    (r"\.\.\.\s*(?:req\.body|req\.query|req\.params)",
     "Prototype Pollution: Object spread med req data – mass assignment risiko",
     "warning", None),

    (r"deepmerge\s*\([^,]+,\s*(?:req\.|JSON\.parse)",
     "Prototype Pollution: deepmerge med user input – prototype pollution risiko",
     "critical", None),

    # ── NOTE: process.env.VAR_NAME og import.meta.env.VAR_NAME er KORREKT brug ──
    # Variabel-*navne* fra .env må og skal fremgå i kildekode (det er hele pointen).
    # scan_hardcoded_env_values() håndterer det farlige: at selve VÆRDIEN er hardcodet.
    # Vi scanner derfor IKKE for process.env / import.meta.env referencer her.
]

SCAN_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".vue", ".svelte", ".py", ".php",
    ".rb",    # Ruby/Rails
    ".go",    # Go
    ".java",  # Java/Spring
    ".cs",    # C#/.NET
    ".rs",    # Rust
    ".kt",    # Kotlin
    ".scala", # Scala
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
