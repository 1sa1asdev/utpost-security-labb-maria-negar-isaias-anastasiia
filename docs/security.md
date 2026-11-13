# Säkerhet – Utpost

*Mall (M8). Byt ut exempelraderna mot era egna fynd. Minst tre rader ska ha ett riktigt fynd, en fix i en PR och ett test som var rött före fixen. "Gäller inte oss, för …" är också ett svar – men bara om det är sant. Listan följer OWASP Top 10 (2025).*

**Datum:** 2026-11-13
**Hotbilden i en mening:** ______ (vad är värt att skydda i Utpost, och vem är angriparen? Användarnas turer och bilder, redaktionens guider, och – när vi lanserar – kontona. Angriparen är oftast ett skript, inte en person.)

## Autentiseringen (M8)

- Lösenord: ______ (hur lagras de, med vilket schema? Var i koden?)
- Token: ______ (vad står i den, hur länge gäller den, var ligger den i klienten, vad händer vid omladdning?)
- Skyddade routes: ______ (vilka anrop kräver token, vilka kräver rollen editor, och var sitter kontrollen – i klientens router eller i API:et?)

## OWASP Top 10 – genomgång

| # | Risk | Gäller oss? | Vad vi hittade (fil, endpoint) | Vad vi gjorde (PR) | Kontroll (testet som var rött före fixen, eller curl) |
|---|---|---|---|---|---|
| A01 | Broken Access Control | ja | `PUT /api/guides/:id` saknade token-, roll- och bodykontroll, så vem som helst kunde ändra en guide. A01-testen bevakar också borttagning av andras turer och bilduppladdning. | `requireUser`, `requireRole('editor')`, `guideUpdateSchema` och `idParam` i [guides.ts](../api/src/routes/guides.ts:64): 401 utan token, 403 för medlem, 400 vid ogiltig indata och 404 när guiden saknas. [PR #1](https://github.com/AnastasiaSkachenko/utpost-security-labb-maria-negar-isaias-anastasiia/pull/1). | Test-först i [routes.test.js](../api/src/routes/routes.test.js:117): *PUT /api/guides/:id utan token ger 401* och *en medlem får inte ändra guider (403)* var röda före fixen; testerna för ägarens tur och redaktörens giltiga uppdatering är gröna. |
| A02 | Security Misconfiguration | ja | `app.use(cors())` gav `Access-Control-Allow-Origin: *`; nginx saknade CSP och övriga säkerhetsheaders, `server_tokens` var på och api-imagen körde som root (Trivy DS-0002). | CORS togs bort i [app.js](../api/src/app.js:17) ([PR #1](https://github.com/AnastasiaSkachenko/utpost-security-labb-maria-negar-isaias-anastasiia/pull/1)); CSP med flera headers lades i [security-headers.conf](../client/security-headers.conf:1) i varje nginx-location, `server_tokens off` sattes i [nginx.conf.template](../client/nginx.conf.template:12) och API-processen kör som `node` i [api/Dockerfile](../api/Dockerfile:26) ([PR #3](https://github.com/AnastasiaSkachenko/utpost-security-labb-maria-negar-isaias-anastasiia/pull/3)). | *API:et skickar ingen Access-Control-Allow-Origin* i [routes.test.js](../api/src/routes/routes.test.js:146); [Säkerhet-jobbet](https://github.com/AnastasiaSkachenko/utpost-security-labb-maria-negar-isaias-anastasiia/actions/runs/43408095518/job/131827332543) fick PASS för ZAP 10020, 10021, 10036 och 10038. `.zap/rules.tsv` gör motsvarande fynd merge-blockerande, och `curl -I http://localhost:3001/` ska visa CSP. |
| A03 | Software Supply Chain Failures | ja | `npm ci` visade 22 sårbarheter i hela beroendeträdet (20 moderate, 2 critical), och basimagen `node:22-alpine` hade onödiga npm-verktyg (`pacote`, `sigstore`, `brace-expansion`) kvar i runtime-imagen. | [PR #3](https://github.com/AnastasiaSkachenko/utpost-security-labb-maria-negar-isaias-anastasiia/pull/3) lade till produktionsaudit och Trivy för repo och api-image i [ci.yml](../.github/workflows/ci.yml:94), uppdaterade Drizzle efter `npm audit fix` och tog bort `npm`/`npx` från [api/Dockerfile](../api/Dockerfile:14). `.trivyignore` har ett motiverat undantag för nginx i client-imagen. | I [Säkerhet-jobbet](https://github.com/AnastasiaSkachenko/utpost-security-labb-maria-negar-isaias-anastasiia/actions/runs/43408095518/job/131827332543) gav `npm audit --omit=dev --audit-level=high` 0 sårbarheter; Trivy `fs` (beroenden, hemligheter, Dockerfiles) och Trivy mot api-imagen passerade för HIGH/CRITICAL utan kvarvarande fynd. |
| A04 | Cryptographic Failures | https://github.com/AnastasiaSkachenko/utpost-security-labb-maria-negar-isaias-anastasiia/pull/4 | | | |
| A05 | Injection | | | | |
| A06 | Insecure Design | | | | |
| A07 | Authentication Failures | | | | |
| A08 | Software or Data Integrity Failures | | | | |
| A09 | Security Logging & Alerting Failures | | | | |
| A10 | Mishandling of Exceptional Conditions | | | | |

## Validering av indata

______ (var sitter valideringen, vilka scheman finns, vad händer vid ogiltig indata – svarskoden och formen på svaret?)

## Headers vi sätter (nginx)

Säkerhetsheadrarna definieras i [client/security-headers.conf](../client/security-headers.conf:9) och inkluderas i varje nginx-location: `/`, `/assets/`, `/api/` och `/graphql`.

- `Content-Security-Policy` tillåter bara appens egna skript och resurser. Stilar får använda `'unsafe-inline'` eftersom guideinnehållet rendreras med `v-html`; inline-skript tillåts inte.
- `X-Content-Type-Options: nosniff` hindrar webbläsaren från att gissa en annan innehållstyp.
- `X-Frame-Options: DENY` och CSP-direktivet `frame-ancestors 'none'` stoppar inbäddning i iframe och clickjacking.
- `Referrer-Policy: strict-origin-when-cross-origin` begränsar hur mycket adressinformation som skickas vidare.
- `Permissions-Policy` stänger av kamera, mikrofon och geolokalisering.

`server_tokens off` i [nginx.conf.template](../client/nginx.conf.template:12) döljer nginx-versionen. API- och GraphQL-svar får dessutom `Cache-Control: no-store`, medan hashnamede filer under `/assets/` får cachas länge. Vi sätter ingen CORS-header. HSTS är förberett men avstängt lokalt eftersom utvecklingsservern kör HTTP. `curl -I http://localhost:3001/` ska visa dessa headers genom nginx.

## Skanning i pipelinen

Jobbet [*Säkerhet*](../.github/workflows/ci.yml:94) kör på varje PR och tar ungefär tre minuter; den sista gröna körningen tog 2 min 52 s.

- **`npm audit --omit=dev --audit-level=high`** granskar npm-beroendena som används i produktion. En känd sårbarhet med severity high eller critical ger röd körning.
- **Trivy `fs`** granskar `package-lock.json`, alla filer efter hemligheter och Dockerfiles efter misconfigurations. HIGH/CRITICAL-fynd ger röd körning.
- **Trivy `image`** granskar hela `utpost-api`-imagen, inklusive Alpine-, Node- och npm-paket som inte syns i appens egen lockfil. HIGH/CRITICAL-fynd ger röd körning.
- **ZAP baseline** spindlar den körande appen på `http://localhost:3001` och testar svaren för bland annat saknad CSP, clickjacking-skydd, `nosniff`, läckt serverversion, cacheinställningar och informationsläckage. Regler som står som `FAIL` i `.zap/rules.tsv` stoppar PR:en; `WARN` gör det inte i den här körningen.
- **`docker compose up --build --wait`** är förutsättningen för Trivy mot imagen och ZAP mot den riktiga nginx/API-kedjan. Om en image eller tjänst inte startar blir jobbet också rött.

Undantagen är uttalade och versionshanterade: Trivys motivering för nginx-imagen börjar på rad 3 i [.trivyignore](../.trivyignore:3), medan själva `DS-0002`-undantaget står på rad 5. ZAP:s `FAIL`, `WARN` och `IGNORE` finns i [.zap/rules.tsv](../.zap/rules.tsv:3). En ny hemlighet eller ett nytt HIGH/CRITICAL-fynd ska inte läggas till som undantag utan att först avgöra om det faktiskt gäller oss.

## Kända brister (medvetet kvar)

______ (det ni valt att inte laga än, och varför. Ärlighet ger poäng: en omladdning loggar ut – refresh-token är inte byggt; bytes lämnar inte browsern; …)
