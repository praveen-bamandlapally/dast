# DAST API Scan Runner (OWASP ZAP + OpenAPI)

This project runs targeted API DAST scans from an OpenAPI spec using OWASP ZAP, stores scan status/results in SQLite, and generates HTML/CSV reports.

## What This Repo Contains

- `server.js`: Sample vulnerable API app (runs on port `3000` by default)
- `setup-zap-db.js`: Creates required SQLite schema (`zap_test_status`)
- `zap-openapi-policy-scan.js`: Runs policy-based API scans via ZAP
- `report.js`: Builds HTML + CSV reports from DB data
- `openapi.json`: API spec used for endpoint extraction

## Prerequisites

- Node.js 18+ (Node 20+ recommended)
- OWASP ZAP running in daemon mode and reachable by API
- Your target API running (for default sample app: `http://localhost:3000`)

## 1) Install Dependencies

```powershell
npm install
```

## 2) Start the Target API

Use the included demo API:

```powershell
node server.js
```

API default base URL:

- `http://localhost:3000`

## 3) Start ZAP Server (Daemon)

### Option A: Docker (quick start)

```powershell
docker run --rm -u zap -p 8090:8090 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true
```

### Option B: Local ZAP installation

Run ZAP in daemon mode and expose API on `8090`.

Example startup options should include equivalents of:

- `-daemon`
- `-host 127.0.0.1`
- `-port 8090`
- API key enabled or disabled per your security preference

## 4) Setup the Scan Database

```powershell
npm run setup:db
```

Equivalent direct command:

```powershell
node setup-zap-db.js --db dast.db
```

## 5) Run ZAP Scan (base-url + OpenAPI + policy)

### Recommended explicit command

```powershell
node zap-openapi-policy-scan.js --spec openapi.json --base-url http://localhost:3000 --policy API
```

### Using npm script

```powershell
npm run scan:api
```

### Important required flags

- `--spec <path>`: OpenAPI/Swagger file path
- `--base-url <url>`: Running API base URL
- `--policy <name>`: Existing ZAP active scan policy name

If your policy name is different, replace `API` with your policy.

## 6) Create Reports

Generate HTML + CSV outputs from the DB:

```powershell
node report.js
```

Default outputs:

- `zap-db-report.html`
- `zap-db-report.csv`
- `zap-db-coverage.csv`

You can customize paths:

```powershell
node report.js --db dast.db --out zap-db-report.html --csv zap-db-report.csv --coverage-csv zap-db-coverage.csv --strategy zap --policy API
```

## Typical End-to-End Flow

In separate terminals:

1. Start API:

```powershell
node server.js
```

2. Start ZAP daemon.

3. Initialize DB:

```powershell
npm run setup:db
```

4. Run scan:

```powershell
node zap-openapi-policy-scan.js --spec openapi.json --base-url http://localhost:3000 --policy API
```

5. Generate reports:

```powershell
node report.js
```

## Useful Scan Options

`zap-openapi-policy-scan.js` supports:

- `--redo-failed`: Re-run failed endpoints
- `--injectable <mask>`: `query,post,path,headers,cookie,all` (default: `query,post`)
- `--header <name:value>`: Extra request header sent to the target on every request (repeatable)
- `--cookie <name=value>`: Extra request cookie sent to the target on every request (repeatable)
- `--scan-log <path>`: Log file for 401/500 error responses (default: `scanlogs.txt`)
- `--alert-log <path>`: Log file for the request/response behind each alert (default: `calls_alerts.txt`)
- `--alert-risk <list>`: Severities logged to the alert log: `high,medium,low,info,all` (default: `high,medium`)
- `--db <path>`: DB file path
- `--strategy <name>`: Strategy label saved in DB
- `--zap-host <host>` / `--zap-port <port>`
- `--api-key <key>`

Example:

```powershell
node zap-openapi-policy-scan.js --spec openapi.json --base-url http://localhost:3000 --policy API --redo-failed --injectable all --zap-host 127.0.0.1 --zap-port 8090
```

## Authentication: Custom Headers & Cookies

Attach an auth header or cookie to every request ZAP sends to the target (useful
for endpoints behind a token/session). Both flags are repeatable, and cookies are
combined into a single `Cookie` header.

```powershell
node zap-openapi-policy-scan.js --spec openapi.json --base-url http://localhost:3000 --policy API `
  --header "Authorization: Bearer <token>" `
  --header "X-API-Key: secret123" `
  --cookie "session=abc123"
```

Notes:

- These values are added to the seeded request for each endpoint; they do not
  change *what* ZAP fuzzes (that is controlled by `--injectable`).
- The sample app exposes `POST /api/secure-data`, which returns `401` unless the
  request carries `X-API-Key: secret123` — handy for verifying header injection.

## Scan Logging

Two debug logs are produced during a scan (a run banner is written to each at
startup):

- **Error responses** — `scanlogs.txt` (override with `--scan-log` / `SCAN_LOG_PATH`).
  Every `401`/`500` response observed for an endpoint (seed request and any
  scanner-generated requests) is logged with the full request and response.
- **Alert calls** — `calls_alerts.txt` (override with `--alert-log` / `ALERT_LOG_PATH`).
  For each discovered alert, the exact fuzzed request/response that triggered it
  is logged along with the attack payload, param, evidence, and CWE/plugin. Use
  `--alert-risk` / `ALERT_LOG_RISKS` to filter by severity (default `high,medium`).

```powershell
# Log only High-severity alert calls to a custom file
node zap-openapi-policy-scan.js --spec openapi.json --base-url http://localhost:3000 --policy API `
  --alert-risk high --alert-log high-alerts.txt
```

## Environment Variable Overrides

Supported environment variables:

- `OPENAPI_SPEC_PATH`
- `BASE_URL`
- `ZAP_SCAN_POLICY`
- `DAST_DB_PATH`
- `TEST_STRATEGY`
- `ZAP_HOST`
- `ZAP_PORT`
- `ZAP_API_KEY`
- `ZAP_INJECTABLE_PARAMS`
- `ZAP_EXTRA_HEADERS` (one `Name: Value` per line)
- `ZAP_EXTRA_COOKIES` (`name=value; name2=value2`)
- `SCAN_LOG_PATH`
- `ALERT_LOG_PATH`
- `ALERT_LOG_RISKS`

Example:

```powershell
$env:BASE_URL="http://localhost:3000"
$env:OPENAPI_SPEC_PATH="openapi.json"
$env:ZAP_SCAN_POLICY="API"
node zap-openapi-policy-scan.js
```

## Troubleshooting

- `Target server is unreachable`: Start your API or fix `--base-url`.
- `Scan policy not found`: Verify policy exists in ZAP and use exact name.
- `ZAP API error` / connection refused: Ensure daemon is running and host/port match.
- Empty/low findings:
  - Confirm endpoints exist in `openapi.json`
  - Verify requests are accepted by target app
  - Try broader injection settings (`--injectable all`)
- Endpoint returns `401`: The target likely requires auth. Supply the header/cookie
  via `--header` / `--cookie`; check `scanlogs.txt` for the logged 401 request/response.

## Security Notes

- The sample `server.js` is intentionally vulnerable for testing.
- Do not run aggressive scans against systems you do not own or have explicit permission to test.
- Prefer enabling ZAP API key in non-local/shared environments.
