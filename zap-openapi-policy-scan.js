const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { URL } = require('node:url');
const sqlite3 = require('sqlite3');
const YAML = require('yaml');

// Injection point bitmask (matches ZAP ascan TargetParamsInjectable flags).
const INJECTABLE = {
  QUERY_STRING: 1,
  POST_DATA: 2,
  URL_PATH: 4,
  HTTP_HEADERS: 8,
  COOKIE: 16
};

const defaults = {
  specPath: 'openapi.json',
  baseUrl: '',
  scanPolicyName: '',
  strategyName: 'zap',
  dbPath: 'dast.db',
  zapHost: '127.0.0.1',
  zapPort: 8090,
  apiKey: '',
  pollIntervalMs: 1000,
  redoFailed: false,
  scanLogPath: 'scanlogs.txt',
  alertLogPath: 'calls_alerts.txt',
  alertLogRisks: ['high', 'medium'],
  extraHeaders: {},
  cookies: {},
  activeScanTuning: {
    threadPerHost: 5,
    delayInMs: 0,
    // Targeted minimal API scan: hit query/body params, skip header/cookie/path fuzzing.
    injectableParams: INJECTABLE.QUERY_STRING | INJECTABLE.POST_DATA,
    maxRuleDurationInMins: 0,
    maxScanDurationInMins: 0
  }
};

function printUsage() {
  console.log([
    'Usage: node zap-openapi-policy-scan.js [options]',
    '',
    'Options:',
    '  --spec <path>          OpenAPI or Swagger file path',
    '  --base-url <url>       Base target URL for API endpoints (required)',
    '  --policy <name>        ZAP active scan policy name (required)',
    '  --db <path>            SQLite DB path (default: dast.db)',
    '  --strategy <name>      Test strategy name (default: zap)',
    '  --redo-failed          Re-run endpoints that previously failed',
    '  --header <name:value>  Extra request header sent to the target (repeatable)',
    '  --cookie <name=value>  Extra request cookie sent to the target (repeatable)',
    '  --scan-log <path>      Log file for 401/500 error responses (default: scanlogs.txt)',
    '  --alert-log <path>     Log file for request/response of each alert (default: calls_alerts.txt)',
    '  --alert-risk <list>    Severities to log to alert log: high,medium,low,info,all (default: high,medium)',
    '  --injectable <mask>    Injection points: query,post,path,headers,cookie,all (default: query,post)',
    '  --zap-host <host>      ZAP host (default: 127.0.0.1)',
    '  --zap-port <port>      ZAP API port',
    '  --api-key <key>        ZAP API key',
    '  --help                 Show this help text',
    '',
    'Environment overrides:',
    '  OPENAPI_SPEC_PATH, BASE_URL, ZAP_SCAN_POLICY, DAST_DB_PATH, TEST_STRATEGY, ZAP_HOST, ZAP_PORT, ZAP_API_KEY, ZAP_INJECTABLE_PARAMS,',
    '  ZAP_EXTRA_HEADERS (one "Name: Value" per line), ZAP_EXTRA_COOKIES ("name=value; name2=value2"), SCAN_LOG_PATH, ALERT_LOG_PATH, ALERT_LOG_RISKS'
  ].join('\n'));
}

function resolvePath(filePath) {
  return path.isAbsolute(filePath) ? filePath : path.resolve(__dirname, filePath);
}

function stripTrailingSlash(value) {
  return String(value || '').replace(/\/+$/, '');
}

function assertValidUrl(value, fieldName) {
  try {
    return new URL(value).toString();
  } catch {
    throw new Error(`Invalid ${fieldName}: ${value}`);
  }
}

function parseInjectableMask(rawValue) {
  const value = String(rawValue || '').trim().toLowerCase();
  if (!value) {
    return defaults.activeScanTuning.injectableParams;
  }

  if (value === 'all') {
    return (
      INJECTABLE.QUERY_STRING |
      INJECTABLE.POST_DATA |
      INJECTABLE.URL_PATH |
      INJECTABLE.HTTP_HEADERS |
      INJECTABLE.COOKIE
    );
  }

  const map = {
    query: INJECTABLE.QUERY_STRING,
    post: INJECTABLE.POST_DATA,
    body: INJECTABLE.POST_DATA,
    path: INJECTABLE.URL_PATH,
    header: INJECTABLE.HTTP_HEADERS,
    headers: INJECTABLE.HTTP_HEADERS,
    cookie: INJECTABLE.COOKIE,
    cookies: INJECTABLE.COOKIE
  };

  let mask = 0;
  const tokens = value.split(/[+,|\s]+/).filter(Boolean);
  for (const token of tokens) {
    const bit = map[token];
    if (!bit) {
      throw new Error(`Invalid injectable mask token: ${token}`);
    }
    mask |= bit;
  }

  if (!mask) {
    throw new Error(`Invalid injectable mask: ${rawValue}`);
  }
  return mask;
}

// Parses the alert-log severity filter into a Set of normalized risk labels
// ('high' | 'medium' | 'low' | 'info'). Accepts a comma/space list or 'all'.
function parseRiskFilter(rawValue) {
  const value = String(rawValue || '').trim().toLowerCase();
  if (!value) {
    return new Set(defaults.alertLogRisks);
  }

  if (value === 'all') {
    return new Set(['high', 'medium', 'low', 'info']);
  }

  const map = {
    high: 'high',
    medium: 'medium',
    med: 'medium',
    low: 'low',
    info: 'info',
    informational: 'info'
  };

  const result = new Set();
  for (const token of value.split(/[,\s|]+/).filter(Boolean)) {
    const risk = map[token];
    if (!risk) {
      throw new Error(`Invalid alert risk filter token: ${token}`);
    }
    result.add(risk);
  }

  if (!result.size) {
    throw new Error(`Invalid alert risk filter: ${rawValue}`);
  }
  return result;
}

// Adds a single "Name: Value" header entry to the target map.
function addHeaderEntry(target, rawValue) {
  const value = String(rawValue || '').trim();
  if (!value) {
    return;
  }
  const separator = value.indexOf(':');
  if (separator === -1) {
    throw new Error(`Invalid header (expected "Name: Value"): ${rawValue}`);
  }
  const name = value.slice(0, separator).trim();
  if (!name) {
    throw new Error(`Invalid header name in: ${rawValue}`);
  }
  target[name] = value.slice(separator + 1).trim();
}

// Adds a single "name=value" cookie entry to the target map.
function addCookieEntry(target, rawValue) {
  const value = String(rawValue || '').trim();
  if (!value) {
    return;
  }
  const separator = value.indexOf('=');
  if (separator === -1) {
    throw new Error(`Invalid cookie (expected "name=value"): ${rawValue}`);
  }
  const name = value.slice(0, separator).trim();
  if (!name) {
    throw new Error(`Invalid cookie name in: ${rawValue}`);
  }
  target[name] = value.slice(separator + 1).trim();
}

// Parses ZAP_EXTRA_HEADERS (one "Name: Value" per line) into a header map.
function parseHeadersEnv(rawValue) {
  const target = {};
  for (const line of String(rawValue || '').split(/\r?\n/)) {
    if (line.trim()) {
      addHeaderEntry(target, line);
    }
  }
  return target;
}

// Parses ZAP_EXTRA_COOKIES ("name=value; name2=value2") into a cookie map.
function parseCookiesEnv(rawValue) {
  const target = {};
  for (const part of String(rawValue || '').split(';')) {
    if (part.trim()) {
      addCookieEntry(target, part);
    }
  }
  return target;
}

// Serializes the cookie map into a single "Cookie" header value.
function buildCookieHeader(cookies) {
  return Object.entries(cookies || {})
    .map(([name, value]) => `${name}=${value}`)
    .join('; ');
}

// Combines configured headers and cookies into the extra headers appended to
// every request seeded into ZAP for the target.
function buildExtraHeaders() {
  const headers = { ...config.extraHeaders };
  const cookie = buildCookieHeader(config.cookies);
  if (cookie) {
    headers.Cookie = headers.Cookie ? `${headers.Cookie}; ${cookie}` : cookie;
  }
  return headers;
}

function parseArgs(argv) {
  const cli = {
    specPath: String(process.env.OPENAPI_SPEC_PATH || defaults.specPath).trim(),
    baseUrl: String(process.env.BASE_URL || defaults.baseUrl).trim(),
    scanPolicyName: String(process.env.ZAP_SCAN_POLICY || defaults.scanPolicyName).trim(),
    strategyName: String(process.env.TEST_STRATEGY || defaults.strategyName).trim() || defaults.strategyName,
    dbPath: String(process.env.DAST_DB_PATH || defaults.dbPath).trim() || defaults.dbPath,
    zapHost: String(process.env.ZAP_HOST || defaults.zapHost).trim() || defaults.zapHost,
    zapPort: Number(process.env.ZAP_PORT || defaults.zapPort),
    apiKey: process.env.ZAP_API_KEY || defaults.apiKey,
    pollIntervalMs: defaults.pollIntervalMs,
    redoFailed: defaults.redoFailed,
    scanLogPath: String(process.env.SCAN_LOG_PATH || defaults.scanLogPath).trim() || defaults.scanLogPath,
    alertLogPath: String(process.env.ALERT_LOG_PATH || defaults.alertLogPath).trim() || defaults.alertLogPath,
    alertLogRisks: parseRiskFilter(process.env.ALERT_LOG_RISKS || ''),
    extraHeaders: parseHeadersEnv(process.env.ZAP_EXTRA_HEADERS || ''),
    cookies: parseCookiesEnv(process.env.ZAP_EXTRA_COOKIES || ''),
    activeScanTuning: {
      ...defaults.activeScanTuning,
      injectableParams: parseInjectableMask(process.env.ZAP_INJECTABLE_PARAMS || '')
    }
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === '--help') {
      printUsage();
      process.exit(0);
    }
    if (arg === '--redo-failed') {
      cli.redoFailed = true;
      continue;
    }
    if (arg === '--header') {
      const value = String(argv[index + 1] || '').trim();
      if (!value) {
        throw new Error('Missing value for --header');
      }
      addHeaderEntry(cli.extraHeaders, value);
      index += 1;
      continue;
    }
    if (arg === '--cookie') {
      const value = String(argv[index + 1] || '').trim();
      if (!value) {
        throw new Error('Missing value for --cookie');
      }
      addCookieEntry(cli.cookies, value);
      index += 1;
      continue;
    }
    if (arg === '--scan-log') {
      const value = String(argv[index + 1] || '').trim();
      if (!value) {
        throw new Error('Missing value for --scan-log');
      }
      cli.scanLogPath = value;
      index += 1;
      continue;
    }
    if (arg === '--alert-log') {
      const value = String(argv[index + 1] || '').trim();
      if (!value) {
        throw new Error('Missing value for --alert-log');
      }
      cli.alertLogPath = value;
      index += 1;
      continue;
    }
    if (arg === '--alert-risk') {
      const value = String(argv[index + 1] || '').trim();
      if (!value) {
        throw new Error('Missing value for --alert-risk');
      }
      cli.alertLogRisks = parseRiskFilter(value);
      index += 1;
      continue;
    }
    if (arg === '--injectable') {
      const mask = String(argv[index + 1] || '').trim();
      if (!mask) {
        throw new Error('Missing value for --injectable');
      }
      cli.activeScanTuning.injectableParams = parseInjectableMask(mask);
      index += 1;
      continue;
    }
    if (arg === '--spec') {
      const specPath = String(argv[index + 1] || '').trim();
      if (!specPath) {
        throw new Error('Missing value for --spec');
      }
      cli.specPath = specPath;
      index += 1;
      continue;
    }
    if (arg === '--base-url') {
      cli.baseUrl = String(argv[index + 1] || '').trim();
      index += 1;
      continue;
    }
    if (arg === '--policy') {
      cli.scanPolicyName = String(argv[index + 1] || '').trim();
      index += 1;
      continue;
    }
    if (arg === '--db') {
      cli.dbPath = String(argv[index + 1] || '').trim();
      index += 1;
      continue;
    }
    if (arg === '--strategy') {
      cli.strategyName = String(argv[index + 1] || '').trim() || defaults.strategyName;
      index += 1;
      continue;
    }
    if (arg === '--zap-host') {
      cli.zapHost = String(argv[index + 1] || '').trim() || defaults.zapHost;
      index += 1;
      continue;
    }
    if (arg === '--zap-port') {
      cli.zapPort = Number(argv[index + 1]);
      index += 1;
      continue;
    }
    if (arg === '--api-key') {
      cli.apiKey = argv[index + 1] || '';
      index += 1;
      continue;
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  if (!cli.specPath) {
    throw new Error('Spec path is required. Use --spec <path>.');
  }

  if (!cli.baseUrl) {
    throw new Error('Base URL is required. Use --base-url <url>.');
  }

  if (!cli.scanPolicyName) {
    throw new Error('Policy name is required. Use --policy <name>.');
  }

  const absPath = resolvePath(cli.specPath);
  if (!fs.existsSync(absPath)) {
    throw new Error(`Spec file not found: ${absPath}`);
  }

  cli.specPath = absPath;
  cli.baseUrl = stripTrailingSlash(assertValidUrl(cli.baseUrl, 'base URL'));
  cli.dbPath = resolvePath(cli.dbPath);
  cli.scanLogPath = resolvePath(cli.scanLogPath);
  cli.alertLogPath = resolvePath(cli.alertLogPath);

  return cli;
}

const config = parseArgs(process.argv.slice(2));

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function loadSpecDocument(specPath) {
  return YAML.parse(fs.readFileSync(specPath, 'utf8'));
}

function describeConnectionError(error) {
  const parts = [];
  if (error?.cause?.code) {
    parts.push(error.cause.code);
  }
  if (error?.cause?.message) {
    parts.push(error.cause.message);
  } else if (error?.message) {
    parts.push(error.message);
  }
  return parts.join(' - ');
}

async function ensureBaseUrlReachable() {
  const targetUrl = config.baseUrl;

  try {
    const response = await fetch(targetUrl, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(5000)
    });

    if (!response) {
      throw new Error('No response received');
    }

    return targetUrl;
  } catch (error) {
    throw new Error(
      `Target server is unreachable: ${targetUrl}. ` +
      `Start the application or use --base-url <url>. ${describeConnectionError(error)}`.trim()
    );
  }
}

function getEffectiveApiKey() {
  return String(config.apiKey || '').trim();
}

function buildQuery(params) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params || {})) {
    if (value !== undefined && value !== null && value !== '') {
      search.set(key, String(value));
    }
  }
  return search.toString();
}

function zapBaseUrl() {
  return `http://${config.zapHost}:${config.zapPort}`;
}

async function zapJson(component, type, name, params) {
  const apiKey = getEffectiveApiKey();
  const query = buildQuery({ ...(params || {}), apikey: apiKey || undefined });
  const url = `${zapBaseUrl()}/JSON/${component}/${type}/${name}/${query ? `?${query}` : ''}`;
  const response = await fetch(url);

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`ZAP API error (${response.status}) at ${url}: ${body}`);
  }

  const body = await response.json();
  if (body.code && body.message) {
    throw new Error(`ZAP API responded with error code=${body.code}, message=${body.message}`);
  }

  return body;
}

function isUrlNotFoundError(error) {
  const message = String(error?.message || error);
  return (
    message.includes('url_not_found') ||
    message.includes('URL Not Found in the Scan Tree')
  );
}

// Builds a raw HTTP request string (origin-form) for ZAP's core/sendRequest
// API, used as the seeding fallback for non-HTTP(S)-proxyable targets.
function buildRawHttpRequest(operation) {
  const target = new URL(operation.requestUrl);
  const headers = { Host: target.host, Accept: 'application/json' };

  const body = operation.bodyString || '';
  if (body) {
    headers['Content-Type'] = operation.contentType || 'application/json';
    headers['Content-Length'] = Buffer.byteLength(body);
  }

  Object.assign(headers, buildExtraHeaders());

  const lines = [`${operation.httpMethod} ${operation.requestPath} HTTP/1.1`];
  for (const [name, value] of Object.entries(headers)) {
    lines.push(`${name}: ${value}`);
  }

  return `${lines.join('\r\n')}\r\n\r\n${body}`;
}

// Sends the operation's concrete request to the target THROUGH ZAP's proxy
// (absolute-form request URI). ZAP records the exact message - method and body
// included - in its Sites tree, giving the active scanner a node to fuzz.
function proxyRequestThroughZap(operation, target) {
  return new Promise((resolve, reject) => {
    const headers = { Host: target.host, Accept: 'application/json' };
    const body = operation.bodyString || '';
    if (body) {
      headers['Content-Type'] = operation.contentType || 'application/json';
      headers['Content-Length'] = Buffer.byteLength(body);
    }

    Object.assign(headers, buildExtraHeaders());

    const request = http.request(
      {
        host: config.zapHost,
        port: config.zapPort,
        method: operation.httpMethod,
        path: operation.requestUrl,
        headers
      },
      (response) => {
        response.resume();
        response.on('end', resolve);
        response.on('error', reject);
      }
    );

    request.on('error', reject);
    request.setTimeout(15000, () => request.destroy(new Error('Seed request timed out')));
    if (body) {
      request.write(body);
    }
    request.end();
  });
}

async function seedRequestInZap(operation) {
  const target = new URL(operation.requestUrl);
  if (target.protocol === 'http:') {
    await proxyRequestThroughZap(operation, target);
    return;
  }

  // HTTPS (or other) targets cannot be proxied with a plain HTTP request, so
  // register the message via ZAP's sendRequest API instead.
  await zapJson('core', 'action', 'sendRequest', {
    request: buildRawHttpRequest(operation),
    followRedirects: false
  });
}

async function seedScanTree(operations) {
  // Drive the requests ourselves: each endpoint's method and body come from the
  // OpenAPI spec and are routed through ZAP so the exact message lands in its
  // Sites tree. No OpenAPI add-on import and no parameter-less GET seeding.
  for (const operation of operations) {
    try {
      await seedRequestInZap(operation);
    } catch (error) {
      console.warn(`Could not seed ${operation.httpMethod} ${operation.requestUrl}: ${String(error?.message || error)}`);
    }
  }
  console.log(`Seeded ${operations.length} request(s) into ZAP from the OpenAPI spec (method + body per endpoint).`);
  const headerNames = Object.keys(config.extraHeaders || {});
  const cookieNames = Object.keys(config.cookies || {});
  if (headerNames.length || cookieNames.length) {
    console.log(
      `Applied extra request headers: [${headerNames.join(', ') || 'none'}], ` +
      `cookies: [${cookieNames.join(', ') || 'none'}].`
    );
  }
}

async function applyActiveScanTuning() {
  const tuning = config.activeScanTuning || {};
  const options = [
    ['setOptionThreadPerHost', 'Integer', tuning.threadPerHost],
    ['setOptionDelayInMs', 'Integer', tuning.delayInMs],
    ['setOptionMaxRuleDurationInMins', 'Integer', tuning.maxRuleDurationInMins],
    ['setOptionMaxScanDurationInMins', 'Integer', tuning.maxScanDurationInMins],
    ['setOptionTargetParamsInjectable', 'Integer', tuning.injectableParams],
    ['setOptionHandleAntiCSRFTokens', 'Boolean', false]
  ];

  for (const [action, paramName, value] of options) {
    if (value === undefined || value === null) {
      continue;
    }
    await zapJson('ascan', 'action', action, { [paramName]: value });
  }

  console.log(
    `Active scan tuning applied: threadPerHost=${tuning.threadPerHost}, ` +
    `injectableParams=${tuning.injectableParams}, delayInMs=${tuning.delayInMs}`
  );
}

async function warnIfSqliScannersUnavailable(scanPolicyName) {
  try {
    const response = await zapJson('ascan', 'view', 'scanners', { scanPolicyName });
    const scanners = Array.isArray(response?.scanners) ? response.scanners : [];
    const sqli = scanners.filter((scanner) => {
      const id = Number(scanner?.id);
      const name = String(scanner?.name || '').toLowerCase();
      return id === 40018 || id === 40019 || name.includes('sql injection');
    });

    if (!sqli.length) {
      console.warn(`No SQL Injection scanners were listed for policy ${scanPolicyName}.`);
      return;
    }

    const disabled = sqli.filter((scanner) => String(scanner?.enabled).toLowerCase() === 'false');
    if (disabled.length) {
      const ids = disabled.map((scanner) => scanner.id || scanner.name).join(', ');
      console.warn(`SQL Injection scanner(s) disabled in policy ${scanPolicyName}: ${ids}`);
    }
  } catch (error) {
    console.warn(`Could not inspect scanner list for policy ${scanPolicyName}: ${String(error?.message || error)}`);
  }
}

async function ensureZapReady() {
  const version = await zapJson('core', 'view', 'version');
  if (!version.version) {
    throw new Error('ZAP did not return a version. Ensure the daemon is running and reachable.');
  }
  console.log(`ZAP ready: version ${version.version}`);
}

async function listAvailableScanPolicies() {
  const result = await zapJson('ascan', 'view', 'scanPolicyNames');
  return Array.isArray(result.scanPolicyNames) ? result.scanPolicyNames.map((name) => String(name)) : [];
}

async function validateScanPolicyName(policyName) {
  const availableNames = await listAvailableScanPolicies();
  const requested = availableNames.find((name) => name.toLowerCase() === policyName.toLowerCase());
  if (!requested) {
    throw new Error(`Scan policy not found: ${policyName}. Available policies: ${availableNames.join(', ') || 'none'}`);
  }
  return requested;
}

async function runActiveScan(operation, scanPolicyName) {
  // Target the seeded node precisely by method + body. ZAP fuzzes only the
  // request body and query string (setOptionTargetParamsInjectable excludes
  // headers, cookies and the URL path) and inspects the responses with the
  // active + passive rules in the policy.
  const params = {
    url: operation.requestUrl,
    method: operation.httpMethod,
    recurse: false,
    inScopeOnly: false,
    scanPolicyName
  };
  if (operation.bodyString) {
    params.postData = operation.bodyString;
  }

  const response = await zapJson('ascan', 'action', 'scan', params);

  const scanId = response.scan;
  if (!scanId) {
    throw new Error(`Invalid scan start response for ${operation.requestUrl}: ${JSON.stringify(response)}`);
  }

  while (true) {
    await sleep(config.pollIntervalMs);
    const status = await zapJson('ascan', 'view', 'status', { scanId });
    if (String(status.status) === '100') {
      return scanId;
    }
  }
}

async function runActiveScanWithRecovery(operation, scanPolicyName) {
  try {
    return await runActiveScan(operation, scanPolicyName);
  } catch (error) {
    if (!isUrlNotFoundError(error)) {
      throw error;
    }

    // The node aged out of the tree (e.g. new ZAP session): re-seed the exact
    // request and retry once.
    console.warn(`ZAP reported url_not_found for ${operation.httpMethod} ${operation.requestUrl}. Re-seeding request and retrying once.`);
    await seedRequestInZap(operation);
    await sleep(500);
    return runActiveScan(operation, scanPolicyName);
  }
}

// Error status codes captured to the scan log for debugging.
const LOGGED_ERROR_STATUS_CODES = new Set([401, 500]);

// Message ids already written to the scan log during this process, so the same
// history entry is not logged twice across per-operation passes.
const loggedMessageIds = new Set();

// History message id that existed before this run started; older messages
// (e.g. from a previous scan sharing the same ZAP session) are skipped so the
// log only reflects the current run.
let scanLogBaselineId = 0;

async function captureScanLogBaseline() {
  try {
    const response = await zapJson('core', 'view', 'numberOfMessages');
    scanLogBaselineId = Number(response?.numberOfMessages) || 0;
  } catch {
    scanLogBaselineId = 0;
  }
}

// Extracts the numeric HTTP status code from a ZAP response header block.
function parseResponseStatusCode(responseHeader) {
  const match = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/i.exec(String(responseHeader || '').trim());
  return match ? Number(match[1]) : null;
}

// Appends a full request/response transcript for one error message to the log.
function appendScanLogEntry(operation, messageId, status, message) {
  const divider = '='.repeat(80);
  const entry = [
    divider,
    `[${new Date().toISOString()}] HTTP ${status} during scan of ${operation.httpMethod} ${operation.scanUrl}`,
    `ZAP history message id: ${messageId}`,
    '',
    '--- REQUEST ---',
    String(message?.requestHeader || '').trimEnd(),
    String(message?.requestBody || ''),
    '',
    '--- RESPONSE ---',
    String(message?.responseHeader || '').trimEnd(),
    String(message?.responseBody || ''),
    '',
    ''
  ].join('\n');

  fs.appendFileSync(config.scanLogPath, entry, 'utf8');
}

// Inspects every ZAP history message for the operation's URL (both the seed
// request and any scanner-generated requests) and logs the 401/500 responses
// (request + response) to the scan log file for debugging.
async function logErrorResponsesForOperation(operation) {
  let messages;
  try {
    const response = await zapJson('core', 'view', 'messages', { baseurl: operation.scanUrl });
    messages = Array.isArray(response?.messages) ? response.messages : [];
  } catch (error) {
    console.warn(`Could not read ZAP history for ${operation.httpMethod} ${operation.scanUrl}: ${String(error?.message || error)}`);
    return 0;
  }

  let logged = 0;
  for (const message of messages) {
    const id = Number(message?.id);
    if (Number.isFinite(id)) {
      if (id < scanLogBaselineId || loggedMessageIds.has(id)) {
        continue;
      }
    }

    const status = parseResponseStatusCode(message?.responseHeader);
    if (!LOGGED_ERROR_STATUS_CODES.has(status)) {
      continue;
    }

    try {
      appendScanLogEntry(operation, message?.id ?? 'unknown', status, message);
      if (Number.isFinite(id)) {
        loggedMessageIds.add(id);
      }
      logged += 1;
    } catch (error) {
      console.warn(`Could not write scan log entry to ${config.scanLogPath}: ${String(error?.message || error)}`);
    }
  }

  if (logged) {
    console.warn(`Logged ${logged} error response(s) (401/500) for ${operation.httpMethod} ${operation.scanUrl} to ${config.scanLogPath}`);
  }
  return logged;
}

// Appends the fuzzed request/response and metadata for a single alert to the
// alert log, so it is clear which attack request triggered each finding.
function appendAlertLogEntry(operation, alert, message) {
  const divider = '#'.repeat(80);
  const entry = [
    divider,
    `[${new Date().toISOString()}] ${alert?.risk || '?'} - ${alert?.alert || alert?.name || 'Alert'}`,
    `Endpoint:   ${operation.httpMethod} ${operation.scanUrl}`,
    `Alert URL:  ${alert?.url || ''}`,
    `Param:      ${alert?.param || ''}`,
    `Attack:     ${alert?.attack || ''}`,
    `Evidence:   ${alert?.evidence || ''}`,
    `CWE=${alert?.cweid ?? ''} plugin=${alert?.pluginId ?? ''} confidence=${alert?.confidence || ''}`,
    `ZAP message id: ${alert?.messageId ?? 'unknown'}`,
    '',
    '--- REQUEST ---',
    message ? String(message?.requestHeader || '').trimEnd() : '(request unavailable — see Attack/Param above)',
    message ? String(message?.requestBody || '') : '',
    '',
    '--- RESPONSE ---',
    message ? String(message?.responseHeader || '').trimEnd() : '(response unavailable)',
    message ? String(message?.responseBody || '') : '',
    '',
    ''
  ].join('\n');

  fs.appendFileSync(config.alertLogPath, entry, 'utf8');
}

// For every alert found on an endpoint, resolves the history message that
// triggered it (alert.messageId) and logs the exact fuzzed request/response.
async function logAlertCalls(alerts, operation) {
  if (!Array.isArray(alerts) || !alerts.length) {
    return 0;
  }

  let logged = 0;
  for (const alert of alerts) {
    if (!config.alertLogRisks.has(normalizeRisk(alert))) {
      continue;
    }

    const messageId = alert?.messageId;
    let message = null;

    if (messageId !== undefined && messageId !== null && String(messageId).trim() !== '') {
      try {
        const response = await zapJson('core', 'view', 'message', { id: messageId });
        message = response?.message || response;
      } catch {
        message = null;
      }
    }

    try {
      appendAlertLogEntry(operation, alert, message);
      logged += 1;
    } catch (error) {
      console.warn(`Could not write alert log entry to ${config.alertLogPath}: ${String(error?.message || error)}`);
    }
  }

  if (logged) {
    console.warn(`Logged ${logged} alert call(s) for ${operation.httpMethod} ${operation.scanUrl} to ${config.alertLogPath}`);
  }
  return logged;
}

async function fetchAlertsForUrl(url) {
  const alerts = await zapJson('core', 'view', 'alerts', {
    baseurl: url,
    start: 0,
    count: 10000
  });
  return Array.isArray(alerts.alerts) ? alerts.alerts : [];
}

function normalizeRisk(alert) {
  const raw = alert?.risk;

  // ZAP's core/view/alerts returns `risk` as a numeric level in some contexts
  // and as a text label ("High"/"Medium"/"Low"/"Informational") in others, and
  // does not always include `riskdesc`. Handle every shape.
  const numeric = Number(raw);
  if (String(raw ?? '').trim() !== '' && Number.isFinite(numeric)) {
    if (numeric >= 3) {
      return 'high';
    }
    if (numeric === 2) {
      return 'medium';
    }
    if (numeric === 1) {
      return 'low';
    }
    return 'info';
  }

  const label = String(raw ?? alert?.riskdesc ?? '').toLowerCase();
  if (label.startsWith('high')) {
    return 'high';
  }
  if (label.startsWith('medium')) {
    return 'medium';
  }
  if (label.startsWith('low')) {
    return 'low';
  }
  return 'info';
}

function summarizeAlerts(alerts) {
  const summary = {
    alertCount: alerts.length,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  for (const alert of alerts) {
    const risk = normalizeRisk(alert);
    if (risk === 'high') {
      summary.high += 1;
    } else if (risk === 'medium') {
      summary.medium += 1;
    } else if (risk === 'low') {
      summary.low += 1;
    } else {
      summary.info += 1;
    }
  }

  return summary;
}

// Follows a single local $ref chain (e.g. #/components/schemas/Foo) and
// returns the referenced node, or the node itself when it is not a reference.
function resolveRef(spec, node) {
  let current = node;
  const seen = new Set();
  while (current && typeof current === 'object' && typeof current.$ref === 'string') {
    if (seen.has(current.$ref)) {
      return {};
    }
    seen.add(current.$ref);
    const segments = current.$ref.replace(/^#\//, '').split('/');
    let target = spec;
    for (const segment of segments) {
      const key = decodeURIComponent(segment.replace(/~1/g, '/').replace(/~0/g, '~'));
      target = target?.[key];
    }
    current = target;
  }
  return current || {};
}

// Builds a concrete example value from a JSON schema, preferring declared
// example/default/enum values and otherwise falling back to type-based stubs.
function buildExampleValue(spec, rawSchema, depth = 0) {
  const schema = resolveRef(spec, rawSchema);
  if (!schema || typeof schema !== 'object' || depth > 6) {
    return null;
  }
  if (schema.example !== undefined) {
    return schema.example;
  }
  if (schema.default !== undefined) {
    return schema.default;
  }
  if (Array.isArray(schema.enum) && schema.enum.length) {
    return schema.enum[0];
  }

  const type = Array.isArray(schema.type) ? schema.type[0] : schema.type;

  if (type === 'object' || schema.properties) {
    const result = {};
    for (const [name, propSchema] of Object.entries(schema.properties || {})) {
      result[name] = buildExampleValue(spec, propSchema, depth + 1);
    }
    return result;
  }
  if (type === 'array') {
    return [buildExampleValue(spec, schema.items || {}, depth + 1)];
  }
  if (type === 'integer' || type === 'number') {
    return 1;
  }
  if (type === 'boolean') {
    return true;
  }
  return 'test';
}

// Derives the request body (content type + serialized payload) an operation
// expects, so the exact message can be seeded into ZAP and fuzzed.
function buildRequestBody(spec, operation) {
  const requestBody = resolveRef(spec, operation?.requestBody);
  const content = requestBody?.content;
  if (!content || typeof content !== 'object') {
    return null;
  }

  const jsonType = Object.keys(content).find((type) => /json/i.test(type));
  if (jsonType) {
    const media = content[jsonType] || {};
    const value = media.example !== undefined ? media.example : buildExampleValue(spec, media.schema || {});
    return { contentType: jsonType, bodyString: JSON.stringify(value ?? {}) };
  }

  const formType = Object.keys(content).find((type) => /x-www-form-urlencoded/i.test(type));
  if (formType) {
    const media = content[formType] || {};
    const value = buildExampleValue(spec, media.schema || {}) || {};
    const search = new URLSearchParams();
    for (const [key, val] of Object.entries(value)) {
      search.set(key, val === null || val === undefined ? '' : String(val));
    }
    return { contentType: formType, bodyString: search.toString() };
  }

  return null;
}

function collectParameters(spec, pathItem, operation) {
  const merged = [];
  for (const list of [pathItem?.parameters, operation?.parameters]) {
    if (Array.isArray(list)) {
      for (const param of list) {
        merged.push(resolveRef(spec, param));
      }
    }
  }
  return merged;
}

// Resolves the concrete request URL for an operation, substituting path
// parameters and appending example query-string values from the spec.
function buildEndpointUrl(spec, base, endpointPath, parameters) {
  let resolvedPath = endpointPath;
  const search = new URLSearchParams();

  for (const param of parameters) {
    if (!param || !param.name) {
      continue;
    }
    const value = param.example !== undefined ? param.example : buildExampleValue(spec, param.schema || {});
    const stringValue = value === null || value === undefined ? '1' : String(value);

    if (param.in === 'path') {
      resolvedPath = resolvedPath.replace(new RegExp(`\\{${param.name}\\}`, 'g'), encodeURIComponent(stringValue));
    } else if (param.in === 'query') {
      search.set(param.name, stringValue);
    }
  }

  // Any path templates left unfilled get a benign placeholder.
  resolvedPath = resolvedPath.replace(/\{[^}]+\}/g, '1');

  const url = new URL(resolvedPath, `${base.protocol}//${base.host}`);
  const query = search.toString();
  if (query) {
    url.search = query;
  }
  return url;
}

function extractOperations(specPath, baseUrl) {
  const spec = loadSpecDocument(specPath);
  const methods = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options']);
  const bodyMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
  const base = new URL(baseUrl);
  const host = base.hostname;
  const port = Number(base.port || (base.protocol === 'https:' ? 443 : 80));
  const operations = [];

  for (const [endpointPath, pathItem] of Object.entries(spec?.paths || {})) {
    if (!pathItem || typeof pathItem !== 'object') {
      continue;
    }

    for (const [method, operation] of Object.entries(pathItem)) {
      if (!methods.has(method.toLowerCase())) {
        continue;
      }
      const normalizedMethod = method.toUpperCase();
      const parameters = collectParameters(spec, pathItem, operation);
      const requestUrlObj = buildEndpointUrl(spec, base, endpointPath, parameters);
      const requestUrl = requestUrlObj.toString();
      const scanUrl = `${requestUrlObj.protocol}//${requestUrlObj.host}${requestUrlObj.pathname}`;
      const body = bodyMethods.has(normalizedMethod) ? buildRequestBody(spec, operation) : null;

      operations.push({
        endpointPath,
        httpMethod: normalizedMethod,
        endpointKey: `${host}:${port}${endpointPath}:${normalizedMethod}`,
        scanUrl,
        requestUrl,
        requestPath: `${requestUrlObj.pathname}${requestUrlObj.search}`,
        contentType: body?.contentType || null,
        bodyString: body?.bodyString || null,
        operationId: operation?.operationId || null,
        host,
        port
      });
    }
  }

  return operations;
}

function openDatabase(dbPath) {
  return new sqlite3.Database(dbPath);
}

function dbRun(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(error) {
      if (error) {
        reject(error);
        return;
      }
      resolve(this);
    });
  });
}

function dbGet(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(row);
    });
  });
}

async function ensureDbSchemaExists(db) {
  const row = await dbGet(
    db,
    "SELECT name FROM sqlite_master WHERE type='table' AND name='zap_test_status'"
  );
  if (!row) {
    throw new Error('Table zap_test_status was not found. Run: node setup-zap-db.js');
  }
}

async function getExistingStatus(db, strategyName, endpointKey) {
  const row = await dbGet(
    db,
    'SELECT status FROM zap_test_status WHERE strategy_name = ? AND endpoint_key = ?',
    [strategyName, endpointKey]
  );
  return row ? String(row.status) : null;
}

async function upsertResult(db, operation, status, details) {
  const now = new Date().toISOString();
  const alertDetailsJson = details.alertDetails ? JSON.stringify(details.alertDetails) : null;

  await dbRun(
    db,
    `INSERT INTO zap_test_status (
      strategy_name,
      endpoint_key,
      base_url,
      host,
      port,
      endpoint_path,
      http_method,
      policy_name,
      operation_id,
      status,
      alert_count,
      risk_high,
      risk_medium,
      risk_low,
      risk_info,
      error_message,
      alert_details_json,
      scanned_at,
      created_at,
      updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(strategy_name, endpoint_key)
    DO UPDATE SET
      base_url = excluded.base_url,
      host = excluded.host,
      port = excluded.port,
      endpoint_path = excluded.endpoint_path,
      http_method = excluded.http_method,
      policy_name = excluded.policy_name,
      operation_id = excluded.operation_id,
      status = excluded.status,
      alert_count = excluded.alert_count,
      risk_high = excluded.risk_high,
      risk_medium = excluded.risk_medium,
      risk_low = excluded.risk_low,
      risk_info = excluded.risk_info,
      error_message = excluded.error_message,
      alert_details_json = excluded.alert_details_json,
      scanned_at = excluded.scanned_at,
      updated_at = excluded.updated_at`,
    [
      config.strategyName,
      operation.endpointKey,
      config.baseUrl,
      operation.host,
      operation.port,
      operation.endpointPath,
      operation.httpMethod,
      config.scanPolicyName,
      operation.operationId,
      status,
      details.alertCount,
      details.high,
      details.medium,
      details.low,
      details.info,
      details.errorMessage || null,
      alertDetailsJson,
      now,
      now,
      now
    ]
  );
}

function closeDatabase(db) {
  return new Promise((resolve, reject) => {
    db.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

async function main() {
  console.log(`Preparing ZAP scan. spec=${config.specPath} baseUrl=${config.baseUrl} policy=${config.scanPolicyName}`);

  await ensureBaseUrlReachable();
  await ensureZapReady();
  config.scanPolicyName = await validateScanPolicyName(config.scanPolicyName);
  await applyActiveScanTuning();
  await warnIfSqliScannersUnavailable(config.scanPolicyName);

  const operations = extractOperations(config.specPath, config.baseUrl);
  if (!operations.length) {
    throw new Error(`No OpenAPI operations found in ${config.specPath}`);
  }

  await seedScanTree(operations);

  try {
    fs.appendFileSync(
      config.scanLogPath,
      `\n##### Scan run started ${new Date().toISOString()} — baseUrl=${config.baseUrl} policy=${config.scanPolicyName} #####\n`,
      'utf8'
    );
    fs.appendFileSync(
      config.alertLogPath,
      `\n##### Scan run started ${new Date().toISOString()} — baseUrl=${config.baseUrl} policy=${config.scanPolicyName} #####\n`,
      'utf8'
    );
  } catch (error) {
    console.warn(`Could not write to scan log ${config.scanLogPath}: ${String(error?.message || error)}`);
  }

  await captureScanLogBaseline();

  const db = openDatabase(config.dbPath);
  const counters = {
    total: operations.length,
    executed: 0,
    completed: 0,
    failed: 0,
    skippedComplete: 0,
    skippedFailed: 0
  };

  try {
    await ensureDbSchemaExists(db);

    for (const operation of operations) {
      const existingStatus = await getExistingStatus(db, config.strategyName, operation.endpointKey);
      if (existingStatus === 'COMPLETE') {
        counters.skippedComplete += 1;
        continue;
      }
      if (existingStatus === 'FAILED' && !config.redoFailed) {
        counters.skippedFailed += 1;
        continue;
      }

      counters.executed += 1;
      console.log(`Scanning ${operation.httpMethod} ${operation.endpointPath} (${operation.scanUrl})`);

      try {
        await runActiveScanWithRecovery(operation, config.scanPolicyName);
        await logErrorResponsesForOperation(operation);
        const alerts = await fetchAlertsForUrl(operation.scanUrl);
        await logAlertCalls(alerts, operation);
        const summary = summarizeAlerts(alerts);
        await upsertResult(db, operation, 'COMPLETE', {
          ...summary,
          alertDetails: alerts,
          errorMessage: null
        });
        counters.completed += 1;
      } catch (error) {
        await upsertResult(db, operation, 'FAILED', {
          alertCount: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
          alertDetails: [],
          errorMessage: String(error.message || error)
        });
        counters.failed += 1;
      }
    }
  } finally {
    await closeDatabase(db);
  }

  console.log('Scan summary:');
  console.log(`  total=${counters.total}`);
  console.log(`  executed=${counters.executed}`);
  console.log(`  completed=${counters.completed}`);
  console.log(`  failed=${counters.failed}`);
  console.log(`  skipped_complete=${counters.skippedComplete}`);
  console.log(`  skipped_failed=${counters.skippedFailed}`);
}

main().catch((error) => {
  console.error(`Scan failed: ${error.message}`);
  process.exitCode = 1;
});
