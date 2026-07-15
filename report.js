const fs = require('node:fs');
const path = require('node:path');
const sqlite3 = require('sqlite3');

const defaults = {
  dbPath: 'dast.db',
  outPath: 'zap-db-report.html',
  csvPath: 'zap-db-report.csv',
  coverageCsvPath: 'zap-db-coverage.csv',
  strategyName: '',
  policyName: ''
};

function printUsage() {
  console.log([
    'Usage: node zap-db-html-report.js [options]',
    '',
    'Options:',
    '  --db <path>         SQLite DB path (default: [dast.db](http://_vscodecontentref_/2))',
    '  --out <path>        Output HTML path (default: zap-db-report.html)',
    '  --csv <path>        Output CSV path for alerts (default: zap-db-report.csv)',
    '  --coverage-csv <path>  Output CSV path for API coverage (default: zap-db-coverage.csv)',
    '  --strategy <name>   Filter by strategy_name',
    '  --policy <name>     Filter by policy_name',
    '  --help              Show this help text'
  ].join('\n'));
}

function resolvePath(filePath) {
  return path.isAbsolute(filePath) ? filePath : path.resolve(__dirname, filePath);
}

function parseArgs(argv) {
  const config = {
    dbPath: String(process.env.DAST_DB_PATH || defaults.dbPath).trim() || defaults.dbPath,
    outPath: String(process.env.DAST_REPORT_OUT || defaults.outPath).trim() || defaults.outPath,
    csvPath: String(process.env.DAST_REPORT_CSV || defaults.csvPath).trim() || defaults.csvPath,
    coverageCsvPath: String(process.env.DAST_REPORT_COVERAGE_CSV || defaults.coverageCsvPath).trim() || defaults.coverageCsvPath,
    strategyName: String(process.env.TEST_STRATEGY || defaults.strategyName).trim(),
    policyName: String(process.env.ZAP_SCAN_POLICY || defaults.policyName).trim()
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--help') {
      printUsage();
      process.exit(0);
    }
    if (arg === '--db') {
      config.dbPath = String(argv[i + 1] || '').trim() || defaults.dbPath;
      i += 1;
      continue;
    }
    if (arg === '--out') {
      config.outPath = String(argv[i + 1] || '').trim() || defaults.outPath;
      i += 1;
      continue;
    }
    if (arg === '--csv') {
      config.csvPath = String(argv[i + 1] || '').trim() || defaults.csvPath;
      i += 1;
      continue;
    }
    if (arg === '--coverage-csv') {
      config.coverageCsvPath = String(argv[i + 1] || '').trim() || defaults.coverageCsvPath;
      i += 1;
      continue;
    }
    if (arg === '--strategy') {
      config.strategyName = String(argv[i + 1] || '').trim();
      i += 1;
      continue;
    }
    if (arg === '--policy') {
      config.policyName = String(argv[i + 1] || '').trim();
      i += 1;
      continue;
    }

    throw new Error('Unknown argument: ' + arg);
  }

  config.dbPath = resolvePath(config.dbPath);
  config.outPath = resolvePath(config.outPath);
  config.csvPath = resolvePath(config.csvPath);
  config.coverageCsvPath = resolvePath(config.coverageCsvPath);
  return config;
}

function openDatabase(dbPath) {
  return new sqlite3.Database(dbPath);
}

function dbAll(db, sql, params) {
  return new Promise((resolve, reject) => {
    db.all(sql, params || [], (error, rows) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(rows || []);
    });
  });
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

function escapeHtml(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function toInt(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function parseJsonArray(value) {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function getRiskLabel(alert) {
  const riskText = String(alert && (alert.riskdesc || alert.risk || '')).toLowerCase();
  if (riskText.indexOf('high') === 0 || riskText === '3' || riskText === 'high') return 'high';
  if (riskText.indexOf('medium') === 0 || riskText === '2' || riskText === 'medium') return 'medium';
  if (riskText.indexOf('low') === 0 || riskText === '1' || riskText === 'low') return 'low';
  return 'info';
}

function buildReportModel(rows, config) {
  const summary = {
    totalEndpoints: rows.length,
    complete: 0,
    failed: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    alerts: 0
  };

  const strategySet = new Set();
  const policySet = new Set();
  const alertNameCount = new Map();

  for (const row of rows) {
    const status = String(row.status || '');
    if (status === 'COMPLETE') summary.complete += 1;
    if (status === 'FAILED') summary.failed += 1;

    summary.high += toInt(row.risk_high);
    summary.medium += toInt(row.risk_medium);
    summary.low += toInt(row.risk_low);
    summary.info += toInt(row.risk_info);
    summary.alerts += toInt(row.alert_count);

    strategySet.add(String(row.strategy_name || ''));
    policySet.add(String(row.policy_name || ''));

    const alerts = parseJsonArray(row.alert_details_json);
    for (const alert of alerts) {
      const name = String(alert && alert.name ? alert.name : 'Unnamed alert');
      const risk = getRiskLabel(alert);
      const key = name + '|' + risk;
      alertNameCount.set(key, (alertNameCount.get(key) || 0) + 1);
    }
  }

  const topAlerts = Array.from(alertNameCount.entries())
    .map((entry) => {
      const parts = entry[0].split('|');
      return {
        name: parts[0],
        risk: parts[1] || 'info',
        count: entry[1]
      };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 15);

  const scannedValues = rows
    .map((r) => String(r.scanned_at || '').trim())
    .filter(Boolean)
    .sort();

  const lastScannedAt = scannedValues.length ? scannedValues[scannedValues.length - 1] : '';

  return {
    generatedAt: new Date().toISOString(),
    dbPath: config.dbPath,
    outPath: config.outPath,
    filters: {
      strategy: config.strategyName || '(all)',
      policy: config.policyName || '(all)'
    },
    summary,
    topAlerts,
    strategies: Array.from(strategySet).filter(Boolean).sort(),
    policies: Array.from(policySet).filter(Boolean).sort(),
    lastScannedAt,
    rows
  };
}

function riskClass(risk) {
  const r = String(risk || '').toLowerCase();
  if (r === 'high') return 'risk-high';
  if (r === 'medium') return 'risk-medium';
  if (r === 'low') return 'risk-low';
  return 'risk-info';
}

function rowStatusClass(status) {
  return String(status || '') === 'COMPLETE' ? 'status-complete' : 'status-failed';
}

function buildTopAlertsHtml(topAlerts) {
  if (!topAlerts.length) {
    return '<p class="muted">No alert details found in alert_details_json.</p>';
  }
  const items = topAlerts.map((a) => {
    return '<tr>' +
      '<td>' + escapeHtml(a.name) + '</td>' +
      '<td><span class="pill ' + riskClass(a.risk) + '">' + escapeHtml(a.risk.toUpperCase()) + '</span></td>' +
      '<td class="right">' + escapeHtml(a.count) + '</td>' +
      '</tr>';
  }).join('');
  return '<table><thead><tr><th>Alert</th><th>Risk</th><th class="right">Count</th></tr></thead><tbody>' + items + '</tbody></table>';
}

function buildRowsHtml(rows) {
  if (!rows.length) {
    return '<tr><td colspan="12" class="muted">No scan rows matched your filter.</td></tr>';
  }

  return rows.map((row) => {
    const alerts = parseJsonArray(row.alert_details_json);
    const topForRow = new Map();
    for (const alert of alerts) {
      const name = String(alert && alert.name ? alert.name : 'Unnamed alert');
      topForRow.set(name, (topForRow.get(name) || 0) + 1);
    }
    const topSummary = Array.from(topForRow.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map((x) => x[0] + ' x' + x[1])
      .join(', ');

    const method = String(row.http_method || '').toUpperCase();
    const endpoint = String(row.endpoint_path || '');
    const error = row.error_message ? escapeHtml(row.error_message) : '';
    const opId = row.operation_id ? escapeHtml(row.operation_id) : '';
    const detailsPreview = topSummary ? escapeHtml(topSummary) : '';
    const scannedAt = row.scanned_at ? escapeHtml(row.scanned_at) : '';

    return '<tr>' +
      '<td>' + escapeHtml(row.strategy_name) + '</td>' +
      '<td>' + escapeHtml(row.policy_name) + '</td>' +
      '<td><span class="pill method">' + escapeHtml(method) + '</span> ' + escapeHtml(endpoint) + '</td>' +
      '<td><span class="pill ' + rowStatusClass(row.status) + '">' + escapeHtml(row.status) + '</span></td>' +
      '<td class="right">' + escapeHtml(toInt(row.alert_count)) + '</td>' +
      '<td class="right">' + escapeHtml(toInt(row.risk_high)) + '</td>' +
      '<td class="right">' + escapeHtml(toInt(row.risk_medium)) + '</td>' +
      '<td class="right">' + escapeHtml(toInt(row.risk_low)) + '</td>' +
      '<td class="right">' + escapeHtml(toInt(row.risk_info)) + '</td>' +
      '<td>' + opId + '</td>' +
      '<td>' + detailsPreview + '</td>' +
      '<td>' + (error || scannedAt) + '</td>' +
      '</tr>';
  }).join('');
}

function escapeCsv(value) {
  const str = String(value == null ? '' : value);
  if (/[",\r\n]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

function buildAlertsCsv(rows) {
  const header = ['baseUrl', 'endpoint', 'method', 'strategy', 'policy', 'Alert', 'Severity'];
  const lines = [header.join(',')];

  for (const row of rows) {
    const baseUrl = String(row.base_url || '');
    const endpoint = String(row.endpoint_path || '');
    const method = String(row.http_method || '').toUpperCase();
    const strategy = String(row.strategy_name || '');
    const policy = String(row.policy_name || '');

    const alerts = parseJsonArray(row.alert_details_json);
    for (const alert of alerts) {
      const name = String(alert && alert.name ? alert.name : 'Unnamed alert');
      const severity = getRiskLabel(alert).toUpperCase();
      lines.push([
        escapeCsv(baseUrl),
        escapeCsv(endpoint),
        escapeCsv(method),
        escapeCsv(strategy),
        escapeCsv(policy),
        escapeCsv(name),
        escapeCsv(severity)
      ].join(','));
    }
  }

  return lines.join('\r\n') + '\r\n';
}

function buildCoverageCsv(rows) {
  const header = ['baseUrl', 'endpoint', 'method', 'strategy', 'policy', 'scan_status'];
  const lines = [header.join(',')];

  for (const row of rows) {
    lines.push([
      escapeCsv(String(row.base_url || '')),
      escapeCsv(String(row.endpoint_path || '')),
      escapeCsv(String(row.http_method || '').toUpperCase()),
      escapeCsv(String(row.strategy_name || '')),
      escapeCsv(String(row.policy_name || '')),
      escapeCsv(String(row.status || ''))
    ].join(','));
  }

  return lines.join('\r\n') + '\r\n';
}

function buildHtml(model) {
  const s = model.summary;
  const rowsHtml = buildRowsHtml(model.rows);
  const topAlertsHtml = buildTopAlertsHtml(model.topAlerts);

  return [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '  <meta charset="utf-8">',
    '  <meta name="viewport" content="width=device-width, initial-scale=1">',
    '  <title>ZAP DB Report</title>',
    '  <style>',
    '    :root {',
    '      --bg: #f7f8fb;',
    '      --card: #ffffff;',
    '      --ink: #1a1d29;',
    '      --muted: #60677a;',
    '      --line: #e2e5ec;',
    '      --high: #b42318;',
    '      --medium: #b54708;',
    '      --low: #175cd3;',
    '      --info: #667085;',
    '      --ok: #027a48;',
    '      --bad: #b42318;',
    '    }',
    '    * { box-sizing: border-box; }',
    '    body { margin: 0; font-family: Segoe UI, Arial, sans-serif; color: var(--ink); background: linear-gradient(180deg, #f1f4fb 0%, var(--bg) 220px); }',
    '    .wrap { max-width: 1200px; margin: 0 auto; padding: 24px; }',
    '    .card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 16px; margin-bottom: 16px; }',
    '    h1 { margin: 0 0 8px; font-size: 28px; }',
    '    h2 { margin: 0 0 12px; font-size: 20px; }',
    '    p { margin: 6px 0; }',
    '    .muted { color: var(--muted); }',
    '    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }',
    '    .kpi { border: 1px solid var(--line); border-radius: 10px; padding: 12px; background: #fcfdff; }',
    '    .kpi .label { color: var(--muted); font-size: 12px; }',
    '    .kpi .value { font-size: 24px; font-weight: 700; margin-top: 4px; }',
    '    table { width: 100%; border-collapse: collapse; }',
    '    th, td { border-bottom: 1px solid var(--line); text-align: left; padding: 8px; vertical-align: top; font-size: 13px; }',
    '    th { background: #fafbff; position: sticky; top: 0; }',
    '    .right { text-align: right; }',
    '    .pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; letter-spacing: 0.2px; }',
    '    .method { background: #e9f2ff; color: #1849a9; }',
    '    .risk-high { background: #fee4e2; color: var(--high); }',
    '    .risk-medium { background: #ffead5; color: var(--medium); }',
    '    .risk-low { background: #dbeafe; color: var(--low); }',
    '    .risk-info { background: #eceff3; color: var(--info); }',
    '    .status-complete { background: #dcfae6; color: var(--ok); }',
    '    .status-failed { background: #fee4e2; color: var(--bad); }',
    '    .meta { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }',
    '    @media (max-width: 900px) {',
    '      .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }',
    '      .meta { grid-template-columns: 1fr; }',
    '    }',
    '    @media (max-width: 640px) {',
    '      .grid { grid-template-columns: 1fr; }',
    '      th, td { font-size: 12px; padding: 6px; }',
    '    }',
    '  </style>',
    '</head>',
    '<body>',
    '  <div class="wrap">',
    '    <div class="card">',
    '      <h1>ZAP Scan Database Report</h1>',
    '      <p class="muted">Generated at: ' + escapeHtml(model.generatedAt) + '</p>',
    '      <p class="muted">DB: ' + escapeHtml(model.dbPath) + '</p>',
    '      <p class="muted">Filters: strategy=' + escapeHtml(model.filters.strategy) + ', policy=' + escapeHtml(model.filters.policy) + '</p>',
    '    </div>',
    '    <div class="card">',
    '      <div class="grid">',
    '        <div class="kpi"><div class="label">Endpoints</div><div class="value">' + escapeHtml(s.totalEndpoints) + '</div></div>',
    '        <div class="kpi"><div class="label">Complete</div><div class="value">' + escapeHtml(s.complete) + '</div></div>',
    '        <div class="kpi"><div class="label">Failed</div><div class="value">' + escapeHtml(s.failed) + '</div></div>',
    '        <div class="kpi"><div class="label">Total Alerts</div><div class="value">' + escapeHtml(s.alerts) + '</div></div>',
    '        <div class="kpi"><div class="label">High</div><div class="value">' + escapeHtml(s.high) + '</div></div>',
    '        <div class="kpi"><div class="label">Medium</div><div class="value">' + escapeHtml(s.medium) + '</div></div>',
    '        <div class="kpi"><div class="label">Low</div><div class="value">' + escapeHtml(s.low) + '</div></div>',
    '        <div class="kpi"><div class="label">Info</div><div class="value">' + escapeHtml(s.info) + '</div></div>',
    '      </div>',
    '      <div class="meta" style="margin-top: 12px;">',
    '        <p class="muted">Strategies: ' + escapeHtml(model.strategies.join(', ') || 'none') + '</p>',
    '        <p class="muted">Policies: ' + escapeHtml(model.policies.join(', ') || 'none') + '</p>',
    '        <p class="muted">Last scanned at: ' + escapeHtml(model.lastScannedAt || 'n/a') + '</p>',
    '      </div>',
    '    </div>',
    '    <div class="card">',
    '      <h2>Top Alerts</h2>',
    '      ' + topAlertsHtml,
    '    </div>',
    '    <div class="card">',
    '      <h2>Endpoint Results</h2>',
    '      <div style="overflow:auto; max-height: 70vh;">',
    '        <table>',
    '          <thead>',
    '            <tr>',
    '              <th>Strategy</th>',
    '              <th>Policy</th>',
    '              <th>Endpoint</th>',
    '              <th>Status</th>',
    '              <th class="right">Alerts</th>',
    '              <th class="right">High</th>',
    '              <th class="right">Medium</th>',
    '              <th class="right">Low</th>',
    '              <th class="right">Info</th>',
    '              <th>Operation ID</th>',
    '              <th>Top Endpoint Alerts</th>',
    '              <th>Error or Scanned At</th>',
    '            </tr>',
    '          </thead>',
    '          <tbody>',
    '            ' + rowsHtml,
    '          </tbody>',
    '        </table>',
    '      </div>',
    '    </div>',
    '  </div>',
    '</body>',
    '</html>'
  ].join('\n');
}

async function loadRows(db, strategyName, policyName) {
  const sql = [
    'SELECT',
    '  strategy_name,',
    '  endpoint_key,',
    '  base_url,',
    '  host,',
    '  port,',
    '  endpoint_path,',
    '  http_method,',
    '  policy_name,',
    '  operation_id,',
    '  status,',
    '  alert_count,',
    '  risk_high,',
    '  risk_medium,',
    '  risk_low,',
    '  risk_info,',
    '  error_message,',
    '  alert_details_json,',
    '  scanned_at,',
    '  created_at,',
    '  updated_at',
    'FROM zap_test_status',
    'WHERE (? = "" OR strategy_name = ?)',
    '  AND (? = "" OR policy_name = ?)',
    'ORDER BY datetime(scanned_at) DESC, endpoint_path, http_method'
  ].join('\n');

  return dbAll(db, sql, [
    strategyName || '',
    strategyName || '',
    policyName || '',
    policyName || ''
  ]);
}

async function main() {
  const config = parseArgs(process.argv.slice(2));

  if (!fs.existsSync(config.dbPath)) {
    throw new Error('Database file not found: ' + config.dbPath);
  }

  const db = openDatabase(config.dbPath);

  try {
    const rows = await loadRows(db, config.strategyName, config.policyName);
    const model = buildReportModel(rows, config);
    const html = buildHtml(model);
    fs.writeFileSync(config.outPath, html, 'utf8');
    console.log('Report written: ' + config.outPath);
    const csv = buildAlertsCsv(rows);
    fs.writeFileSync(config.csvPath, csv, 'utf8');
    console.log('CSV written: ' + config.csvPath);
    const coverageCsv = buildCoverageCsv(rows);
    fs.writeFileSync(config.coverageCsvPath, coverageCsv, 'utf8');
    console.log('Coverage CSV written: ' + config.coverageCsvPath);
    console.log('Rows included: ' + rows.length);
  } finally {
    await closeDatabase(db);
  }
}

main().catch((error) => {
  console.error('Report generation failed: ' + String(error && error.message ? error.message : error));
  process.exitCode = 1;
});
