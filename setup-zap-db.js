const path = require('node:path');
const sqlite3 = require('sqlite3');

const defaults = {
  dbPath: 'dast.db'
};

function resolvePath(filePath) {
  return path.isAbsolute(filePath) ? filePath : path.resolve(__dirname, filePath);
}

function parseArgs(argv) {
  const config = {
    dbPath: String(process.env.DAST_DB_PATH || defaults.dbPath).trim() || defaults.dbPath
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--db') {
      config.dbPath = String(argv[index + 1] || '').trim() || defaults.dbPath;
      index += 1;
      continue;
    }
    if (arg === '--help') {
      console.log('Usage: node setup-zap-db.js [--db <path>]');
      process.exit(0);
    }
    throw new Error(`Unknown argument: ${arg}`);
  }

  config.dbPath = resolvePath(config.dbPath);
  return config;
}

function openDatabase(dbPath) {
  return new sqlite3.Database(dbPath);
}

function run(db, sql) {
  return new Promise((resolve, reject) => {
    db.run(sql, (error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
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

async function main() {
  const config = parseArgs(process.argv.slice(2));
  const db = openDatabase(config.dbPath);

  try {
    await run(
      db,
      `CREATE TABLE IF NOT EXISTS zap_test_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        strategy_name TEXT NOT NULL,
        endpoint_key TEXT NOT NULL,
        base_url TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        endpoint_path TEXT NOT NULL,
        http_method TEXT NOT NULL,
        policy_name TEXT NOT NULL,
        operation_id TEXT,
        status TEXT NOT NULL CHECK(status IN ('COMPLETE', 'FAILED')),
        alert_count INTEGER NOT NULL DEFAULT 0,
        risk_high INTEGER NOT NULL DEFAULT 0,
        risk_medium INTEGER NOT NULL DEFAULT 0,
        risk_low INTEGER NOT NULL DEFAULT 0,
        risk_info INTEGER NOT NULL DEFAULT 0,
        error_message TEXT,
        alert_details_json TEXT,
        scanned_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(strategy_name, endpoint_key)
      )`
    );

    await run(
      db,
      'CREATE INDEX IF NOT EXISTS idx_zap_test_status_lookup ON zap_test_status(strategy_name, endpoint_key)'
    );

    await run(
      db,
      'CREATE INDEX IF NOT EXISTS idx_zap_test_status_status ON zap_test_status(strategy_name, status)'
    );

    console.log(`SQLite setup complete: ${config.dbPath}`);
  } finally {
    await closeDatabase(db);
  }
}

main().catch((error) => {
  console.error(`DB setup failed: ${error.message}`);
  process.exitCode = 1;
});
