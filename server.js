const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// VULNERABILITY 9: Missing/Insecure CORS Configuration
// Permissive wildcard origin so ZAP's "Cross-Domain Misconfiguration" passive rule flags it.
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  next();
});

// Initialize SQLite database
const db = new sqlite3.Database(':memory:');

// Create users table and insert sample data
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    email TEXT,
    role TEXT
  )`);

  db.run(`INSERT INTO users (username, password, email, role) VALUES 
    ('admin', 'admin123', 'admin@example.com', 'admin'),
    ('user1', 'password123', 'user1@example.com', 'user'),
    ('user2', 'qwerty', 'user2@example.com', 'user')`);
});

// VULNERABILITY 1: SQL Injection
app.post('/api/user', (req, res) => {
  const username = req.body.username;
  
  // Vulnerable: Direct string concatenation in SQL query
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  
  db.all(query, [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ users: rows });
  });
});

// VULNERABILITY 2: Command Injection (SAFE SIMULATION)
// Never spawns a shell. Detects OS command-injection fuzzing payloads and
// echoes the leaked-output signatures ZAP looks for, so it is flagged without
// executing anything on the host.
app.post('/api/ping', (req, res) => {
  const host = String(req.body.host || '');
  const injectionPattern = /[;&|`]|\$\(|\|\||&&|\b(sleep|timeout|cat|type|id|whoami|dir|ls)\b/i;

  let output = `Pinging ${host} with 32 bytes of data:\nReply from 127.0.0.1: bytes=32 time=1ms TTL=64`;

  if (injectionPattern.test(host)) {
    // Emulated command output only — nothing is actually executed.
    output += '\nuid=0(root) gid=0(root) groups=0(root)';
    output += '\nroot:x:0:0:root:/root:/bin/bash';
    output += '\n[fonts]';
  }

  res.type('text/plain').send(output);
});

// VULNERABILITY 3: Missing Authentication
app.post('/api/admin/users', (req, res) => {
  // Vulnerable: No authentication check
  db.all('SELECT * FROM users', [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ users: rows });
  });
});

// VULNERABILITY 4: Insecure Direct Object Reference (IDOR)
app.post('/api/user/id', (req, res) => {
  const userId = req.body.id;
  
  // Vulnerable: No authorization check
  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, row) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ user: row });
  });
});

// VULNERABILITY 5: Cross-Site Scripting (XSS)
app.post('/api/search', (req, res) => {
  const searchTerm = req.body.q;
  
  // Vulnerable: Reflecting user input without sanitization
  res.send(`
    <html>
      <head><title>Search Results</title></head>
      <body>
        <h1>Search Results for: ${searchTerm}</h1>
        <p>No results found</p>
      </body>
    </html>
  `);
});

// VULNERABILITY 6: Sensitive Data Exposure
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ? AND password = ?', 
    [username, password], 
    (err, row) => {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      
      if (row) {
        // Vulnerable: Exposing sensitive data in response
        res.json({ 
          success: true, 
          message: 'Login successful',
          user: row // Exposes password and other sensitive info
        });
      } else {
        // Vulnerable: Information disclosure
        res.json({ 
          success: false, 
          message: 'Invalid username or password' 
        });
      }
    });
});

// VULNERABILITY 7: Missing Rate Limiting
app.post('/api/reset-password', (req, res) => {
  const { email } = req.body;
  
  // Vulnerable: No rate limiting, can be brute-forced
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    
    if (row) {
      res.json({ message: 'Password reset link sent to email' });
    } else {
      res.json({ message: 'Email not found' });
    }
  });
});

// VULNERABILITY 8: Weak Password Policy
app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body;
  
  // Vulnerable: No password strength validation
  db.run('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
    [username, password, email, 'user'],
    function(err) {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }
      res.json({ 
        success: true, 
        message: 'User registered',
        userId: this.lastID 
      });
    });
});

// VULNERABILITY 10: Directory Traversal / Path Traversal (SAFE SIMULATION)
// Never touches the filesystem. Detects traversal fuzzing payloads and returns
// canned file signatures ZAP's Path Traversal rule recognizes, without exposing
// any real file on disk.
app.post('/api/file', (req, res) => {
  const name = String(req.body.name || '');
  const traversalPattern = /\.\.[\\/]|%2e%2e|\/etc\/passwd|\bwin\.ini\b|\bboot\.ini\b|\\windows\\|%00/i;

  if (traversalPattern.test(name)) {
    if (/win\.ini|boot\.ini|\\windows\\|system32/i.test(name)) {
      res.type('text/plain').send('[fonts]\n[extensions]\n[mci extensions]\n[files]');
      return;
    }
    res.type('text/plain').send('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin');
    return;
  }

  res.status(404).json({ error: 'File not found' });
});

// NEW: Header-protected endpoint to exercise the scanner's --header injection
// and 401 error-response logging. Requires the X-API-Key request header:
// missing/invalid key -> 401 (logged by the scanner); valid key -> 200 data.
app.post('/api/secure-data', (req, res) => {
  const apiKey = req.get('X-API-Key');

  if (apiKey !== 'secret123') {
    res.status(401).json({ error: 'Unauthorized: missing or invalid X-API-Key header' });
    return;
  }

  db.all('SELECT id, username, email, role FROM users', [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({ data: rows });
  });
});

// Root endpoint - Serve HTML page
app.get('/', (req, res) => {
  const fs = require('fs');
  const path = require('path');
  const htmlPath = path.join(__dirname, 'index.html');
  
  fs.readFile(htmlPath, 'utf8', (err, data) => {
    if (err) {
      res.json({
        message: 'Vulnerable API Demo - For Testing Only!',
        endpoints: [
          'POST /api/user (SQL Injection)',
          'POST /api/ping (Command Injection)',
          'POST /api/admin/users (Missing Authentication)',
          'POST /api/user/id (IDOR)',
          'POST /api/search (XSS)',
          'POST /api/login (Sensitive Data Exposure)',
          'POST /api/reset-password (No Rate Limiting)',
          'POST /api/register (Weak Password Policy)',
          'POST /api/file (Directory Traversal)',
          'POST /api/secure-data (Requires X-API-Key header; 401 without it)'
        ],
        openapi: 'OpenAPI spec available at /openapi.json'
      });
      return;
    }
    res.send(data);
  });
});

// Serve OpenAPI specification
app.get('/openapi.json', (req, res) => {
  const fs = require('fs');
  const path = require('path');
  const openapiPath = path.join(__dirname, 'openapi.json');
  
  fs.readFile(openapiPath, 'utf8', (err, data) => {
    if (err) {
      res.status(500).json({ error: 'OpenAPI spec not found' });
      return;
    }
    res.setHeader('Content-Type', 'application/json');
    res.send(data);
  });
});

app.listen(PORT, () => {
  console.log(`⚠️  VULNERABLE API SERVER RUNNING ON PORT ${PORT}`);
  console.log(`⚠️  WARNING: This server contains intentional vulnerabilities!`);
  console.log(`⚠️  Use for testing purposes only in isolated environments!`);
  console.log(`\nAccess the API at: http://localhost:${PORT}`);
});
