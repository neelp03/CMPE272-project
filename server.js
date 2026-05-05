'use strict';

// ═══════════════════════════════════════════════════════════════
//  Intentionally Vulnerable Express API — DevSecOps Demo
//  !!  FOR EDUCATIONAL PURPOSES ONLY !!
//
//  Vulnerability index (13 total):
//   VULN-01  Hardcoded JWT secret                   config.js:8
//   VULN-02  Hardcoded credentials & cloud keys     config.js:11-16
//   VULN-03  Insecure CORS (all origins + creds)    server.js:27
//   VULN-04  SQL injection — login                  routes/auth.js:22
//   VULN-05  SQL error leaks full query             routes/auth.js:27
//   VULN-06  IDOR — no ownership check on /users/:id routes/users.js:18
//   VULN-07  Sensitive data exposure (passwords)    routes/users.js:9
//   VULN-08  SQL injection — product search         routes/products.js:14
//   VULN-09  Stored XSS — unescaped HTML in desc    routes/products.js:32
//   VULN-10  Path traversal — arbitrary file read   routes/files.js:14
//   VULN-11  Command injection — ping utility       routes/admin.js:18
//   VULN-12  Missing auth on admin endpoints        routes/admin.js:6
//   VULN-13  Insecure Dockerfile (EOL image, root)  Dockerfile
// ═══════════════════════════════════════════════════════════════

const express    = require('express');
const cors       = require('cors');
const bodyParser = require('body-parser');

const app = express();

// VULN-03: Wildcard CORS with credentials — allows any origin to make
// credentialed requests, defeating Same-Origin Policy protections.
app.use(cors({ origin: '*', credentials: true }));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Mount route handlers
app.use('/api/auth',     require('./routes/auth'));
app.use('/api/users',    require('./routes/users'));
app.use('/api/products', require('./routes/products'));
app.use('/api/files',    require('./routes/files'));
app.use('/api/admin',    require('./routes/admin'));

// Health / root
app.get('/health', (_req, res) => res.json({ status: 'ok' }));
app.get('/',       (_req, res) => res.json({
  message: 'Vulnerable API — DevSecOps Demo',
  version: '1.0.0',
  endpoints: ['/api/auth', '/api/users', '/api/products', '/api/files', '/api/admin'],
}));

const { PORT } = require('./config');
app.listen(PORT, () => console.log(`[server] listening on http://localhost:${PORT}`));

module.exports = app;
