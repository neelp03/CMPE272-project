'use strict';

// VULN-11 — Command Injection via exec() with user-supplied input (CWE-78)
// VULN-12 — Missing authentication on admin endpoints (CWE-306)

const express = require('express');
const router  = express.Router();
const { exec } = require('child_process');
const db      = require('../db');

// ⚠ VULN-12: No authentication middleware on ANY of these admin routes.
// Anyone can call these endpoints without a token.

// POST /api/admin/ping
// VULN-11: `host` is passed directly to exec().
// Attack: host = "127.0.0.1; cat /etc/passwd"
//         host = "127.0.0.1 && rm -rf /tmp/*"
router.post('/ping', (req, res) => {
  const { host } = req.body;
  if (!host) return res.status(400).json({ error: 'host required' });

  // ⚠ VULNERABLE: shell interpolation allows arbitrary command execution
  exec(`ping -c 3 ${host}`, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: err.message, stderr });
    }
    res.json({ output: stdout });
  });
});

// GET /api/admin/users — dump all users (VULN-12 + VULN-07)
router.get('/users', (_req, res) => {
  db.all('SELECT * FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows); // passwords included
  });
});

// DELETE /api/admin/users/:id — delete any user without auth (VULN-12)
router.delete('/users/:id', (req, res) => {
  db.run('DELETE FROM users WHERE id = ?', [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes });
  });
});

// GET /api/admin/env — leaks all environment variables (VULN-12)
router.get('/env', (_req, res) => {
  res.json(process.env);
});

module.exports = router;
