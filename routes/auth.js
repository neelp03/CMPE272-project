'use strict';

// VULN-04 — SQL Injection in login (CWE-89)
// VULN-05 — Error response leaks the full SQL query (CWE-209)

const express = require('express');
const jwt     = require('jsonwebtoken');
const router  = express.Router();
const db      = require('../db');
const { JWT_SECRET } = require('../config');

// POST /api/auth/login
// VULN-04: username and password are interpolated directly into the SQL string.
// Sending username = admin'-- bypasses password verification entirely.
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' });
  }

  // ⚠ VULNERABLE: string concatenation instead of parameterised query
  const sql = `SELECT * FROM users
               WHERE username = '${username}'
                 AND password = '${password}'`;

  db.get(sql, (err, user) => {
    if (err) {
      // VULN-05: full query (including injected payload) returned to the client
      return res.status(500).json({ error: err.message, query: sql });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // VULN-01 (from config.js): JWT_SECRET = 'supersecret123'
    // No expiry set → tokens live forever
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET
    );

    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  });
});

// POST /api/auth/register
// Also vulnerable to SQL injection (same pattern)
router.post('/register', (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: 'username, password, and email required' });
  }

  // ⚠ VULNERABLE: string interpolation
  const sql = `INSERT INTO users (username, password, email)
               VALUES ('${username}', '${password}', '${email}')`;

  db.run(sql, function (err) {
    if (err) {
      return res.status(500).json({ error: err.message, query: sql }); // VULN-05
    }
    res.status(201).json({ message: 'User created', id: this.lastID });
  });
});

module.exports = router;
