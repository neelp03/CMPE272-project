'use strict';

// VULN-06 — IDOR: any authenticated (or even unauthenticated) user
//           can fetch any user record by ID (CWE-639)
// VULN-07 — Sensitive data exposure: password field returned in responses (CWE-312)

const express = require('express');
const jwt     = require('jsonwebtoken');
const router  = express.Router();
const db      = require('../db');
const { JWT_SECRET } = require('../config');

// Weak auth middleware — only checks token validity, never ownership
function optionalAuth(req, _res, next) {
  const header = req.headers.authorization || '';
  const token  = header.replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
  } catch (_) {
    req.user = null; // unauthenticated requests still proceed
  }
  next();
}

// GET /api/users/:id
// VULN-06: No check that req.user.id === req.params.id
//          → any caller can read any user's data (including admin)
// VULN-07: The full row is returned, including the plaintext password column
router.get('/:id', optionalAuth, (req, res) => {
  const { id } = req.params;

  db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
    if (err)   return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: 'User not found' });

    // ⚠ VULN-07: returns password in plaintext — should at minimum omit the field
    res.json(user);
  });
});

// GET /api/users
// VULN-07: lists ALL users including their plaintext passwords
router.get('/', optionalAuth, (req, res) => {
  db.all('SELECT * FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    // ⚠ No pagination, no field filtering — dumps everything
    res.json(rows);
  });
});

// GET /api/users/:id/orders
// VULN-06: fetches another user's order history without ownership check
router.get('/:id/orders', optionalAuth, (req, res) => {
  const { id } = req.params;
  db.all(
    'SELECT * FROM orders WHERE user_id = ?',
    [id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

module.exports = router;
