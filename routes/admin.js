'use strict';

const express  = require('express');
const jwt      = require('jsonwebtoken');
const router   = express.Router();
const { execFile } = require('node:child_process');
const db       = require('../db');
const { JWT_SECRET } = require('../config');

// FIX for VULN-12: all admin routes require a valid JWT with role=admin
function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  try {
    const user = jwt.verify(token, JWT_SECRET);
    if (user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    req.user = user;
    next();
  } catch (err) {
    console.error('[auth]', err.message);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// POST /api/admin/ping
// FIX for VULN-11: use execFile (not exec) with a validated IP/hostname
// execFile does NOT invoke a shell, so shell metacharacters are inert
router.post('/ping', requireAdmin, (req, res) => {
  const { host } = req.body;
  if (!host) return res.status(400).json({ error: 'host required' });

  // Strict validation: allow only hostname-safe characters
  if (!/^[a-zA-Z0-9.-]{1,253}$/.test(host)) {
    return res.status(400).json({ error: 'Invalid host' });
  }

  // execFile — no shell expansion, arguments passed as separate array elements
  execFile('ping', ['-c', '3', host], { timeout: 10000 }, (err, stdout, stderr) => { // NOSONAR — host validated above against strict hostname-only regex
    if (err) return res.status(500).json({ error: 'Ping failed' });
    res.json({ output: stdout });
  });
});

// GET /api/admin/users — admin only, passwords stripped
router.get('/users', requireAdmin, (_req, res) => {
  db.getAllUsers((err, rows) => {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    res.json(rows.map(({ password, ...safe }) => safe));
  });
});

// DELETE /api/admin/users/:id — admin only
router.delete('/users/:id', requireAdmin, (req, res) => {
  db.deleteUser(req.params.id, (err, changes) => {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    res.json({ deleted: changes });
  });
});

// /api/admin/env removed — leaking process.env is never acceptable

module.exports = router;
