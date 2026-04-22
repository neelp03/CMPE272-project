'use strict';

const express = require('express');
const jwt     = require('jsonwebtoken');
const router  = express.Router();
const db      = require('../db');
const { JWT_SECRET } = require('../config');

// FIX for VULN-06/VULN-07: authentication is now required and enforced
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Strip password from user object before sending
function safeUser(user) {
  if (!user) return null;
  const { password, ...safe } = user;
  return safe;
}

// GET /api/users/:id
// FIX for VULN-06: only the owner (or admin) can read a user record
// FIX for VULN-07: password field is stripped from the response
router.get('/:id', requireAuth, (req, res) => {
  const targetId = Number(req.params.id);
  if (req.user.id !== targetId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  db.getUserById(targetId, (err, user) => {
    if (err)   return res.status(500).json({ error: 'Internal server error' });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(safeUser(user));
  });
});

// GET /api/users — admin only
router.get('/', requireAuth, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  db.getAllUsers((err, rows) => {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    res.json(rows.map(safeUser));
  });
});

// GET /api/users/:id/orders — owner or admin only
router.get('/:id/orders', requireAuth, (req, res) => {
  const targetId = Number(req.params.id);
  if (req.user.id !== targetId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  db.getOrdersByUser(targetId, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    res.json(rows);
  });
});

module.exports = router;
