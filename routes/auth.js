'use strict';

const express      = require('express');
const jwt          = require('jsonwebtoken');
const rateLimit    = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const router       = express.Router();
const db           = require('../db');
const { JWT_SECRET, JWT_EXPIRY } = require('../config');

// FIX for VULN-08: rate-limit login to 10 attempts per 15 minutes
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// POST /api/auth/login
router.post(
  '/login',
  loginLimiter,
  [
    body('username').isString().trim().notEmpty(),
    body('password').isString().notEmpty(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Invalid input' });
    }

    const { username, password } = req.body;

    // FIX for VULN-04: bcrypt compare via secure db method — no SQL involved
    // FIX for VULN-05: errors never expose query text
    db.getUserByCredentials(username, password, (err, user) => {
      if (err) return res.status(500).json({ error: 'Internal server error' });
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });

      // FIX for VULN-01: secret from env; FIX for missing expiry: expiresIn set
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRY }
      );

      res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
    });
  }
);

// POST /api/auth/register
router.post(
  '/register',
  [
    body('username').isString().trim().isLength({ min: 3, max: 32 }),
    body('password').isString().isLength({ min: 8 }),
    body('email').isEmail().normalizeEmail(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Invalid input', details: errors.array() });
    }

    const { username, password, email } = req.body;

    // FIX for VULN-03 (plaintext storage): bcrypt hash handled inside db.createUser
    db.createUser(username, password, email, (err, id) => {
      if (err) {
        if (err.message === 'Username already taken') {
          return res.status(409).json({ error: err.message });
        }
        return res.status(500).json({ error: 'Internal server error' });
      }
      res.status(201).json({ message: 'User created', id });
    });
  }
);

module.exports = router;
