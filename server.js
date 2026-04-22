'use strict';

require('dotenv').config();

const express    = require('express');
const helmet     = require('helmet');
const cors       = require('cors');
const bodyParser = require('body-parser');
const { PORT }   = require('./config');

const app = express();

// FIX for VULN-13: helmet adds secure HTTP headers
// Additional directives address ZAP findings: CSP fallback, Permissions-Policy
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'"],
      styleSrc:       ["'self'"],
      imgSrc:         ["'self'"],
      connectSrc:     ["'self'"],
      fontSrc:        ["'self'"],
      objectSrc:      ["'none'"],
      frameAncestors: ["'none'"],
      formAction:     ["'self'"],
      baseUri:        ["'self'"],
    },
  },
  permissionsPolicy: {
    features: {
      camera:      [],
      microphone:  [],
      geolocation: [],
      payment:     [],
    },
  },
}));

// No-cache for all API responses (ZAP: Storable and Cacheable Content)
app.use((_req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

// FIX for VULN-03: explicit CORS allowlist (no wildcard, no credentials leak)
const ALLOWED_ORIGINS = new Set((process.env.CORS_ORIGINS || 'http://localhost:5173').split(','));
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.has(origin)) return cb(null, true);
    cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));

app.use(bodyParser.json({ limit: '10kb' }));
app.use(bodyParser.urlencoded({ extended: false, limit: '10kb' }));

// Routes
app.use('/api/auth',     require('./routes/auth'));
app.use('/api/users',    require('./routes/users'));
app.use('/api/products', require('./routes/products'));
app.use('/api/files',    require('./routes/files'));
app.use('/api/admin',    require('./routes/admin'));

// Health check
app.get('/health', (_req, res) => res.json({ status: 'ok' }));
app.get('/',       (_req, res) => res.json({
  message: 'Fixed API — DevSecOps Demo',
  version: '2.0.0',
}));

// FIX for stack trace leakage: generic error handler, no internals exposed
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => console.log(`[app-fixed] listening on port ${PORT}`));
module.exports = app;
