'use strict';

// All secrets loaded from environment variables.
// Copy .env.example → .env and fill in real values before running locally.

module.exports = {
  PORT:       process.env.PORT       || 3000,
  JWT_SECRET: process.env.JWT_SECRET || (() => { throw new Error('JWT_SECRET env var is required'); })(),
  JWT_EXPIRY: process.env.JWT_EXPIRY || '1h',
};
