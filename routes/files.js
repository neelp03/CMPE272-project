'use strict';

const express = require('express');
const router  = express.Router();
const fs      = require('node:fs');
const path    = require('node:path');

const FILES_DIR = path.resolve(__dirname, '..', 'public');

// Allowlist of permitted filenames (no directories, no path components)
const ALLOWED_FILES = new Set(['sample.txt', 'readme.txt', 'products.json']);

// GET /api/files?name=<filename>
// FIX for VULN-10: strict whitelist — only files explicitly listed above are served
router.get('/', (req, res) => {
  const { name } = req.query;
  if (!name) return res.status(400).json({ error: 'name parameter required' });

  // Reject anything that looks like a path traversal attempt
  if (name.includes('/') || name.includes('\\') || name.includes('..')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  if (!ALLOWED_FILES.has(name)) {
    return res.status(404).json({ error: 'File not found' });
  }

  // Extra containment check even after whitelist
  const filePath = path.resolve(FILES_DIR, name);
  if (!filePath.startsWith(FILES_DIR + path.sep) && filePath !== FILES_DIR) {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).json({ error: 'File not found' });
    res.type('text/plain').send(data);
  });
});

// POST /api/files/upload — disabled in the fixed version
router.post('/upload', (_req, res) => {
  res.status(403).json({ error: 'File upload is disabled' });
});

module.exports = router;
