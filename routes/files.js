'use strict';

// VULN-10 — Path Traversal: arbitrary file read via directory escape (CWE-22)

const express = require('express');
const router  = express.Router();
const fs      = require('fs');
const path    = require('path');

const FILES_DIR = path.join(__dirname, '..', 'public');

// GET /api/files?name=<filename>
// VULN-10: `name` is joined directly without path normalisation or containment check.
// Attack:  GET /api/files?name=../../etc/passwd
//          GET /api/files?name=../../config.js      (leaks hardcoded secrets)
//          GET /api/files?name=../../.env
router.get('/', (req, res) => {
  const { name } = req.query;
  if (!name) return res.status(400).json({ error: 'name parameter required' });

  // ⚠ VULNERABLE: no path.normalize / no startsWith(FILES_DIR) check
  const filePath = path.join(FILES_DIR, name);

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({
        error: 'File not found',
        attempted: filePath, // also leaks resolved path
      });
    }
    res.type('text/plain').send(data);
  });
});

// POST /api/files/upload
// VULN-10: writes user-supplied `filename` with no sanitisation
router.post('/upload', (req, res) => {
  const { filename, content } = req.body;
  if (!filename || !content) return res.status(400).json({ error: 'filename and content required' });

  // ⚠ VULNERABLE: attacker controls the destination path
  const dest = path.join(FILES_DIR, filename);

  fs.writeFile(dest, content, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'File saved', path: dest }); // also leaks abs path
  });
});

module.exports = router;
