'use strict';

// VULN-08 — SQL Injection in product search (CWE-89)
// VULN-09 — Stored / Reflected XSS: HTML not sanitised before storage or output (CWE-79)

const express = require('express');
const router  = express.Router();
const db      = require('../db');

// GET /api/products/search?q=<term>
// VULN-08: query term injected directly into SQL
// Try: q=' OR '1'='1     → dumps all products
// Try: q=' UNION SELECT id,username,password,email,0 FROM users--
router.get('/search', (req, res) => {
  const { q = '' } = req.query;

  // ⚠ VULNERABLE: string interpolation in LIKE clause
  const sql = `SELECT * FROM products WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'`;

  db.all(sql, (err, rows) => {
    if (err) {
      // Also leaks the query on error (VULN-05 pattern)
      return res.status(500).json({ error: err.message, query: sql });
    }
    res.json({ results: rows, query: q }); // VULN-09 (reflected): q echoed in response
  });
});

// GET /api/products
router.get('/', (_req, res) => {
  db.all('SELECT * FROM products', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// GET /api/products/:id
router.get('/:id', (req, res) => {
  db.get('SELECT * FROM products WHERE id = ?', [req.params.id], (err, row) => {
    if (err)  return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'Product not found' });
    res.json(row);
  });
});

// POST /api/products
// VULN-09: description is stored as-is with no HTML sanitisation.
// A client that renders this field with innerHTML will execute injected scripts.
router.post('/', (req, res) => {
  const { name, price, description = '', stock = 0 } = req.body;
  if (!name || !price) return res.status(400).json({ error: 'name and price required' });

  // ⚠ VULNERABLE: no sanitisation of `description` — stored XSS
  db.run(
    `INSERT INTO products (name, price, description, stock) VALUES (?, ?, ?, ?)`,
    [name, price, description, stock],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.status(201).json({ id: this.lastID, name, price, description, stock });
    }
  );
});

// PUT /api/products/:id
// VULN-09 again: description update also unsanitised
router.put('/:id', (req, res) => {
  const { name, price, description, stock } = req.body;
  const { id } = req.params;

  // ⚠ VULNERABLE: no sanitisation
  db.run(
    `UPDATE products SET name=?, price=?, description=?, stock=? WHERE id=?`,
    [name, price, description, stock, id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ updated: this.changes });
    }
  );
});

module.exports = router;
