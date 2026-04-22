'use strict';

const express = require('express');
const { body, query, validationResult } = require('express-validator');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const router  = express.Router();
const db      = require('../db');

// FIX for VULN-09: sanitise HTML before storage / output
const window    = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

function sanitize(str) {
  return DOMPurify.sanitize(str || '', { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
}

// GET /api/products/search?q=<term>
// FIX for VULN-08: term passed to a safe array-search, no SQL used
router.get(
  '/search',
  [query('q').optional().isString().trim().isLength({ max: 200 })],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Invalid query' });

    const q = req.query.q || '';
    db.searchProducts(q, (err, rows) => {
      if (err) return res.status(500).json({ error: 'Internal server error' });
      // FIX for VULN-09 (reflected): q is never echoed back raw
      res.json({ results: rows });
    });
  }
);

// GET /api/products
router.get('/', (_req, res) => {
  db.getAllProducts((err, rows) => {
    if (err) return res.status(500).json({ error: 'Internal server error' });
    res.json(rows);
  });
});

// GET /api/products/:id
router.get('/:id', (req, res) => {
  db.getProductById(req.params.id, (err, row) => {
    if (err)  return res.status(500).json({ error: 'Internal server error' });
    if (!row) return res.status(404).json({ error: 'Product not found' });
    res.json(row);
  });
});

// POST /api/products
// FIX for VULN-09: description is sanitised before storage
router.post(
  '/',
  [
    body('name').isString().trim().notEmpty().isLength({ max: 200 }),
    body('price').isFloat({ min: 0 }),
    body('description').optional().isString().isLength({ max: 2000 }),
    body('stock').optional().isInt({ min: 0 }),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Invalid input', details: errors.array() });

    const { name, price, stock = 0 } = req.body;
    const description = sanitize(req.body.description || '');

    db.createProduct(name, parseFloat(price), description, parseInt(stock, 10), (err, id) => {
      if (err) return res.status(500).json({ error: 'Internal server error' });
      res.status(201).json({ id, name, price, description, stock });
    });
  }
);

// PUT /api/products/:id
router.put(
  '/:id',
  [
    body('name').isString().trim().notEmpty().isLength({ max: 200 }),
    body('price').isFloat({ min: 0 }),
    body('description').optional().isString().isLength({ max: 2000 }),
    body('stock').optional().isInt({ min: 0 }),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Invalid input', details: errors.array() });

    const { name, price, stock } = req.body;
    const description = sanitize(req.body.description || '');
    const { id } = req.params;

    db.updateProduct(id, name, parseFloat(price), description, parseInt(stock, 10), (err, changes) => {
      if (err) return res.status(500).json({ error: 'Internal server error' });
      res.json({ updated: changes });
    });
  }
);

module.exports = router;
