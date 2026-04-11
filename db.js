'use strict';

// In-memory SQLite database seeded with sample data.
// Plaintext passwords are intentional (VULN-07).

const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database(':memory:', (err) => {
  if (err) { console.error('[db] open error:', err.message); process.exit(1); }
  console.log('[db] in-memory SQLite ready');
});

db.serialize(() => {
  db.run(`CREATE TABLE users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT    UNIQUE NOT NULL,
    password TEXT    NOT NULL,
    email    TEXT    NOT NULL,
    role     TEXT    DEFAULT 'user',
    balance  REAL    DEFAULT 0
  )`);

  // VULN-07 seed: passwords stored in plaintext
  const insertUser = db.prepare(
    `INSERT INTO users (username, password, email, role, balance) VALUES (?,?,?,?,?)`
  );
  [
    ['admin', 'admin123',    'admin@shopvuln.local',  'admin', 9999.99],
    ['alice', 'password1',   'alice@example.com',     'user',    150.00],
    ['bob',   'ilovecats42', 'bob@example.com',       'user',     75.50],
    ['carol', 'qwerty123',   'carol@example.com',     'user',    200.00],
  ].forEach(row => insertUser.run(row));
  insertUser.finalize();

  db.run(`CREATE TABLE products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT  NOT NULL,
    price       REAL  NOT NULL,
    description TEXT,
    stock       INTEGER DEFAULT 0
  )`);

  const insertProduct = db.prepare(
    `INSERT INTO products (name, price, description, stock) VALUES (?,?,?,?)`
  );
  [
    ['Laptop Pro',          999.99, 'High-performance laptop for professionals',  10],
    ['Mechanical Keyboard',  89.99, 'RGB backlit mechanical keyboard',             50],
    ['USB Hub',              29.99, 'USB 3.0 7-port hub with power adapter',       30],
    ['Monitor Stand',        49.99, 'Adjustable ergonomic monitor riser',          20],
  ].forEach(row => insertProduct.run(row));
  insertProduct.finalize();

  db.run(`CREATE TABLE orders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity   INTEGER NOT NULL DEFAULT 1,
    total      REAL    NOT NULL,
    FOREIGN KEY(user_id)    REFERENCES users(id),
    FOREIGN KEY(product_id) REFERENCES products(id)
  )`);

  db.run(`INSERT INTO orders (user_id, product_id, quantity, total)
          VALUES (2, 1, 1, 999.99), (3, 2, 2, 179.98), (4, 3, 1, 29.99)`);
});

module.exports = db;
