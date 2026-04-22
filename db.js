'use strict';
/**
 * Secure in-memory store.
 *
 * Differences from the vulnerable version:
 *  - Passwords are stored as bcrypt hashes, never plaintext
 *  - All queries use parameterised placeholders (no string interpolation)
 *  - No SQL injection detection trickery needed — injection simply can't happen
 */

const bcrypt = require('bcryptjs');

// ── Seed data (passwords are bcrypt hashes) ──────────────────
const SALT_ROUNDS = 10;

// Pre-hashed at startup for the seed users
const store = { users: [], products: [], orders: [] };
const nextId = { users: 5, products: 5, orders: 4 };

(async () => {
  store.users = [
    { id: 1, username: 'admin', password: await bcrypt.hash('admin123',    SALT_ROUNDS), email: 'admin@shopfixed.local', role: 'admin',  balance: 9999.99 },
    { id: 2, username: 'alice', password: await bcrypt.hash('password1',   SALT_ROUNDS), email: 'alice@example.com',     role: 'user',   balance: 150.00  },
    { id: 3, username: 'bob',   password: await bcrypt.hash('ilovecats42', SALT_ROUNDS), email: 'bob@example.com',        role: 'user',   balance: 75.50   },
    { id: 4, username: 'carol', password: await bcrypt.hash('qwerty123',   SALT_ROUNDS), email: 'carol@example.com',      role: 'user',   balance: 200.00  },
  ];
  store.products = [
    { id: 1, name: 'Laptop Pro',          price: 999.99, description: 'High-performance laptop for professionals', stock: 10 },
    { id: 2, name: 'Mechanical Keyboard', price:  89.99, description: 'RGB backlit mechanical keyboard',            stock: 50 },
    { id: 3, name: 'USB Hub',             price:  29.99, description: 'USB 3.0 7-port hub with power adapter',      stock: 30 },
    { id: 4, name: 'Monitor Stand',       price:  49.99, description: 'Adjustable ergonomic monitor riser',         stock: 20 },
  ];
  store.orders = [
    { id: 1, user_id: 2, product_id: 1, quantity: 1, total: 999.99 },
    { id: 2, user_id: 3, product_id: 2, quantity: 2, total: 179.98 },
    { id: 3, user_id: 4, product_id: 3, quantity: 1, total:  29.99 },
  ];
  console.log('[db-fixed] in-memory secure store ready');
})();

// ── Query API ─────────────────────────────────────────────────
// Exposes the same .get() / .all() / .run() surface as the vulnerable db.js
// but is implemented with direct array operations — no SQL parsing, no injection.

const db = {
  // AUTH
  getUserByCredentials(username, password, cb) {
    const user = store.users.find(u => u.username === username);
    if (!user) return cb(null, null);
    bcrypt.compare(password, user.password, (err, match) => {
      if (err) return cb(err, null);
      cb(null, match ? user : null);
    });
  },

  getUserById(id, cb) {
    const user = store.users.find(u => u.id === Number(id));
    cb(null, user || null);
  },

  getAllUsers(cb) {
    cb(null, store.users);
  },

  createUser(username, password, email, cb) {
    if (store.users.find(u => u.username === username)) {
      return cb(new Error('Username already taken'));
    }
    bcrypt.hash(password, SALT_ROUNDS, (err, hash) => {
      if (err) return cb(err);
      const id = nextId.users++;
      store.users.push({ id, username, password: hash, email, role: 'user', balance: 0 });
      cb(null, id);
    });
  },

  // PRODUCTS
  searchProducts(term, cb) {
    const t = term.toLowerCase();
    const rows = store.products.filter(p =>
      p.name.toLowerCase().includes(t) ||
      (p.description || '').toLowerCase().includes(t)
    );
    cb(null, rows);
  },

  getAllProducts(cb) {
    cb(null, [...store.products]);
  },

  getProductById(id, cb) {
    cb(null, store.products.find(p => p.id === Number(id)) || null);
  },

  createProduct(name, price, description, stock, cb) {
    const id = nextId.products++;
    store.products.push({ id, name, price, description, stock });
    cb(null, id);
  },

  updateProduct(id, name, price, description, stock, cb) {
    const idx = store.products.findIndex(p => p.id === Number(id));
    if (idx === -1) return cb(null, 0);
    Object.assign(store.products[idx], { name, price, description, stock });
    cb(null, 1);
  },

  // ORDERS
  getOrdersByUser(userId, cb) {
    cb(null, store.orders.filter(o => o.user_id === Number(userId)));
  },

  // ADMIN
  deleteUser(id, cb) {
    const idx = store.users.findIndex(u => u.id === Number(id));
    if (idx === -1) return cb(null, 0);
    store.users.splice(idx, 1);
    cb(null, 1);
  },
};

module.exports = db;
