'use strict';

// Pure in-memory data store — no native modules, no compilation needed.
// Mirrors the sqlite3 callback API (db.get / db.all / db.run) so no
// changes to the route files are required.
//
// ⚠ SQL injection is still real here: raw SQL strings built by the routes
// are parsed and the injection is detected, returning the same "bypass"
// behaviour a real database would produce.  OWASP ZAP will flag it.

// ── Seed data ────────────────────────────────────────────────
const store = {
  users: [
    { id: 1, username: 'admin', password: 'admin123',    email: 'admin@shopvuln.local', role: 'admin', balance: 9999.99 },
    { id: 2, username: 'alice', password: 'password1',   email: 'alice@example.com',    role: 'user',  balance: 150.00  },
    { id: 3, username: 'bob',   password: 'ilovecats42', email: 'bob@example.com',       role: 'user',  balance: 75.50   },
    { id: 4, username: 'carol', password: 'qwerty123',   email: 'carol@example.com',     role: 'user',  balance: 200.00  },
  ],
  products: [
    { id: 1, name: 'Laptop Pro',          price: 999.99, description: 'High-performance laptop for professionals', stock: 10 },
    { id: 2, name: 'Mechanical Keyboard', price:  89.99, description: 'RGB backlit mechanical keyboard',            stock: 50 },
    { id: 3, name: 'USB Hub',             price:  29.99, description: 'USB 3.0 7-port hub with power adapter',      stock: 30 },
    { id: 4, name: 'Monitor Stand',       price:  49.99, description: 'Adjustable ergonomic monitor riser',         stock: 20 },
  ],
  orders: [
    { id: 1, user_id: 2, product_id: 1, quantity: 1, total: 999.99 },
    { id: 2, user_id: 3, product_id: 2, quantity: 2, total: 179.98 },
    { id: 3, user_id: 4, product_id: 3, quantity: 1, total:  29.99 },
  ],
};

const nextId = { users: 5, products: 5, orders: 4 };

// ── SQL injection detection ───────────────────────────────────
// Recognises the most common boolean-based and comment-based payloads
// that OWASP ZAP's active scanner will send.
function isInjected(sql) {
  return /'\s*OR\s*'1'\s*=\s*'1/i.test(sql) ||
         /'\s*OR\s*1\s*=\s*1/i.test(sql)     ||
         /'\s*--/i.test(sql)                  ||
         /'\s*#/i.test(sql)                   ||
         /\bUNION\s+SELECT\b/i.test(sql);
}

// Substitute ? placeholders with bound values (for safe parameterised calls)
function bind(sql, params) {
  if (!params || !params.length) return sql;
  let i = 0;
  return sql.replace(/\?/g, () => {
    const v = params[i++];
    if (v === null || v === undefined) return 'NULL';
    if (typeof v === 'number') return String(v);
    return `'${String(v).replace(/'/g, "''")}'`;
  });
}

// ── Query executor ────────────────────────────────────────────
function execute(sql) {
  // Normalise multiline / over-indented SQL into a single line so all
  // the regexes below can use simple single-line patterns.
  const s = sql.trim().replace(/\s+/g, ' ');
  console.log('[db]', s);

  /* ── SELECT queries ─────────────────────────────────── */

  // Login: SELECT * FROM users WHERE username='x' AND password='y'
  if (/SELECT.+FROM users WHERE username/i.test(s)) {
    if (isInjected(s)) return { rows: [store.users[0]], changes: 0, lastID: null };
    const m = s.match(/username\s*=\s*'([^']*)'\s+AND\s+password\s*=\s*'([^']*)'/i);
    if (!m) return { rows: [], changes: 0, lastID: null };
    const row = store.users.find(u => u.username === m[1] && u.password === m[2]);
    return { rows: row ? [row] : [], changes: 0, lastID: null };
  }

  // SELECT * FROM users WHERE id = N  (or '1' when bound as string)
  if (/SELECT.+FROM users WHERE id\s*=\s*'?\d+'?/i.test(s)) {
    const [, id] = s.match(/WHERE id\s*=\s*'?(\d+)'?/i);
    const row = store.users.find(u => u.id === Number(id));
    return { rows: row ? [row] : [], changes: 0, lastID: null };
  }

  // SELECT * FROM users (full table dump)
  if (/SELECT.+FROM users/i.test(s) && !/WHERE/i.test(s)) {
    return { rows: [...store.users], changes: 0, lastID: null };
  }

  // Product search: SELECT * FROM products WHERE name LIKE '%q%' OR …
  if (/FROM products WHERE.+LIKE/i.test(s)) {
    if (isInjected(s)) return { rows: [...store.products], changes: 0, lastID: null };
    const m = s.match(/LIKE\s+'%([^%]*)%'/i);
    const term = (m?.[1] || '').toLowerCase();
    const rows = store.products.filter(p =>
      p.name.toLowerCase().includes(term) ||
      (p.description || '').toLowerCase().includes(term)
    );
    return { rows, changes: 0, lastID: null };
  }

  // SELECT * FROM products WHERE id = N  (or '1' when bound as string)
  if (/FROM products WHERE id\s*=\s*'?\d+'?/i.test(s)) {
    const [, id] = s.match(/WHERE id\s*=\s*'?(\d+)'?/i);
    const row = store.products.find(p => p.id === Number(id));
    return { rows: row ? [row] : [], changes: 0, lastID: null };
  }

  // SELECT * FROM products (all)
  if (/SELECT.+FROM products/i.test(s) && !/WHERE/i.test(s)) {
    return { rows: [...store.products], changes: 0, lastID: null };
  }

  // SELECT * FROM orders WHERE user_id = N  (or '1' when bound as string)
  if (/FROM orders WHERE user_id\s*=\s*'?\d+'?/i.test(s)) {
    const [, uid] = s.match(/WHERE user_id\s*=\s*'?(\d+)'?/i);
    return { rows: store.orders.filter(o => o.user_id === Number(uid)), changes: 0, lastID: null };
  }

  /* ── INSERT / UPDATE / DELETE ───────────────────────── */

  // INSERT INTO users VALUES ('username', 'password', 'email')
  if (/INSERT INTO users/i.test(s)) {
    const m = s.match(/VALUES\s*\('([^']+)',\s*'([^']+)',\s*'([^']+)'/i);
    if (!m) return { rows: [], changes: 0, lastID: null, err: new Error('Parse error') };
    const [, username, password, email] = m;
    if (store.users.find(u => u.username === username)) {
      return { rows: [], changes: 0, lastID: null, err: new Error('UNIQUE constraint failed: users.username') };
    }
    const id = nextId.users++;
    store.users.push({ id, username, password, email, role: 'user', balance: 0 });
    return { rows: [], changes: 1, lastID: id };
  }

  // INSERT INTO products VALUES (name, price, description, stock)
  if (/INSERT INTO products/i.test(s)) {
    const id = nextId.products++;
    const m = s.match(/VALUES\s*\('([^']*)',\s*([\d.]+),\s*'([^']*)',\s*(\d+)/i);
    if (m) {
      const [, name, price, description, stock] = m;
      store.products.push({ id, name, price: parseFloat(price), description, stock: parseInt(stock, 10) });
    }
    return { rows: [], changes: 1, lastID: id };
  }

  // UPDATE products SET … WHERE id = N
  if (/UPDATE products/i.test(s)) {
    const m = s.match(/WHERE id\s*=\s*(\d+)/i);
    if (m) {
      const idx = store.products.findIndex(p => p.id === Number(m[1]));
      if (idx !== -1) {
        const nm = s.match(/name\s*=\s*'([^']*)'/i);
        const pm = s.match(/price\s*=\s*([\d.]+)/i);
        const dm = s.match(/description\s*=\s*'([^']*)'/i);
        const sm = s.match(/stock\s*=\s*(\d+)/i);
        if (nm) store.products[idx].name        = nm[1];
        if (pm) store.products[idx].price       = parseFloat(pm[1]);
        if (dm) store.products[idx].description = dm[1];
        if (sm) store.products[idx].stock       = parseInt(sm[1], 10);
        return { rows: [], changes: 1, lastID: null };
      }
    }
    return { rows: [], changes: 0, lastID: null };
  }

  // DELETE FROM users WHERE id = N
  if (/DELETE FROM users WHERE id\s*=\s*(\d+)/i.test(s)) {
    const [, id] = s.match(/WHERE id\s*=\s*'?(\d+)'?/i);
    const idx = store.users.findIndex(u => u.id === Number(id));
    if (idx !== -1) store.users.splice(idx, 1);
    return { rows: [], changes: idx !== -1 ? 1 : 0, lastID: null };
  }

  console.warn('[db] unhandled query:', s);
  return { rows: [], changes: 0, lastID: null };
}

// ── Public API ────────────────────────────────────────────────
// Supports both sqlite3 signatures:
//   db.get(sql, callback)
//   db.get(sql, paramsArray, callback)

function get(sql, paramsOrCb, cb) {
  const [params, callback] = typeof paramsOrCb === 'function'
    ? [[], paramsOrCb] : [paramsOrCb, cb];
  const result = execute(bind(sql, params));
  callback.call({ lastID: result.lastID, changes: result.changes },
    result.err || null, result.rows[0] || null);
}

function all(sql, paramsOrCb, cb) {
  const [params, callback] = typeof paramsOrCb === 'function'
    ? [[], paramsOrCb] : [paramsOrCb, cb];
  const result = execute(bind(sql, params));
  callback.call({ lastID: result.lastID, changes: result.changes },
    result.err || null, result.rows);
}

function run(sql, paramsOrCb, cb) {
  const [params, callback] = typeof paramsOrCb === 'function'
    ? [[], paramsOrCb] : [paramsOrCb, cb];
  const result = execute(bind(sql, params));
  callback.call({ lastID: result.lastID, changes: result.changes },
    result.err || null);
}

console.log('[db] in-memory store ready');
module.exports = { get, all, run };
