const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');


require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Seed Default Users with Bcrypt Hashes on Startup
async function seedDefaultUsers() {
  try {
    const ownerHash = await bcrypt.hash('owner_password', 10);
    const staffHash = await bcrypt.hash('staff_password', 10);

    await pool.query(
      `INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'owner') ON CONFLICT (username) DO NOTHING`,
      ['owner', ownerHash]
    );
    await pool.query(
      `INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'staff') ON CONFLICT (username) DO NOTHING`,
      ['staff', staffHash]
    );
    console.log('Default accounts verified: owner / staff');
  } catch (err) {
    console.error('Error seeding users:', err.message);
  }
}

// --- JWT & COOKIE MIDDLEWARE ---
function requireAuth(req, res, next) {
  const token = req.cookies.suki_token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireOwner(req, res, next) {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Owner privileges required' });
  }
  next();
}

// --- HTML VIEWS ---
app.get('/order', (req, res) => res.sendFile(path.join(__dirname, 'public', 'customer.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/staff', (req, res) => {
  const token = req.cookies.suki_token;
  if (!token) return res.redirect('/login');
  try {
    jwt.verify(token, JWT_SECRET);
    res.sendFile(path.join(__dirname, 'public', 'staff.html'));
  } catch {
    res.redirect('/login');
  }
});

// --- AUTHENTICATION ENDPOINTS ---
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.cookie('suki_token', token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 12 * 60 * 60 * 1000
    });

    res.json({ id: user.id, username: user.username, role: user.role });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('suki_token');
  res.json({ message: 'Logged out' });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json(req.user);
});

// --- OWNER: STAFF ACCOUNT MANAGEMENT ---
app.get('/api/owner/users', requireAuth, requireOwner, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, role FROM users ORDER BY id ASC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/owner/users', requireAuth, requireOwner, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, role',
      [username, hash, role || 'staff']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Username already exists' });
    res.status(500).json({ error: err.message });
  }
});

// --- MENU CRUD (Public Read, Owner Write) ---
app.get('/api/menu', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM menu_items ORDER BY id ASC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/menu', requireAuth, requireOwner, async (req, res) => {
  const { name_th, name_en, category, tier } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO menu_items (name_th, name_en, category, tier) VALUES ($1, $2, $3, $4) RETURNING *',
      [name_th, name_en, category, tier || 'STANDARD']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/menu/:id', requireAuth, requireOwner, async (req, res) => {
  const { name_th, name_en, category, tier } = req.body;
  try {
    const result = await pool.query(
      'UPDATE menu_items SET name_th=$1, name_en=$2, category=$3, tier=$4 WHERE id=$5 RETURNING *',
      [name_th, name_en, category, tier, req.params.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/menu/:id', requireAuth, requireOwner, async (req, res) => {
  try {
    await pool.query('DELETE FROM menu_items WHERE id = $1', [req.params.id]);
    res.json({ message: 'Menu item deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.post('/api/staff/sessions', requireAuth, async (req, res) => {
  const { table_number } = req.body;
  if (!table_number || !table_number.trim()) {
    return res.status(400).json({ error: 'Table number required' });
  }

  const sessionToken = crypto.randomBytes(16).toString('hex');
  try {
    const result = await pool.query(
      `
      INSERT INTO table_sessions (table_number, session_token)
      VALUES ($1, $2)
      RETURNING
        id,
        table_number,
        session_token,
        status,
        TO_CHAR(created_at AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Bangkok', 'HH24:MI:SS') AS created_th,
        TO_CHAR(expires_at AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Bangkok', 'HH24:MI:SS') AS expires_th
      `,
      [table_number.trim(), sessionToken]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/staff/sessions', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id,
        table_number,
        session_token,
        status,
        TO_CHAR(created_at AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Bangkok', 'HH24:MI:SS') AS created_th,
        TO_CHAR(expires_at AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Bangkok', 'HH24:MI:SS') AS expires_th
      FROM table_sessions
      WHERE status = 'ACTIVE'
      ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/staff/sessions/:id/close', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`UPDATE table_sessions SET status = 'CLOSED' WHERE id = $1 RETURNING *`, [req.params.id]);
    res.json({ message: 'Session closed', session: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/staff/orders', requireAuth, async (req, res) => {
  try {
    const query = `
      SELECT 
        oi.id AS item_id,
        o.table_number,
        m.name_th,
        m.name_en,
        oi.quantity,
        oi.status,
        TO_CHAR(o.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Bangkok', 'HH24:MI:SS') AS ordered_th
      FROM order_items oi
      JOIN orders o ON oi.order_id = o.id
      JOIN table_sessions s ON o.session_id = s.id
      JOIN menu_items m ON oi.menu_item_id = m.id
      WHERE s.status = 'ACTIVE'
      ORDER BY CASE WHEN oi.status = 'PREPARING' THEN 1 ELSE 2 END, o.created_at ASC
    `;
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/staff/order-items/:itemId/deliver', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`UPDATE order_items SET status = 'DELIVERED' WHERE id = $1 RETURNING *`, [req.params.itemId]);
    res.json({ message: 'Delivered', item: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- CUSTOMER ROUTES ---
app.get('/api/session/verify/:token', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM table_sessions WHERE session_token = $1 AND status = 'ACTIVE' AND expires_at > NOW()`,
      [req.params.token]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Session expired or closed.' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/orders', async (req, res) => {
  const { session_token, items } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const sessionRes = await client.query(
      `SELECT id, table_number FROM table_sessions WHERE session_token = $1 AND status = 'ACTIVE'`,
      [session_token]
    );
    if (sessionRes.rows.length === 0) throw new Error('Invalid session');
    const session = sessionRes.rows[0];

    const orderRes = await client.query(
      'INSERT INTO orders (session_id, table_number) VALUES ($1, $2) RETURNING id',
      [session.id, session.table_number]
    );
    const orderId = orderRes.rows[0].id;

    for (const item of items) {
      await client.query(
        'INSERT INTO order_items (order_id, menu_item_id, quantity) VALUES ($1, $2, $3)',
        [orderId, item.menu_item_id, item.quantity]
      );
    }
    await client.query('COMMIT');
    res.status(201).json({ message: 'Order placed' });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: err.message });
  } finally {
    client.release();
  }
});

app.get('/api/orders/session/:token', async (req, res) => {
  try {
    const query = `
      SELECT 
        oi.id,
        m.name_th,
        m.name_en,
        oi.quantity,
        oi.status,
        TO_CHAR(o.created_at AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Bangkok', 'HH24:MI:SS') AS ordered_th
      FROM order_items oi
      JOIN orders o ON oi.order_id = o.id
      JOIN table_sessions s ON o.session_id = s.id
      JOIN menu_items m ON oi.menu_item_id = m.id
      WHERE s.session_token = $1
      ORDER BY o.created_at DESC
    `;
    const result = await pool.query(query, [req.params.token]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, '0.0.0.0', async () => {
  await seedDefaultUsers();
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});