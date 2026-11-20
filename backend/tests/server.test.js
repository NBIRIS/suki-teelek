const request = require('supertest');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { app, pool } = require('../server');

const JWT_SECRET = process.env.JWT_SECRET || 'suki_teelek_super_secret_jwt_key_2026';

// Helper to generate valid JWT cookies for testing protected routes
function makeAuthCookie(role = 'staff', username = 'staff') {
  const token = jwt.sign({ id: 1, username, role }, JWT_SECRET, { expiresIn: '1h' });
  return `suki_token=${token}`;
}

afterEach(() => {
  jest.restoreAllMocks();
});

describe('Authentication Endpoints', () => {
  test('POST /api/auth/login succeeds with valid credentials and sets HttpOnly cookie', async () => {
    const hash = await bcrypt.hash('owner_password', 10);
    jest.spyOn(pool, 'query').mockResolvedValueOnce({
      rows: [{ id: 1, username: 'owner', password_hash: hash, role: 'owner' }],
    });

    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'owner', password: 'owner_password' });

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ id: 1, username: 'owner', role: 'owner' });
    expect(res.headers['set-cookie'][0]).toContain('suki_token=');
    expect(res.headers['set-cookie'][0]).toContain('HttpOnly');
  });

  test('POST /api/auth/login rejects wrong password with 401', async () => {
    const hash = await bcrypt.hash('owner_password', 10);
    jest.spyOn(pool, 'query').mockResolvedValueOnce({
      rows: [{ id: 1, username: 'owner', password_hash: hash, role: 'owner' }],
    });

    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'owner', password: 'wrong_password' });

    expect(res.statusCode).toBe(401);
    expect(res.body.error).toBe('Invalid credentials');
  });

  test('GET /api/auth/me returns 401 when unauthenticated', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.statusCode).toBe(401);
  });
});

describe('Role-Based Access Control (Owner vs Staff)', () => {
  test('POST /api/owner/users allows owner to create a staff account', async () => {
    jest.spyOn(pool, 'query').mockResolvedValueOnce({
      rows: [{ id: 3, username: 'new_staff', role: 'staff' }],
    });

    const res = await request(app)
      .post('/api/owner/users')
      .set('Cookie', makeAuthCookie('owner', 'owner'))
      .send({ username: 'new_staff', password: 'secret123', role: 'staff' });

    expect(res.statusCode).toBe(201);
    expect(res.body).toEqual({ id: 3, username: 'new_staff', role: 'staff' });
  });

  test('POST /api/owner/users blocks staff from creating accounts (403)', async () => {
    const res = await request(app)
      .post('/api/owner/users')
      .set('Cookie', makeAuthCookie('staff', 'staff'))
      .send({ username: 'hacker', password: '123', role: 'staff' });

    expect(res.statusCode).toBe(403);
    expect(res.body.error).toBe('Owner privileges required');
  });

  test('POST /api/owner/users prevents creating another owner account (403)', async () => {
    const res = await request(app)
      .post('/api/owner/users')
      .set('Cookie', makeAuthCookie('owner', 'owner'))
      .send({ username: 'owner2', password: '123', role: 'owner' });

    expect(res.statusCode).toBe(403);
  });
});

describe('Menu & Table Sessions', () => {
  test('GET /api/menu returns public menu list', async () => {
    const mockMenu = [
      { id: 1, name_th: 'หมูสไลซ์', name_en: 'Sliced Pork', category: 'Meat', tier: 'STANDARD' },
    ];
    jest.spyOn(pool, 'query').mockResolvedValueOnce({ rows: mockMenu });

    const res = await request(app).get('/api/menu');
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual(mockMenu);
  });

  test('POST /api/staff/sessions creates a new table session with Thailand timestamps', async () => {
    jest.spyOn(pool, 'query').mockResolvedValueOnce({
      rows: [{
        id: 10,
        table_number: 'T5',
        session_token: 'abc123token',
        status: 'ACTIVE',
        created_th: '18:30:00',
        expires_th: '20:30:00',
      }],
    });

    const res = await request(app)
      .post('/api/staff/sessions')
      .set('Cookie', makeAuthCookie('staff', 'staff'))
      .send({ table_number: 'T5' });

    expect(res.statusCode).toBe(201);
    expect(res.body.table_number).toBe('T5');
    expect(res.body.created_th).toBe('18:30:00');
  });
});

describe('Customer QR Verification & Ordering', () => {
  test('GET /api/session/verify/:token returns 404 for expired or closed session', async () => {
    jest.spyOn(pool, 'query').mockResolvedValueOnce({ rows: [] });

    const res = await request(app).get('/api/session/verify/expired_token');
    expect(res.statusCode).toBe(404);
  });

  test('POST /api/orders commits transaction when session is active', async () => {
    const mockClient = {
      query: jest.fn()
        .mockResolvedValueOnce({}) // BEGIN
        .mockResolvedValueOnce({ rows: [{ id: 10, table_number: 'T5' }] }) // SELECT session
        .mockResolvedValueOnce({ rows: [{ id: 99 }] }) // INSERT orders
        .mockResolvedValueOnce({}) // INSERT order_items
        .mockResolvedValueOnce({}), // COMMIT
      release: jest.fn(),
    };

    jest.spyOn(pool, 'connect').mockResolvedValueOnce(mockClient);

    const res = await request(app)
      .post('/api/orders')
      .send({
        session_token: 'valid_token',
        items: [{ menu_item_id: 1, quantity: 2 }],
      });

    expect(res.statusCode).toBe(201);
    expect(res.body.message).toBe('Order placed');
    expect(mockClient.release).toHaveBeenCalled();
  });
});