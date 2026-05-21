// ============================================
// PC STORE - Backend API
// ============================================
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'pc_store_secret_2024_change_in_production';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.connect()
  .then(() => console.log('✅ Conectado a PostgreSQL'))
  .catch(err => console.error('❌ Error DB:', err.message));

// ── MIDDLEWARE ───────────────────────────────
app.use(cors());
app.use(express.json());

// ── AUTH MIDDLEWARE ──────────────────────────
const verifyToken = (req, res, next) => {
  const auth = req.headers['authorization'];
  const token = auth && auth.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(403).json({ error: 'Token inválido' });
  }
};

// Verifica permiso de rol antes de ejecutar la acción
const checkPerm = (module, action) => async (req, res, next) => {
  // Admin (role_id=1) siempre tiene acceso total
  if (req.user.role_id === 1) return next();
  try {
    const r = await pool.query(
      'SELECT * FROM permissions WHERE role_id=$1 AND module=$2',
      [req.user.role_id, module]
    );
    if (!r.rows[0] || !r.rows[0][action]) {
      return res.status(403).json({ error: 'Sin permisos para esta acción' });
    }
    next();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};

// ─────────────────────────────────────────────
// RUTAS AUTH
// ─────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  try {
    const r = await pool.query(
      `SELECT u.*, r.name as role_name
       FROM users u JOIN roles r ON u.role_id = r.id
       WHERE u.username = $1 AND u.active = TRUE`,
      [username]
    );
    if (!r.rows[0]) return res.status(401).json({ error: 'Credenciales inválidas' });
    const user = r.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Credenciales inválidas' });

    // Cargar permisos
    const perms = await pool.query(
      'SELECT module, can_view, can_create, can_edit, can_delete FROM permissions WHERE role_id=$1',
      [user.role_id]
    );
    const permissions = {};
    perms.rows.forEach(p => { permissions[p.module] = p; });

    const token = jwt.sign(
      { id: user.id, username: user.username, role_id: user.role_id, role_name: user.role_name },
      JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.json({
      token,
      user: { id: user.id, username: user.username, full_name: user.full_name,
              role_id: user.role_id, role_name: user.role_name, permissions }
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Endpoint para re-hash de contraseñas del seed SQL
app.post('/api/auth/seed', async (req, res) => {
  try {
    const users = [
      { username: 'admin',      password: 'admin123' },
      { username: 'vendedor',   password: 'vendedor123' },
      { username: 'inventario', password: 'inventario123' },
    ];
    for (const u of users) {
      const hash = await bcrypt.hash(u.password, 10);
      await pool.query('UPDATE users SET password_hash=$1 WHERE username=$2', [hash, u.username]);
    }
    res.json({ ok: true, message: 'Contraseñas actualizadas correctamente' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT u.id, u.username, u.full_name, u.role_id, r.name as role_name
       FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id=$1`,
      [req.user.id]
    );
    const perms = await pool.query(
      'SELECT module, can_view, can_create, can_edit, can_delete FROM permissions WHERE role_id=$1',
      [req.user.role_id]
    );
    const permissions = {};
    perms.rows.forEach(p => { permissions[p.module] = p; });
    res.json({ ...r.rows[0], permissions });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────
// CRUD: PRODUCTS
// ─────────────────────────────────────────────
app.get('/api/products', verifyToken, checkPerm('products', 'can_view'), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT p.*, c.name as category_name
       FROM products p LEFT JOIN categories c ON p.category_id = c.id
       ORDER BY p.created_at DESC`
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/products', verifyToken, checkPerm('products', 'can_create'), async (req, res) => {
  const { name, category_id, brand, price, stock, description } = req.body;
  if (!name || !price) return res.status(400).json({ error: 'Nombre y precio requeridos' });
  try {
    const r = await pool.query(
      `INSERT INTO products (name, category_id, brand, price, stock, description)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [name, category_id || null, brand, price, stock || 0, description]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/products/:id', verifyToken, checkPerm('products', 'can_edit'), async (req, res) => {
  const { name, category_id, brand, price, stock, description } = req.body;
  try {
    const r = await pool.query(
      `UPDATE products SET name=$1, category_id=$2, brand=$3, price=$4, stock=$5, description=$6
       WHERE id=$7 RETURNING *`,
      [name, category_id || null, brand, price, stock, description, req.params.id]
    );
    if (!r.rows[0]) return res.status(404).json({ error: 'Producto no encontrado' });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/products/:id', verifyToken, checkPerm('products', 'can_delete'), async (req, res) => {
  try {
    const r = await pool.query('DELETE FROM products WHERE id=$1 RETURNING id', [req.params.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Producto no encontrado' });
    res.json({ deleted: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// CRUD: CATEGORIES
// ─────────────────────────────────────────────
app.get('/api/categories', verifyToken, checkPerm('categories', 'can_view'), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT c.*, COUNT(p.id)::int as product_count
       FROM categories c LEFT JOIN products p ON p.category_id = c.id
       GROUP BY c.id ORDER BY c.name`
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/categories', verifyToken, checkPerm('categories', 'can_create'), async (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Nombre requerido' });
  try {
    const r = await pool.query(
      'INSERT INTO categories (name, description) VALUES ($1,$2) RETURNING *',
      [name, description]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/categories/:id', verifyToken, checkPerm('categories', 'can_edit'), async (req, res) => {
  const { name, description } = req.body;
  try {
    const r = await pool.query(
      'UPDATE categories SET name=$1, description=$2 WHERE id=$3 RETURNING *',
      [name, description, req.params.id]
    );
    if (!r.rows[0]) return res.status(404).json({ error: 'Categoría no encontrada' });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/categories/:id', verifyToken, checkPerm('categories', 'can_delete'), async (req, res) => {
  try {
    const r = await pool.query('DELETE FROM categories WHERE id=$1 RETURNING id', [req.params.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Categoría no encontrada' });
    res.json({ deleted: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// CRUD: ROLES & PERMISSIONS
// ─────────────────────────────────────────────
app.get('/api/roles', verifyToken, checkPerm('roles', 'can_view'), async (req, res) => {
  try {
    const roles = await pool.query('SELECT * FROM roles ORDER BY id');
    const perms = await pool.query('SELECT * FROM permissions ORDER BY role_id, module');
    const result = roles.rows.map(role => ({
      ...role,
      permissions: perms.rows.filter(p => p.role_id === role.id)
    }));
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/roles', verifyToken, checkPerm('roles', 'can_create'), async (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'Nombre requerido' });
  try {
    const r = await pool.query(
      'INSERT INTO roles (name, description) VALUES ($1,$2) RETURNING *',
      [name, description]
    );
    // Crear permisos vacíos para todos los módulos
    const modules = ['products', 'categories', 'users', 'roles'];
    for (const mod of modules) {
      await pool.query(
        'INSERT INTO permissions (role_id, module) VALUES ($1,$2)',
        [r.rows[0].id, mod]
      );
    }
    res.status(201).json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/roles/:id', verifyToken, checkPerm('roles', 'can_edit'), async (req, res) => {
  const { name, description, permissions } = req.body;
  try {
    await pool.query(
      'UPDATE roles SET name=$1, description=$2 WHERE id=$3',
      [name, description, req.params.id]
    );
    if (permissions && Array.isArray(permissions)) {
      for (const p of permissions) {
        await pool.query(
          `INSERT INTO permissions (role_id, module, can_view, can_create, can_edit, can_delete)
           VALUES ($1,$2,$3,$4,$5,$6)
           ON CONFLICT (role_id, module) DO UPDATE
           SET can_view=$3, can_create=$4, can_edit=$5, can_delete=$6`,
          [req.params.id, p.module, !!p.can_view, !!p.can_create, !!p.can_edit, !!p.can_delete]
        );
      }
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/roles/:id', verifyToken, checkPerm('roles', 'can_delete'), async (req, res) => {
  if (req.params.id === '1') return res.status(400).json({ error: 'No se puede eliminar el rol Admin' });
  try {
    await pool.query('DELETE FROM roles WHERE id=$1', [req.params.id]);
    res.json({ deleted: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
// CRUD: USERS
// ─────────────────────────────────────────────
app.get('/api/users', verifyToken, checkPerm('users', 'can_view'), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT u.id, u.username, u.full_name, u.active, u.created_at, r.name as role_name, u.role_id
       FROM users u LEFT JOIN roles r ON u.role_id = r.id ORDER BY u.id`
    );
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/users', verifyToken, checkPerm('users', 'can_create'), async (req, res) => {
  const { username, full_name, password, role_id } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      'INSERT INTO users (username, full_name, password_hash, role_id) VALUES ($1,$2,$3,$4) RETURNING id, username, full_name, role_id, active, created_at',
      [username, full_name, hash, role_id || null]
    );
    res.status(201).json(r.rows[0]);
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'El usuario ya existe' });
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/users/:id', verifyToken, checkPerm('users', 'can_edit'), async (req, res) => {
  const { full_name, role_id, active, password } = req.body;
  try {
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        'UPDATE users SET full_name=$1, role_id=$2, active=$3, password_hash=$4 WHERE id=$5',
        [full_name, role_id, active, hash, req.params.id]
      );
    } else {
      await pool.query(
        'UPDATE users SET full_name=$1, role_id=$2, active=$3 WHERE id=$4',
        [full_name, role_id, active, req.params.id]
      );
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/:id', verifyToken, checkPerm('users', 'can_delete'), async (req, res) => {
  if (req.params.id === String(req.user.id))
    return res.status(400).json({ error: 'No puedes eliminar tu propio usuario' });
  try {
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    res.json({ deleted: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
  console.log(`   POST /api/auth/seed  ← ejecutar UNA vez para configurar contraseñas`);
});
