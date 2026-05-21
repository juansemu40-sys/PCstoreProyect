
-- TABLAS


DROP TABLE IF EXISTS products CASCADE;
DROP TABLE IF EXISTS categories CASCADE;
DROP TABLE IF EXISTS permissions CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS roles CASCADE;

CREATE TABLE roles (
  id SERIAL PRIMARY KEY,
  name VARCHAR(50) UNIQUE NOT NULL,
  description TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(100) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  full_name VARCHAR(150),
  role_id INTEGER REFERENCES roles(id) ON DELETE SET NULL,
  active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE permissions (
  id SERIAL PRIMARY KEY,
  role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
  module VARCHAR(50) NOT NULL,
  can_view BOOLEAN DEFAULT FALSE,
  can_create BOOLEAN DEFAULT FALSE,
  can_edit BOOLEAN DEFAULT FALSE,
  can_delete BOOLEAN DEFAULT FALSE,
  UNIQUE(role_id, module)
);

CREATE TABLE categories (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE products (
  id SERIAL PRIMARY KEY,
  name VARCHAR(200) NOT NULL,
  category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
  brand VARCHAR(100),
  price DECIMAL(10,2) NOT NULL DEFAULT 0,
  stock INTEGER DEFAULT 0,
  description TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);


-- ROLES

INSERT INTO roles (name, description) VALUES
  ('Admin', 'Acceso total al sistema'),
  ('Vendedor', 'Puede ver y gestionar productos'),
  ('Inventario', 'Solo puede consultar stock');


-- USUARIOS
-- Passwords: admin123 / vendedor123 / inventario123
-- (generados con bcrypt rounds=10)

INSERT INTO users (username, full_name, password_hash, role_id) VALUES
  ('admin',      'Administrador Sistema',  '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 1),
  ('vendedor',   'Juan Pérez',             '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 2),
  ('inventario', 'María López',            '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 3);




PERMISOS POR ROL


-- Admin: acceso total
INSERT INTO permissions (role_id, module, can_view, can_create, can_edit, can_delete) VALUES
  (1, 'products',   TRUE, TRUE, TRUE, TRUE),
  (1, 'categories', TRUE, TRUE, TRUE, TRUE),
  (1, 'users',      TRUE, TRUE, TRUE, TRUE),
  (1, 'roles',      TRUE, TRUE, TRUE, TRUE);

-- Vendedor: ve y crea productos/categorías, no gestiona usuarios ni roles
INSERT INTO permissions (role_id, module, can_view, can_create, can_edit, can_delete) VALUES
  (2, 'products',   TRUE, TRUE,  TRUE,  FALSE),
  (2, 'categories', TRUE, TRUE,  FALSE, FALSE),
  (2, 'users',      FALSE, FALSE, FALSE, FALSE),
  (2, 'roles',      FALSE, FALSE, FALSE, FALSE);

-- Inventario: solo lectura en productos y categorías
INSERT INTO permissions (role_id, module, can_view, can_create, can_edit, can_delete) VALUES
  (3, 'products',   TRUE,  FALSE, FALSE, FALSE),
  (3, 'categories', TRUE,  FALSE, FALSE, FALSE),
  (3, 'users',      FALSE, FALSE, FALSE, FALSE),
  (3, 'roles',      FALSE, FALSE, FALSE, FALSE);


--CATEGORÍAS

INSERT INTO categories (name, description) VALUES
  ('Procesadores',    'CPUs Intel y AMD para escritorio y portátil'),
  ('Tarjetas Gráficas', 'GPUs NVIDIA y AMD para gaming y trabajo'),
  ('Memorias RAM',    'Módulos DDR4 y DDR5'),
  ('Almacenamiento',  'SSDs, HDDs y NVMe'),
  ('Placas Madre',    'Motherboards ATX, mATX y ITX'),
  ('Fuentes de Poder','PSUs certificadas 80+ Bronze/Gold/Platinum');


--PRODUCTOS

INSERT INTO products (name, category_id, brand, price, stock, description) VALUES
  ('Intel Core i9-14900K',    1, 'Intel',   589.99, 15, 'Procesador de escritorio 24 núcleos, 6GHz boost'),
  ('AMD Ryzen 9 7950X',       1, 'AMD',     699.99,  8, 'Procesador 16 núcleos, 5.7GHz, socket AM5'),
  ('AMD Ryzen 5 7600X',       1, 'AMD',     249.99, 30, 'Procesador 6 núcleos ideal para gaming'),
  ('NVIDIA RTX 4090',         2, 'NVIDIA', 1599.99,  5, 'GPU flagship, 24GB GDDR6X'),
  ('NVIDIA RTX 4070 Ti',      2, 'NVIDIA',  779.99, 12, '12GB GDDR6X, perfecto para 4K gaming'),
  ('AMD RX 7800 XT',          2, 'AMD',     499.99, 18, '16GB GDDR6, excelente relación precio/rendimiento'),
  ('Corsair Vengeance 32GB',  3, 'Corsair', 119.99, 25, 'DDR5 6000MHz, kit 2x16GB CL36'),
  ('G.Skill Trident Z5 64GB', 3, 'G.Skill', 229.99, 10, 'DDR5 6400MHz, kit 2x32GB RGB'),
  ('Samsung 990 Pro 2TB',     4, 'Samsung', 179.99, 40, 'NVMe PCIe 4.0, 7450MB/s lectura'),
  ('WD Black SN850X 1TB',     4, 'WD',      129.99, 35, 'NVMe PCIe 4.0, 7300MB/s, ideal PS5/PC'),
  ('ASUS ROG Maximus Z790',   5, 'ASUS',    599.99,  7, 'Placa madre LGA1700, DDR5, WiFi 6E'),
  ('MSI MPG B650 Carbon',     5, 'MSI',     299.99, 14, 'AM5, DDR5, PCIe 5.0, RGB'),
  ('Corsair RM1000x 1000W',   6, 'Corsair', 189.99, 20, 'Certificación 80+ Gold, modular, 1000W'),
  ('EVGA SuperNOVA 850 G6',   6, 'EVGA',   149.99, 16, '850W, 80+ Gold, completamente modular');
