DROP TABLE IF EXISTS order_items;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS table_sessions;
DROP TABLE IF EXISTS menu_items;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('owner', 'staff'))
);

CREATE TABLE menu_items (
    id SERIAL PRIMARY KEY,
    name_th VARCHAR(100) NOT NULL,
    name_en VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    tier VARCHAR(20) DEFAULT 'STANDARD'
);

CREATE TABLE table_sessions (
    id SERIAL PRIMARY KEY,
    table_number VARCHAR(10) NOT NULL,
    session_token VARCHAR(64) UNIQUE NOT NULL,
    status VARCHAR(20) DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '2 hours')
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    session_id INT REFERENCES table_sessions(id) ON DELETE CASCADE,
    table_number VARCHAR(10) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE order_items (
    id SERIAL PRIMARY KEY,
    order_id INT REFERENCES orders(id) ON DELETE CASCADE,
    menu_item_id INT REFERENCES menu_items(id),
    quantity INT NOT NULL CHECK (quantity > 0 AND quantity <= 10),
    status VARCHAR(20) DEFAULT 'PREPARING'
);

-- Seed Menu
INSERT INTO menu_items (name_th, name_en, category, tier) VALUES
('หมูสามชั้นสไลซ์', 'Sliced Pork Belly', 'Meat', 'STANDARD'),
('สันคอหมูสไลซ์', 'Sliced Pork Neck', 'Meat', 'STANDARD'),
('เนื้อริบอายออสเตรเลีย', 'Australian Ribeye', 'Meat', 'PLUS'),
('กุ้งสดแกะเปลือก', 'Peeled Fresh Shrimp', 'Seafood', 'STANDARD');