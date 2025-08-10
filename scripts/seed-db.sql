
-- Enable foreign key constraints
PRAGMA foreign_keys = ON;

-- Drop tables in correct order (child tables first)
DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS request_logs;

-- Create users table first (parent table)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    email TEXT,
    last_login DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create posts table with updated schema
CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    content TEXT NOT NULL,
    excerpt TEXT,
    author_id INTEGER NOT NULL,
    published BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create settings table
CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  type TEXT DEFAULT 'string',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create request_logs table
CREATE TABLE request_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    path TEXT NOT NULL,
    method TEXT NOT NULL,
    duration INTEGER NOT NULL,
    status_code INTEGER,
    user_agent TEXT,
    ip TEXT,
    referer TEXT,
    country TEXT,
    error TEXT
);

-- Create indexes for better performance
CREATE INDEX idx_posts_published ON posts(published);
CREATE INDEX idx_posts_author ON posts(author_id);
CREATE INDEX idx_posts_created ON posts(created_at);
CREATE INDEX idx_posts_slug ON posts(slug);

-- Insert admin user with role
INSERT INTO users (username, password, salt, role, email)
VALUES (
  'admin',
  '0ba766f033ed5a15cb6956aa263a569950b036bade23ecb605f1094c0e78ec98',
  '68b7a9d1d26c86014c6a384578e9529d',
  'admin',
  'admin@deadlight.boo'
);

-- Insert default settings
INSERT INTO settings (key, value, type) VALUES 
  ('site_title', 'deadlight.boo', 'string'),
  ('site_description', 'A minimal blog framework', 'string'),
  ('posts_per_page', '10', 'number'),
  ('date_format', 'M/D/YYYY', 'string'),
  ('timezone', 'UTC', 'string'),
  ('enable_registration', 'false', 'boolean'),
  ('require_login_to_read', 'false', 'boolean'),
  ('maintenance_mode', 'false', 'boolean');