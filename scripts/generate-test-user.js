// scripts/generate-test-user.js
import { hashPassword, verifyPassword } from '../src/utils/auth.js';

// Base SQL for creating tables - updated to match current schema
const baseSql = `
-- Enable foreign key constraints
PRAGMA foreign_keys = ON;

-- Drop tables in correct order (child tables first)
DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS request_logs;

-- Create users table (parent table)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    email TEXT,
    last_login DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    subdomain TEXT,
    profile_title TEXT,
    profile_description TEXT,
    updated_at TIMESTAMP
);

-- Create posts table
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
    is_email INTEGER DEFAULT 0,
    email_metadata TEXT DEFAULT NULL,
    is_reply_draft INTEGER DEFAULT 0,
    visibility TEXT DEFAULT 'public' CHECK (visibility IN ('public', 'private')),
    moderation_status TEXT DEFAULT 'approved' CHECK (moderation_status IN ('approved', 'pending', 'rejected')),
    moderation_notes TEXT,
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

-- Indexes
CREATE INDEX idx_posts_published ON posts(published);
CREATE INDEX idx_posts_author ON posts(author_id);
CREATE INDEX idx_posts_created ON posts(created_at);
CREATE INDEX idx_posts_slug ON posts(slug);
`;

async function generateTestUserCredentials() {
  try {
    const password = 'gross-gnar';
    console.error('Generating credentials for password:', password);
    
    const { hash, salt } = await hashPassword(password);
    
    console.error('Generated credentials:', {
      password,
      hashStart: hash.substring(0, 10),
      hashLength: hash.length,
      saltStart: salt.substring(0, 10),
      saltLength: salt.length
    });

    const testVerify = await verifyPassword(password, hash, salt);
    console.error('Verification test:', { testVerify });

    const fullSql = `${baseSql}

-- Insert admin user with role
INSERT INTO users (username, password, salt, role, email)
VALUES (
  'admin',
  '${hash}',
  '${salt}',
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
`;

    process.stdout.write(fullSql);
  } catch (error) {
    console.error('Error generating credentials:', error);
    process.exit(1);
  }
}

generateTestUserCredentials();
