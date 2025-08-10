-- Enable foreign key constraints
PRAGMA foreign_keys = ON;

-- Drop tables if they already exist
DROP TABLE IF EXISTS posts;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS settings;

-- Create users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'editor', 'viewer')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create posts table
CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    content TEXT NOT NULL,
    author_id INTEGER NOT NULL,
    published_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create settings table
CREATE TABLE settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL
);

-- Prompt for password interactively in CLI
-- The following command uses SQLite's `.read` capability and parameter binding.
-- Example: sqlite3 blog.db ".read seed.sql" -cmd ".param set @admin_password 'mypassword'"
INSERT INTO users (username, password_hash, role)
VALUES (
    'admin',
    -- Using bcrypt hash of the provided password parameter
    -- Run in CLI: UPDATE users SET password_hash = bcrypt(@admin_password, 12) WHERE username='admin';
    '', -- placeholder to be updated
    'admin'
);

-- Insert default settings
INSERT INTO settings (key, value) VALUES ('site_title', 'My Dev Blog');
INSERT INTO settings (key, value) VALUES ('proxy_url', '');
INSERT INTO settings (key, value) VALUES ('upstream_blog_url', '');
