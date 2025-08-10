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

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    type TEXT DEFAULT 'string',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);