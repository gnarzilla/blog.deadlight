-- Full schema migration for new installations as of August 15, 2025

-- USERS
CREATE TABLE IF NOT EXISTS users (
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

-- POSTS
CREATE TABLE IF NOT EXISTS posts (
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
    parent_id INTEGER,
    thread_id INTEGER,
    federation_pending INTEGER DEFAULT 0,
    federation_sent_at TIMESTAMP,
    federation_metadata TEXT,
    post_type TEXT CHECK (post_type IN ('blog', 'email', 'comment', 'federated')) DEFAULT 'blog',
    retry_count INTEGER DEFAULT 0,
    last_error TEXT,
    last_attempt TIMESTAMP,
    comments_enabled BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES posts(id) ON DELETE SET NULL,
    FOREIGN KEY (thread_id) REFERENCES posts(id) ON DELETE SET NULL
);

-- REQUEST LOGS
CREATE TABLE IF NOT EXISTS request_logs (
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

-- SETTINGS
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    type TEXT DEFAULT 'string',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- USER SETTINGS
CREATE TABLE IF NOT EXISTS user_settings (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT
);

-- FEDERATION TRUST
CREATE TABLE IF NOT EXISTS federation_trust (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    trust_level TEXT DEFAULT 'verified' CHECK (trust_level IN ('verified', 'unverified', 'blocked')),
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP
);

-- API TOKENS
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    scopes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_used TIMESTAMP
);

-- POST META
CREATE TABLE IF NOT EXISTS post_meta (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- NOTIFICATIONS
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    type TEXT CHECK (type IN ('comment', 'like', 'mention', 'follow', 'system')),
    content TEXT,
    related_post_id INTEGER REFERENCES posts(id) ON DELETE SET NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    message_type TEXT CHECK (message_type IN ('email', 'sms', 'system', 'federated')) DEFAULT 'system',
    retry_count INTEGER DEFAULT 0,
    last_error TEXT,
    last_attempt TEXT
);

-- TAGS
CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
);

-- POST TAGS
CREATE TABLE IF NOT EXISTS post_tags (
    post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
    tag_id INTEGER REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (post_id, tag_id)
);

-- POST REACTIONS
CREATE TABLE IF NOT EXISTS post_reactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER REFERENCES posts(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    reaction TEXT CHECK (reaction IN ('like', 'dislike')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ANALYTICS MIDDLEWARE
CREATE TABLE IF NOT EXISTS analytics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    path TEXT NOT NULL,
    method TEXT NOT NULL,
    status INTEGER,
    duration INTEGER,
    ip TEXT,
    country TEXT,
    user_agent TEXT,
    referer TEXT,
    error TEXT,
    date_bucket TEXT GENERATED ALWAYS AS (date(timestamp)) STORED,
    hour_bucket INTEGER GENERATED ALWAYS AS (strftime('%H', timestamp)) STORED
);
