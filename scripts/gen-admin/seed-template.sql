-- Ensure table exists
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

INSERT INTO users (username, email, password, salt, role)
VALUES ('{{USERNAME}}', '{{EMAIL}}', '{{PASSWORD}}', '{{SALT}}', 'admin');