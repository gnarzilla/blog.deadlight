-- Migration to add missing columns to existing tables as of August 15, 2025

-- Add missing columns to posts table
ALTER TABLE posts ADD COLUMN parent_id INTEGER REFERENCES posts(id) ON DELETE SET NULL;
ALTER TABLE posts ADD COLUMN thread_id INTEGER REFERENCES posts(id) ON DELETE SET NULL;
ALTER TABLE posts ADD COLUMN federation_pending INTEGER DEFAULT 0;
ALTER TABLE posts ADD COLUMN federation_sent_at TIMESTAMP;
ALTER TABLE posts ADD COLUMN federation_metadata TEXT;
ALTER TABLE posts ADD COLUMN post_type TEXT CHECK (post_type IN ('blog', 'email', 'comment', 'federated')) DEFAULT 'blog';
ALTER TABLE posts ADD COLUMN retry_count INTEGER DEFAULT 0;
ALTER TABLE posts ADD COLUMN last_error TEXT;
ALTER TABLE posts ADD COLUMN last_attempt TIMESTAMP;
ALTER TABLE posts ADD COLUMN comments_enabled BOOLEAN DEFAULT TRUE;

-- Add FOREIGN KEY for author_id (SQLite doesn't support post-creation, so recreate if necessary; skip for now if data exists)
-- Note: If needed, backup data, drop table, recreate with FK, and restore.

-- Other tables are already present; no changes needed unless specified.