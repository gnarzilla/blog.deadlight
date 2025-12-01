ALTER TABLE notifications ADD COLUMN retry_count INTEGER DEFAULT 0;
ALTER TABLE notifications ADD COLUMN last_error TEXT;
ALTER TABLE notifications ADD COLUMN last_attempt TEXT;
