-- Add composite index for cursor-based pagination
-- This index supports ORDER BY created_at DESC, id DESC with WHERE deleted_at IS NULL
CREATE INDEX IF NOT EXISTS idx_users_search_cursor
ON users (created_at DESC, id DESC)
WHERE deleted_at IS NULL;

-- Add index for name searches with partial index for active users only
-- Email already has idx_active_users which covers email searches
CREATE INDEX IF NOT EXISTS idx_users_name_active
ON users (name)
WHERE deleted_at IS NULL;

-- Note: For ILIKE queries, PostgreSQL will use index scans when appropriate
-- If you need fuzzy/trigram search, consider enabling pg_trgm extension:
-- CREATE EXTENSION IF NOT EXISTS pg_trgm;
-- CREATE INDEX idx_users_name_trgm ON users USING gin (name gin_trgm_ops) WHERE deleted_at IS NULL;
