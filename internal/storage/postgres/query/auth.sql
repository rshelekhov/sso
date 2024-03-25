-- name: GetUserStatus :one
SELECT CASE
WHEN EXISTS(
    SELECT 1
    FROM users
    WHERE users.email = $1
      AND deleted_at IS NULL FOR UPDATE
    ) THEN 'active'
    WHEN EXISTS(
    SELECT 1
    FROM users
    WHERE users.email = $1
      AND deleted_at IS NOT NULL FOR UPDATE
    ) THEN 'soft_deleted'
ELSE 'not_found' END AS status;

-- name: SetDeletedUserAtNull :exec
UPDATE users
SET deleted_at = NULL
WHERE email = $1;

-- name: InsertUser :exec
INSERT INTO users (id, email, password_hash, app_id,updated_at)
VALUES ($1, $2, $3, $4, $5);