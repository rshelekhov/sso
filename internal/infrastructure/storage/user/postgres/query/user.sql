-- name: GetUserByID :one
SELECT id, email, name,verified, updated_at
FROM users
WHERE id = $1
  AND deleted_at IS NULL;

-- name: GetUserByEmail :one
SELECT id, email, name, updated_at
FROM users
WHERE email = $1
  AND deleted_at IS NULL;

-- name: GetUserData :one
SELECT id, email, name, password_hash, updated_at
FROM users
WHERE id = $1
  AND deleted_at IS NULL;

-- name: DeleteUser :exec
UPDATE users
SET deleted_at = $1
WHERE id = $2
  AND deleted_at IS NULL;

-- name: GetUserStatusByEmail :one
SELECT CASE
           WHEN EXISTS(
               SELECT 1
               FROM users
               WHERE users.email = $1
                 AND deleted_at IS NULL
           ) THEN 'active'
           WHEN EXISTS(
               SELECT 1
               FROM users
               WHERE users.email = $1
                 AND deleted_at IS NOT NULL
           ) THEN 'soft_deleted'
           ELSE 'not_found' END AS status;

-- name: GetUserStatusByID :one
SELECT CASE
           WHEN EXISTS(
               SELECT 1
               FROM users
               WHERE users.id = $1
                 AND deleted_at IS NULL
           ) THEN 'active'
           WHEN EXISTS(
               SELECT 1
               FROM users
               WHERE users.id = $1
                 AND deleted_at IS NOT NULL
           ) THEN 'soft_deleted'
           ELSE 'not_found' END AS status;

-- name: SearchUsers :many
SELECT id, email, name, verified, created_at, updated_at
FROM users
WHERE deleted_at IS NULL
  AND (
    email ILIKE '%' || sqlc.arg(query)::text || '%'
    OR name ILIKE '%' || sqlc.arg(query)::text || '%'
  )
  AND (
    -- Cursor filtering: return results BEFORE the cursor (created_at < cursor OR (created_at = cursor AND id < cursor_id))
    sqlc.narg(cursor_created_at)::timestamptz IS NULL
    OR created_at < sqlc.narg(cursor_created_at)::timestamptz
    OR (created_at = sqlc.narg(cursor_created_at)::timestamptz
        AND id < sqlc.narg(cursor_id)::text)
  )
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_size)::int;

-- name: CountSearchUsers :one
SELECT COUNT(*)
FROM users
WHERE deleted_at IS NULL
  AND (
    email ILIKE '%' || sqlc.arg(query)::text || '%'
    OR name ILIKE '%' || sqlc.arg(query)::text || '%'
  );