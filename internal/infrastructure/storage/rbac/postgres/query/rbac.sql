-- name: GetUserRole :one
SELECT role
FROM users
WHERE id = $1
  AND app_id = $2
  AND deleted_at IS NULL;

-- name: SetUserRole :one
UPDATE users
SET role = $1
WHERE id = $2
  AND app_id = $3
  AND deleted_at IS NULL
RETURNING id;