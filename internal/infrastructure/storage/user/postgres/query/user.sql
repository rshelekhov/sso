-- name: GetUserByID :one
SELECT id, email, app_id, verified, updated_at
FROM users
WHERE id = $1
  AND app_id = $2
  AND deleted_at IS NULL;

-- name: GetUserByEmail :one
SELECT id, email, app_id, updated_at
FROM users
WHERE email = $1
  AND app_id = $2
  AND deleted_at IS NULL;

-- name: GetUserData :one
SELECT id, email, password_hash, app_id, updated_at
FROM users
WHERE id = $1
  AND app_id = $2
  AND deleted_at IS NULL;

-- name: DeleteUser :exec
UPDATE users
SET deleted_at = $1
WHERE id = $2
  AND app_id = $3
  AND deleted_at IS NULL;

-- name: GetUserStatusByEmail :one
SELECT CASE
           WHEN EXISTS(
               SELECT 1
               FROM users
               WHERE users.email = $1
                 AND users.app_id = $2
                 AND deleted_at IS NULL
           ) THEN 'active'
           WHEN EXISTS(
               SELECT 1
               FROM users
               WHERE users.email = $1
                 AND users.app_id = $2
                 AND deleted_at IS NOT NULL
           ) THEN 'soft_deleted'
           ELSE 'not_found' END AS status;

-- name: GetUserStatusByID :one
SELECT CASE
           WHEN EXISTS(
               SELECT 1
               FROM users
               WHERE users.id = $1
                 AND users.app_id = $2
                 AND deleted_at IS NULL
           ) THEN 'active'
           WHEN EXISTS(
               SELECT 1
               FROM users
               WHERE users.id = $1
                 AND users.app_id = $2
                 AND deleted_at IS NOT NULL
           ) THEN 'soft_deleted'
           ELSE 'not_found' END AS status;