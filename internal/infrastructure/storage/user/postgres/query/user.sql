-- name: GetUserByID :one
SELECT id, email, client_id, verified, updated_at
FROM users
WHERE id = $1
  AND client_id = $2
  AND deleted_at IS NULL;

-- name: GetUserByEmail :one
SELECT id, email, client_id, updated_at
FROM users
WHERE email = $1
  AND client_id = $2
  AND deleted_at IS NULL;

-- name: GetUserData :one
SELECT id, email, password_hash, client_id, updated_at
FROM users
WHERE id = $1
  AND client_id = $2
  AND deleted_at IS NULL;

-- name: DeleteUser :exec
UPDATE users
SET deleted_at = $1
WHERE id = $2
  AND client_id = $3
  AND deleted_at IS NULL;

-- name: GetUserStatusByEmail :one
SELECT CASE
           WHEN EXISTS(
               SELECT 1
               FROM users
               WHERE users.email = $1
                 AND users.client_id = $2
                 AND deleted_at IS NULL
           ) THEN 'active'
           WHEN EXISTS(
               SELECT 1
               FROM users
               WHERE users.email = $1
                 AND users.client_id = $2
                 AND deleted_at IS NOT NULL
           ) THEN 'soft_deleted'
           ELSE 'not_found' END AS status;

-- name: GetUserStatusByID :one
SELECT CASE
           WHEN EXISTS(
               SELECT 1
               FROM users
               WHERE users.id = $1
                 AND users.client_id = $2
                 AND deleted_at IS NULL
           ) THEN 'active'
           WHEN EXISTS(
               SELECT 1
               FROM users
               WHERE users.id = $1
                 AND users.client_id = $2
                 AND deleted_at IS NOT NULL
           ) THEN 'soft_deleted'
           ELSE 'not_found' END AS status;