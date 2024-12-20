-- name: CheckAppIDExists :one
SELECT EXISTS(SELECT 1 FROM apps WHERE id = $1);

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

-- name: RegisterUser :exec
INSERT INTO users (id, email, password_hash, app_id, verified, created_at,updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: CreateToken :exec
INSERT INTO tokens (token, user_id, app_id, endpoint, recipient, token_type_id,  created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetTokenData :one
SELECT token, user_id, app_id, endpoint, token_type_id, recipient, expires_at
FROM tokens
WHERE token = $1;

-- name: GetUserIDByToken :one
SELECT user_id
FROM tokens
WHERE token = $1;

-- name: MarkEmailVerified :exec
UPDATE users
SET verified = TRUE
WHERE id = $1
  AND app_id = $2
  AND deleted_at IS NULL;

-- name: GetUserByEmail :one
SELECT id, email, app_id, updated_at
FROM users
WHERE email = $1
  AND app_id = $2
  AND deleted_at IS NULL;

-- name: GetUserByID :one
SELECT id, email, app_id, verified, updated_at
FROM users
WHERE id = $1
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

-- name: DeleteAllTokens :exec
DELETE FROM tokens
WHERE user_id = $1
  AND app_id = $2;

-- name: DeleteToken :exec
DELETE FROM tokens
WHERE token = $1;