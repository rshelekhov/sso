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

-- name: GetUserByEmail :one
SELECT id, email, app_id, updated_at
FROM users
WHERE email = $1
  AND app_id = $2
  AND deleted_at IS NULL;

-- name: GetUserByID :one
SELECT id, email, app_id, updated_at
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

-- name: GetUserDeviceID :one
SELECT id
FROM user_devices
WHERE user_id = $1
  AND user_agent = $2
  AND detached = FALSE;

-- name: UpdateLatestLoginAt :exec
UPDATE user_devices
SET last_login_at = $1
WHERE id = $2
  AND app_id = $3;

-- name: RegisterDevice :exec
INSERT INTO user_devices (id, user_id, app_id, user_agent, ip, detached, last_login_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: CreateUserSession :exec
INSERT INTO refresh_sessions (user_id, app_id, device_id, refresh_token, last_login_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetSessionByRefreshToken :one
SELECT user_id, app_id, device_id, last_login_at, expires_at
FROM refresh_sessions
WHERE refresh_token = $1;

-- name: DeleteRefreshTokenFromSession :exec
DELETE FROM refresh_sessions
WHERE refresh_token = $1;

-- name: DeleteSession :exec
DELETE FROM refresh_sessions
WHERE user_id = $1
  AND app_id = $2
  AND device_id = $3;

-- name: DeleteUser :exec
UPDATE users
SET deleted_at = $1
WHERE id = $2
  AND app_id = $3
  AND deleted_at IS NULL;