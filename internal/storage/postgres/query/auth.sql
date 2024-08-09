-- name: CheckAppIDExists :one
SELECT EXISTS(SELECT 1 FROM apps WHERE id = $1);

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

-- name: GetUserDeviceID :one
SELECT id
FROM user_devices
WHERE user_id = $1
  AND user_agent = $2
  AND detached = FALSE;

-- name: UpdateLatestLoginAt :exec
UPDATE user_devices
SET last_visited_at = $1
WHERE id = $2
  AND app_id = $3;

-- name: RegisterDevice :exec
INSERT INTO user_devices (id, user_id, app_id, user_agent, ip, detached, last_visited_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: CreateUserSession :exec
INSERT INTO refresh_sessions (user_id, app_id, device_id, refresh_token, last_visited_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetSessionByRefreshToken :one
SELECT user_id, app_id, device_id, last_visited_at, expires_at
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

-- name: DeleteAllSessions :exec
DELETE FROM refresh_sessions
WHERE user_id = $1
  AND app_id = $2;

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