-- name: CreateUserSession :exec
INSERT INTO refresh_sessions (user_id, app_id, device_id, refresh_token, last_visited_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetSessionByRefreshToken :one
SELECT user_id, app_id, device_id, last_visited_at, expires_at
FROM refresh_sessions
WHERE refresh_token = $1;

-- name: UpdateLastVisitedAt :exec
UPDATE user_devices
SET last_visited_at = $1
WHERE id = $2
  AND app_id = $3;

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

-- name: DeleteAllUserDevices :exec
DELETE FROM user_devices
WHERE user_id = $1
  AND app_id = $2;


-- name: GetUserDeviceID :one
SELECT id
FROM user_devices
WHERE user_id = $1
  AND user_agent = $2
  AND detached = FALSE;

-- name: RegisterDevice :exec
INSERT INTO user_devices (id, user_id, app_id, user_agent, ip, detached, last_visited_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);