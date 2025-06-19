-- name: RegisterDevice :exec
INSERT INTO user_devices (id, user_id, client_id, user_agent, ip, detached, last_visited_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: UpdateLastVisitedAt :exec
UPDATE user_devices
SET last_visited_at = $1
WHERE id = $2
  AND client_id = $3;

-- name: GetUserDeviceID :one
SELECT id
FROM user_devices
WHERE user_id = $1
  AND user_agent = $2
  AND client_id = $3
  AND detached = FALSE;

-- name: DeleteAllUserDevices :exec
DELETE FROM user_devices
WHERE user_id = $1
  AND client_id = $2;