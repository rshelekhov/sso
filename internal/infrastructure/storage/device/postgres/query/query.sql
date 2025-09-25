-- name: RegisterDevice :exec
INSERT INTO user_devices (id, user_id, user_agent, ip, detached, last_visited_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: UpdateLastVisitedAt :exec
UPDATE user_devices
SET last_visited_at = $1
WHERE id = $2;

-- name: GetUserDeviceID :one
SELECT id
FROM user_devices
WHERE user_id = $1
  AND user_agent = $2
  AND detached = FALSE;

-- name: DeleteAllUserDevices :one
WITH deleted AS (
  DELETE FROM user_devices
  WHERE user_id = $1 AND detached = FALSE
  RETURNING 1
)
SELECT COUNT(*)::int AS deleted_count
FROM deleted;