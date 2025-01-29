-- name: RegisterUser :exec
INSERT INTO users (id, email, password_hash, app_id, verified, created_at,updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: MarkEmailVerified :exec
UPDATE users
SET verified = TRUE
WHERE id = $1
  AND app_id = $2
  AND deleted_at IS NULL;