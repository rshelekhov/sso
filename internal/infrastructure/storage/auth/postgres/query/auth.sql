-- name: RegisterUser :exec
INSERT INTO users (id, email, password_hash, role, app_id, verified, created_at,updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: ReplaceSoftDeletedUser :exec
UPDATE users
SET
    id = $1,
    password_hash = $2,
    role = $3,
    app_id = $4,
    verified = $5,
    created_at = $6,
    updated_at = $7,
    deleted_at = NULL
WHERE email = $7
  AND deleted_at IS NOT NULL;

-- name: MarkEmailVerified :exec
UPDATE users
SET verified = TRUE
WHERE id = $1
  AND app_id = $2
  AND deleted_at IS NULL;