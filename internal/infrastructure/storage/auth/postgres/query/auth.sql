-- name: RegisterUser :exec
INSERT INTO users (id, email, password_hash, client_id, verified, created_at,updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ReplaceSoftDeletedUser :exec
UPDATE users
SET
    id = $1,
    password_hash = $2,
    client_id = $3,
    verified = $4,
    created_at = $5,
    updated_at = $6,
    deleted_at = NULL
WHERE email = $7
  AND deleted_at IS NOT NULL;

-- name: MarkEmailVerified :exec
UPDATE users
SET verified = TRUE
WHERE id = $1
  AND client_id = $2
  AND deleted_at IS NULL;