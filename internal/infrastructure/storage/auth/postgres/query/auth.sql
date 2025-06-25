-- name: RegisterUser :exec
INSERT INTO users (id, email, password_hash, verified, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ReplaceSoftDeletedUser :exec
UPDATE users
SET
    id = $1,
    password_hash = $2,
    verified = $3,
    created_at = $4,
    updated_at = $5,
    deleted_at = NULL
WHERE email = $6
  AND deleted_at IS NOT NULL;

-- name: MarkEmailVerified :exec
UPDATE users
SET verified = TRUE
WHERE id = $1
  AND deleted_at IS NULL;