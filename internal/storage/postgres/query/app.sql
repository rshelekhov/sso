-- name: InsertApp :exec
INSERT INTO apps (id, name, secret, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: DeleteApp :exec
UPDATE apps
SET deleted_at = $1
WHERE id = $2
  AND secret = $3
    AND deleted_at IS NULL;