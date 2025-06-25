-- name: InsertClient :exec
INSERT INTO clients (id, name, secret, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: DeleteClient :exec
UPDATE clients
SET deleted_at = $1
WHERE id = $2
  AND secret = $3
  AND deleted_at IS NULL;

-- name: CheckClientIDExists :one
SELECT EXISTS(
    SELECT 1
    FROM clients
    WHERE id = $1
        AND deleted_at IS NULL
    );