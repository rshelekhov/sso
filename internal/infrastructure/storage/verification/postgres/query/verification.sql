-- name: SaveVerificationToken :exec
INSERT INTO tokens (token, user_id, app_id, endpoint, recipient, token_type_id,  created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetVerificationTokenData :one
SELECT token, user_id, app_id, endpoint, token_type_id, recipient, expires_at
FROM tokens
WHERE token = $1;

-- name: DeleteVerificationToken :exec
DELETE FROM tokens
WHERE token = $1;


-- name: DeleteAllVerificationTokens :exec
DELETE FROM tokens
WHERE user_id = $1
  AND app_id = $2;