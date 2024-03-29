INSERT INTO apps (id, name, sign_key)
VALUES (1, 'test', 'test-sign-key')
ON CONFLICT DO NOTHING;