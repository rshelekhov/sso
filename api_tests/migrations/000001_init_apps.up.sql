INSERT INTO apps (id, name)
VALUES ('test-app-id', 'test')
ON CONFLICT DO NOTHING;