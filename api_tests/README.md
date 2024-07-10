# Before testing

- Connect to PostgresQL
- Insert into database the test app with this data:
  INSERT INTO apps (id, name, secret, status, created_at, updated_at)
  VALUES ('test-app-id', 'test', 'test-secret', 1, NOW(), NOW())
  ON CONFLICT DO NOTHING;