DELETE FROM tokens WHERE token_type_id IN (SELECT id FROM token_types);
DELETE FROM token_types;
DELETE FROM app_statuses;