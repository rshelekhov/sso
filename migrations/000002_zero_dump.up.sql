INSERT INTO token_types
(id, title)
VALUES
    (0, 'verify_email'),
    (1, 'reset_password');

INSERT INTO client_statuses
(id, title)
VALUES
    (0, 'inactive'),
    (1, 'active'),
    (2, 'deleted');