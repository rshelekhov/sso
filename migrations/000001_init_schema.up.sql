CREATE TABLE IF NOT EXISTS users
(
    id            character varying PRIMARY KEY,
    email         character varying NOT NULL,
    password_hash character varying NOT NULL,
    role          character varying NOT NULL,
    app_id        character varying NOT NULL,
    verified      boolean DEFAULT false,
    created_at    timestamp WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at    timestamp WITH TIME ZONE NOT NULL DEFAULT now(),
    deleted_at    timestamp WITH TIME ZONE DEFAULT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_active_users ON users (email, app_id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS token_types
(
    id    int PRIMARY KEY,
    title character varying NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS tokens
(
    token         character varying PRIMARY KEY,
    user_id       character varying NOT NULL,
    app_id        character varying NOT NULL,
    endpoint      character varying NOT NULL,
    recipient     character varying NOT NULL,
    token_type_id int NOT NULL,
    created_at    timestamp WITH TIME ZONE NOT NULL DEFAULT now(),
    expires_at    timestamp WITH TIME ZONE NOT NULL,
    UNIQUE (token, user_id, token_type_id, app_id)
);

CREATE TABLE IF NOT EXISTS apps
(
    id         character varying PRIMARY KEY,
    name       character varying NOT NULL UNIQUE,
    secret     character varying NOT NULL UNIQUE,
    status     int NOT NULL,
    created_at timestamp WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at timestamp WITH TIME ZONE NOT NULL DEFAULT now(),
    deleted_at timestamp WITH TIME ZONE DEFAULT NULL
);


CREATE TABLE IF NOT EXISTS app_statuses
(
    id    int PRIMARY KEY,
    title character varying NOT NULL
);

CREATE TABLE IF NOT EXISTS user_devices
(
    id              character varying PRIMARY KEY,
    user_id         character varying NOT NULL,
    app_id          character varying NOT NULL,
    user_agent      character varying NOT NULL,
    ip              character varying NOT NULL,
    detached        boolean NOT NULL,
    last_visited_at timestamp WITH TIME ZONE NOT NULL DEFAULT now(),
    detached_at     timestamp WITH TIME ZONE DEFAULT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_device ON user_devices (user_id, app_id, user_agent, ip);

ALTER TABLE users ADD FOREIGN KEY (app_id) REFERENCES apps(id);
ALTER TABLE tokens ADD FOREIGN KEY (user_id) REFERENCES users(id);
ALTER TABLE tokens ADD FOREIGN KEY (token_type_id) REFERENCES token_types(id);
ALTER TABLE tokens ADD FOREIGN KEY (app_id) REFERENCES apps(id);
ALTER TABLE user_devices ADD FOREIGN KEY (user_id) REFERENCES users(id);
ALTER TABLE user_devices ADD FOREIGN KEY (app_id) REFERENCES apps(id);
