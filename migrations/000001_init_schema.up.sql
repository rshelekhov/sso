CREATE TABLE IF NOT EXISTS users
(
    id            character varying PRIMARY KEY,
    email         character varying NOT NULL,
    password_hash character varying NOT NULL,
    app_id        character varying NOT NULL,
    created_at    timestamp WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at    timestamp WITH TIME ZONE NOT NULL DEFAULT now(),
    deleted_at    timestamp WITH TIME ZONE DEFAULT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_active_users ON users (email) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS apps
(
    id       character varying PRIMARY KEY,
    name     character varying NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS refresh_sessions
(
    id            SERIAL PRIMARY KEY,
    user_id       character varying NOT NULL,
    app_id        character varying NOT NULL,
    device_id     character varying NOT NULL,
    refresh_token character varying NOT NULL,
    last_login_at timestamp WITH TIME ZONE NOT NULL DEFAULT now(),
    expires_at    timestamp WITH TIME ZONE NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_active_sessions ON refresh_sessions (user_id, refresh_token);

CREATE TABLE IF NOT EXISTS user_devices
(
    id              character varying PRIMARY KEY,
    user_id         character varying NOT NULL,
    app_id          character varying NOT NULL,
    user_agent      character varying NOT NULL,
    ip              character varying NOT NULL,
    detached        boolean NOT NULL,
    last_login_at   timestamp WITH TIME ZONE NOT NULL DEFAULT now(),
    detached_at     timestamp WITH TIME ZONE DEFAULT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_device ON user_devices (user_id, user_agent, ip);

ALTER TABLE users ADD FOREIGN KEY (app_id) REFERENCES apps(id);
ALTER TABLE refresh_sessions ADD FOREIGN KEY (user_id) REFERENCES users(id);
ALTER TABLE refresh_sessions ADD FOREIGN KEY (app_id) REFERENCES apps(id);
ALTER TABLE user_devices ADD FOREIGN KEY (user_id) REFERENCES users(id);
ALTER TABLE user_devices ADD FOREIGN KEY (app_id) REFERENCES apps(id);
