CREATE TABLE dpop_replays (
    jti_digest bytea PRIMARY KEY CHECK (octet_length(jti_digest) = 32),
    expires_at timestamptz NOT NULL
);
CREATE INDEX dpop_replays_expiry_idx ON dpop_replays (expires_at);
