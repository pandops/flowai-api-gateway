-- +goose Up

CREATE TABLE IF NOT EXISTS api_gateway.operator_preferences (
    operator_id text PRIMARY KEY CHECK (operator_id <> ''),
    time_zone text NOT NULL CHECK (length(time_zone) BETWEEN 1 AND 128),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down

-- A downgrade stops using preferences but preserves durable personal data.
-- The additive, independently keyed table is safe for the previous executable.
SELECT 1;
