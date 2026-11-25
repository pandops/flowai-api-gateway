-- +goose Up

-- v0048: every FlowAI identifier is a positive 64-bit integer. Earlier rows
-- carry text identifiers that have no integer form; the DTU deployment is
-- wiped for this change, so they are removed rather than converted.
DELETE FROM api_gateway.working_token_records;
DELETE FROM api_gateway.derived_operator_team_access;
DELETE FROM api_gateway.membership_observations;
DELETE FROM api_gateway.oidc_sessions;
DELETE FROM api_gateway.oidc_team_mappings;
DELETE FROM api_gateway.operator_preferences;
DELETE FROM api_gateway.auth_audit;

CREATE SEQUENCE api_gateway.operator_id_seq AS bigint MINVALUE 1;

CREATE TABLE api_gateway.operators (
    operator_id bigint PRIMARY KEY DEFAULT nextval('api_gateway.operator_id_seq') CHECK (operator_id > 0),
    issuer text NOT NULL CHECK (issuer <> ''),
    subject text NOT NULL CHECK (subject <> ''),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT operators_identity_unique UNIQUE (issuer, subject)
);
ALTER SEQUENCE api_gateway.operator_id_seq OWNED BY api_gateway.operators.operator_id;

ALTER TABLE api_gateway.oidc_team_mappings DROP CONSTRAINT oidc_team_mappings_team_id_check;
ALTER TABLE api_gateway.oidc_team_mappings ALTER COLUMN team_id TYPE bigint USING team_id::bigint;
ALTER TABLE api_gateway.oidc_team_mappings ADD CONSTRAINT oidc_team_mappings_team_id_check CHECK (team_id > 0);

ALTER TABLE api_gateway.oidc_sessions DROP CONSTRAINT oidc_sessions_operator_id_check;
ALTER TABLE api_gateway.oidc_sessions ALTER COLUMN operator_id TYPE bigint USING operator_id::bigint;
ALTER TABLE api_gateway.oidc_sessions ADD CONSTRAINT oidc_sessions_operator_id_fkey FOREIGN KEY (operator_id) REFERENCES api_gateway.operators(operator_id);

ALTER TABLE api_gateway.derived_operator_team_access DROP CONSTRAINT derived_operator_team_access_operator_id_check;
ALTER TABLE api_gateway.derived_operator_team_access DROP CONSTRAINT derived_operator_team_access_team_id_check;
ALTER TABLE api_gateway.derived_operator_team_access DROP CONSTRAINT derived_operator_team_access_pkey;
ALTER TABLE api_gateway.derived_operator_team_access ALTER COLUMN operator_id TYPE bigint USING operator_id::bigint;
ALTER TABLE api_gateway.derived_operator_team_access ALTER COLUMN team_id TYPE bigint USING team_id::bigint;
ALTER TABLE api_gateway.derived_operator_team_access ADD PRIMARY KEY (session_id_hash, team_id);
ALTER TABLE api_gateway.derived_operator_team_access ADD CHECK (operator_id > 0 AND team_id > 0);

ALTER TABLE api_gateway.working_token_records ALTER COLUMN operator_id TYPE bigint USING operator_id::bigint;
ALTER TABLE api_gateway.working_token_records ALTER COLUMN team_id TYPE bigint USING team_id::bigint;
ALTER TABLE api_gateway.working_token_records ADD CHECK (operator_id > 0 AND team_id > 0);

ALTER TABLE api_gateway.operator_preferences DROP CONSTRAINT operator_preferences_operator_id_check;
ALTER TABLE api_gateway.operator_preferences ALTER COLUMN operator_id TYPE bigint USING operator_id::bigint;
ALTER TABLE api_gateway.operator_preferences ADD CHECK (operator_id > 0);

ALTER TABLE api_gateway.auth_audit ALTER COLUMN audit_id TYPE bigint USING audit_id::bigint;
ALTER TABLE api_gateway.auth_audit ALTER COLUMN operator_id TYPE bigint USING operator_id::bigint;
ALTER TABLE api_gateway.auth_audit ALTER COLUMN team_id TYPE bigint USING team_id::bigint;
ALTER TABLE api_gateway.auth_audit ALTER COLUMN request_id TYPE bigint USING request_id::bigint;

-- +goose Down

-- Integer identifiers cannot be narrowed back to the earlier text contract
-- without inventing values; a downgrade keeps the integer schema.
SELECT 1;
