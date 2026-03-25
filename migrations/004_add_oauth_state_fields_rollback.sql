-- Rollback: remove OAuth state metadata fields

ALTER TABLE IF EXISTS oauth_states
    DROP COLUMN IF EXISTS nonce,
    DROP COLUMN IF EXISTS code_verifier,
    DROP COLUMN IF EXISTS user_agent,
    DROP COLUMN IF EXISTS redirect_path;
