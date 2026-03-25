-- Add server-side OAuth state metadata fields
-- Adds redirect_path, user_agent, code_verifier, and nonce columns

ALTER TABLE IF EXISTS oauth_states
    ADD COLUMN IF NOT EXISTS redirect_path VARCHAR(255),
    ADD COLUMN IF NOT EXISTS user_agent TEXT,
    ADD COLUMN IF NOT EXISTS code_verifier VARCHAR(255),
    ADD COLUMN IF NOT EXISTS nonce VARCHAR(255);
