-- Rollback: remove OAuth state metadata fields

ALTER TABLE IF EXISTS oauth_states
    DROP COLUMN IF EXISTS nonce, -- remove OIDC nonce
    DROP COLUMN IF EXISTS code_verifier, -- remove PKCE verifier
    DROP COLUMN IF EXISTS user_agent, -- remove UA binding
    DROP COLUMN IF EXISTS redirect_path; -- remove frontend redirect path
