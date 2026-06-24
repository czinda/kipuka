-- Migration v2: Add composite index on otp_tokens for efficient hash lookup.
CREATE INDEX IF NOT EXISTS idx_otp_tokens_hash ON otp_tokens (entity_id, token_hash);
