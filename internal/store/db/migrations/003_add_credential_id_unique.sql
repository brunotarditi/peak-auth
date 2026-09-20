-- Migration: Add credential_id column with unique constraint to user_mfa_credentials
-- This prevents replay attacks by ensuring each WebAuthn credential can only be registered once

-- Add the credential_id column (nullable initially to allow existing records)
ALTER TABLE user_mfa_credentials ADD COLUMN IF NOT EXISTS credential_id VARCHAR(512);

-- Create a unique index on credential_id (excluding NULL values and soft-deleted records)
-- This ensures that each WebAuthn credential ID can only be registered once across all users
CREATE UNIQUE INDEX IF NOT EXISTS idx_credential_id 
ON user_mfa_credentials(credential_id) 
WHERE credential_id IS NOT NULL AND deleted_at IS NULL;

-- Note: Existing TOTP credentials will have NULL credential_id, which is fine
-- Only WebAuthn credentials will populate this field going forward
