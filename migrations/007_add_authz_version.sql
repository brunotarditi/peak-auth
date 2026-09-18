-- Migration: Add authz_version column to users table for immediate token revocation
-- This column is incremented when a user's access is revoked from an application,
-- causing all existing access tokens to become invalid immediately.

ALTER TABLE users ADD COLUMN IF NOT EXISTS authz_version INTEGER NOT NULL DEFAULT 0;

-- Create an index for faster lookups during token verification
CREATE INDEX IF NOT EXISTS idx_users_authz_version ON users(authz_version);
