-- Migration 002: Azure Service Principal onboarding columns on finops_tenants
--
-- Additive only -- every new column is nullable, existing AWS-connected
-- rows are untouched. connected_provider is the explicit discriminator
-- scan dispatch branches on (matches this repo's own existing idiom:
-- finops_scans.provider is already an explicit string column, not
-- inferred from which fields are populated).
--
-- azure_client_secret_encrypted holds real secret material (unlike AWS's
-- external_id, which isn't sensitive) -- encrypted via security/
-- encryption.py (Fernet/ENCRYPTION_KEY) before it's ever written here.
--
-- Provider-switch behavior (decided, not left implicit): if a tenant
-- that's already connected to one provider onboards the other, the new
-- onboarding route nulls out the old provider's credential columns on
-- success -- no orphaned secrets left behind, connected_provider always
-- reflects the one currently active connection.

ALTER TABLE finops_tenants ADD COLUMN IF NOT EXISTS connected_provider VARCHAR(10);
ALTER TABLE finops_tenants ADD COLUMN IF NOT EXISTS azure_tenant_id TEXT;
ALTER TABLE finops_tenants ADD COLUMN IF NOT EXISTS azure_client_id TEXT;
ALTER TABLE finops_tenants ADD COLUMN IF NOT EXISTS azure_client_secret_encrypted TEXT;
ALTER TABLE finops_tenants ADD COLUMN IF NOT EXISTS azure_subscription_id TEXT;
ALTER TABLE finops_tenants ADD COLUMN IF NOT EXISTS azure_verified_at TIMESTAMPTZ;

-- Backfill: every existing row with a verified AWS role is, by
-- definition, currently connected via AWS -- make that explicit rather
-- than leaving connected_provider NULL for pre-existing tenants.
UPDATE finops_tenants SET connected_provider = 'aws' WHERE aws_verified_at IS NOT NULL AND connected_provider IS NULL;
