-- Migration 001: finops_tenants, finops_scans, finops_hitl_queue
--
-- Phase 1 of kdavis-finops-agent. Lives in the same shared Postgres
-- instance as the rest of the Decoded Empire portfolio (microsaas-prod)
-- rather than provisioning new infrastructure -- matches this session's
-- established convention. Confirmed no collision with any existing table
-- there at the time this was written.
--
-- No resume/execution flow on finops_hitl_queue: approving an item is a
-- terminal status change a human acts on manually, never automatic.

CREATE TABLE IF NOT EXISTS finops_tenants (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_name        VARCHAR(255) NOT NULL,
    tenant_token        VARCHAR(255) UNIQUE NOT NULL,  -- SHA-256 hash, raw token never stored
    aws_role_arn        TEXT,
    aws_external_id     VARCHAR(64) NOT NULL,
    aws_verified_at     TIMESTAMPTZ,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending_setup',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS finops_scans (
    id                                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                          UUID NOT NULL REFERENCES finops_tenants(id) ON DELETE CASCADE,
    provider                           VARCHAR(20) NOT NULL,
    status                             VARCHAR(20) NOT NULL DEFAULT 'running',
    error_message                      TEXT,
    total_findings                     INT NOT NULL DEFAULT 0,
    total_estimated_monthly_waste_usd  NUMERIC(10,2) NOT NULL DEFAULT 0,
    started_at                         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at                       TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS finops_hitl_queue (
    id                            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id                       UUID NOT NULL REFERENCES finops_scans(id) ON DELETE CASCADE,
    tenant_id                     UUID NOT NULL REFERENCES finops_tenants(id) ON DELETE CASCADE,
    severity                      VARCHAR(10) NOT NULL,
    category                      VARCHAR(20) NOT NULL,
    title                         TEXT NOT NULL,
    description                   TEXT NOT NULL,
    remediation                   TEXT NOT NULL,
    estimated_monthly_waste_usd   NUMERIC(10,2) NOT NULL DEFAULT 0,
    priority_rank                 INT NOT NULL,
    status                        VARCHAR(20) NOT NULL DEFAULT 'pending_approval',
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actioned_at                   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_finops_scans_tenant ON finops_scans (tenant_id);
CREATE INDEX IF NOT EXISTS idx_finops_hitl_scan ON finops_hitl_queue (scan_id);
CREATE INDEX IF NOT EXISTS idx_finops_hitl_tenant ON finops_hitl_queue (tenant_id);

ALTER TABLE finops_tenants ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_all" ON finops_tenants
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "tenant_read" ON finops_tenants
  FOR SELECT TO authenticated
  USING (id = (current_setting('app.tenant_id')::uuid));

ALTER TABLE finops_scans ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_all" ON finops_scans
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "tenant_read" ON finops_scans
  FOR SELECT TO authenticated
  USING (tenant_id = (current_setting('app.tenant_id')::uuid));

ALTER TABLE finops_hitl_queue ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_all" ON finops_hitl_queue
  FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "tenant_read" ON finops_hitl_queue
  FOR SELECT TO authenticated
  USING (tenant_id = (current_setting('app.tenant_id')::uuid));
