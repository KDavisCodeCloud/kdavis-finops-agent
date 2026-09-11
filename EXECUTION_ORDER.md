# EXECUTION_ORDER.md — kdavis-finops-agent

Numbered phase sequence. Do not reorder. Do not start the next phase
without Kelvin's go-ahead — each phase ends with a status summary and a
stop, same discipline as `kdavis-cloud-audit`'s own file.

## Phase 1 — AWS-only MVP (in progress)

1. Repo scaffold, `db/migrations/001_finops_core.sql`
   (`finops_tenants`/`finops_scans`/`finops_hitl_queue`, RLS +
   service-role-first policies).
2. `core/aws_onboarding.py` — external ID generation, trust-policy JSON
   generation (principal: `FINOPS_AWS_ACCOUNT_ID`, condition:
   `sts:ExternalId`), permissions-policy JSON scoped to exactly what
   `AWSProvider.collect()` reads (not the broad `ReadOnlyAccess` managed
   policy), `assume_role` verification.
3. `api/middleware/auth.py` — `X-Tenant-Token` auth, same shape as Cloud
   Decoded's `get_workspace`.
4. `api/routes/tenants.py` — `POST /tenants` (create + return setup
   instructions), `PATCH /tenants/{id}/aws-role` (verify), `GET
   /tenants/{id}/dashboard` (latest scan + open HITL items), `GET
   /tenants/{id}/scans` (history).
5. `agents/finops_analysis.py` — one LLM call groups/prioritizes raw
   findings into HITL queue items. Plain sequential code, no LangGraph
   (see its own module docstring for why).
6. `api/routes/scans.py` — `POST /tenants/{id}/scan`: assume the stored
   role fresh, build a `boto3.Session` from the temp credentials, run
   kdavis-cloud-audit's `AWSProvider(session=...).collect()`, sanitize via
   kdavis-cloud-audit's `sanitize_findings`, store, analyze, return the
   full result synchronously (same shape as Cloud Decoded's
   `POST /audit/submit`).
7. `api/routes/hitl.py` — `POST /hitl/{item_id}/approve|dismiss`. Terminal
   status change only, never triggers execution.
8. Tests alongside every module above (mock `boto3`/`asyncpg`, no real AWS
   calls in unit tests).

**Phase 1 complete signal:** `✅ FINOPS AGENT CORE READY`. Stop and wait.

## Phase 2 — Azure onboarding (not started)

Same shape as AWS: Service Principal (app_id + tenant_id + client_secret,
the secret encrypted at rest via `ENCRYPTION_KEY`/Fernet — provisioned but
unused in Phase 1), `AzureProvider(credential=ClientSecretCredential(...),
subscription_id=...)` from kdavis-cloud-audit, same scan/HITL flow reused
as-is (provider-agnostic already).

## Phase 3 — Scheduling + Reporter (not started)

A "Monitor" that runs scans on a schedule (needs a scheduler decision:
Railway cron hitting an internal trigger endpoint vs. an in-process
APScheduler — evaluate both before building) instead of only
manually-triggered. A weekly digest ("Reporter") summarizing new findings
since the last scan.

## Phase 4 — Frontend dashboard (not started)

Mirrors the pattern just built for Cloud Decoded's Cloud Audit tab
(`kdavis-agentic-platform/frontend/src/components/AuditDashboard.tsx` +
`AuditRemediationItemCard.tsx`) — list of tenants/scans, remediation items
with approve/dismiss. Decide then whether this lives as its own Next.js
app or (more likely, per the portfolio's `no-separate-dashboards`
convention) a route inside an existing dashboard.

## Phase 5 — Billing (not started)

Stripe subscription gating, matching Cloud Decoded's
`api/routes/stripe_billing.py` pattern once there's a product to charge
for.
