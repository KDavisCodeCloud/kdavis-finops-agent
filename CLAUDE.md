# CLAUDE.md — kdavis-finops-agent

## What this is

The paid continuous cloud-cost-and-security monitoring product. Where
`kdavis-cloud-audit` is a free, one-shot, local CLI a prospect runs
against their own credentials, this is a hosted service: a customer grants
**read-only, revocable** access to their cloud account (AWS cross-account
IAM role in Phase 1; Azure Service Principal in Phase 2), and this service
scans it, analyzes findings with an LLM into a prioritized remediation
plan, and holds every action item in a human-approval queue.

**Non-negotiable, inherited from `kdavis-cloud-audit` and the wider THD
Agentic Systems rules: nothing here ever auto-executes a remediation.**
Approving an item is a terminal status change a human acts on manually —
there is no "resume and run this fix" code path anywhere in this repo, by
design, not as a missing feature.

## Key architectural decision: depends on kdavis-cloud-audit

This repo does not reimplement AWS/Azure scanning logic. It depends on
`kdavis-cloud-audit` (https://github.com/KDavisCodeCloud/kdavis-cloud-audit)
as a package and reuses its `audit.providers.aws.AWSProvider`,
`audit.providers.azure.AzureProvider`, `audit.findings.Finding`, and
`audit.sanitizer.sanitize_findings` directly. Both provider classes accept
injected credentials (`AWSProvider(session=...)`,
`AzureProvider(credential=..., subscription_id=...)`) — built for a local
CLI picking up the operator's own credentials, but the exact same
mechanism lets this service inject a customer's **assumed cross-account
role** credentials instead. Zero changes to kdavis-cloud-audit needed.

Do not duplicate scanning logic here. If a new AWS/Azure check is needed,
it belongs in `kdavis-cloud-audit`'s providers, with this repo's
`requirements.txt` pin bumped to pick it up.

## Stack

Python 3.11+, FastAPI, asyncpg, boto3, (Phase 2: azure-identity +
azure-mgmt-*), Anthropic SDK direct (see `providers/llm.py` — an
LLM-agnostic seam per the global non-negotiable, kept minimal for a
single-provider Phase 1 rather than a full multi-provider router), pytest.

**No LangGraph.** Every analysis step here is one LLM call with no
branching and no resume path — see `agents/finops_analysis.py`'s module
docstring for the full reasoning (identical to
`kdavis-agentic-platform/agents/audit_analysis/workflow.py`'s, which this
module mirrors).

## Database

Shares the same Postgres instance as the rest of the Decoded Empire
portfolio (`microsaas-prod`) rather than provisioning new infrastructure —
matches this session's established convention. Tables are prefixed
`finops_*`; confirmed no collision with any existing table in that
database at the time this was built (`finops_tenants`, `finops_scans`,
`finops_hitl_queue` — see `db/migrations/001_finops_core.sql`).

RLS follows the `current_setting('app.tenant_id')` idiom (this backend has
no Supabase Auth wiring — connects with an effectively service-role
connection string), not `auth.uid()`.

## Auth

`X-Tenant-Token` header, SHA-256 hashed before lookup, never stored in
plaintext — the exact same pattern as `kdavis-agentic-platform`'s
`workspace_token`/`get_workspace`. Can't literally share the code
(different repo, that one's proprietary), so `api/middleware/auth.py` is a
small, deliberate reimplementation of the same shape, not a dependency.

## Non-negotiables (inherited from THD Agentic Systems global rules)

- tenant_id on every table.
- No hardcoded secrets — `FINOPS_AWS_ACCOUNT_ID`, `DATABASE_URL`,
  `ANTHROPIC_API_KEY`, `ENCRYPTION_KEY` all from environment only.
- No auto-execution of any remediation, ever.
- No silent failures — a failed scan or failed analysis is stored with a
  clear `error_message`/`analysis_error`, never swallowed.
- Tests written alongside each module, not after.

## Current status

Phase: 1 (AWS-only MVP) in progress. See `EXECUTION_ORDER.md` for the full
phase sequence and what's explicitly deferred.
