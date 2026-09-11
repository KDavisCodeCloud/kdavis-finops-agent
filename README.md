# kdavis-finops-agent

Continuous cloud-cost-and-security monitoring, the paid upgrade from
[kdavis-cloud-audit](https://github.com/KDavisCodeCloud/kdavis-cloud-audit)'s
free one-shot CLI. A customer grants read-only, revocable access to their
cloud account; this service scans it, an LLM turns findings into a
prioritized remediation plan, and every action item sits in a
human-approval queue. **Nothing here ever auto-executes a remediation.**

**Status:** Phase 1 (AWS-only MVP) — see `EXECUTION_ORDER.md`.

## How a customer connects their AWS account

1. `POST /tenants` with `{"company_name": "..."}` — returns a tenant
   token (save it, shown once) plus a trust-policy JSON and a
   permissions-policy JSON to paste into AWS.
2. In AWS: create an IAM role using the trust policy (grants this
   service's AWS account permission to assume it, gated by a unique
   external ID — nobody else can assume your role even if they guess the
   ARN) and attach the permissions policy (read-only, scoped to exactly
   what gets scanned — not a broad managed policy).
3. `PATCH /tenants/{id}/aws-role` with `{"role_arn": "..."}` — verifies
   the role actually works before marking the tenant active.
4. `POST /tenants/{id}/scan` — runs a real scan, returns findings + a
   prioritized remediation plan.
5. `GET /tenants/{id}/dashboard` any time after — latest scan + open
   items. `POST /hitl/{item_id}/approve` or `/dismiss` to act on one.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in DATABASE_URL, ANTHROPIC_API_KEY, FINOPS_AWS_ACCOUNT_ID
```

## Run

```bash
uvicorn api.main:app --reload --port 8001
```

## Test

```bash
pytest tests/ -v
```
