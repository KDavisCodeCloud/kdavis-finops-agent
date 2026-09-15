# kdavis-finops-agent

Continuous cloud-cost-and-security monitoring — the paid, hosted upgrade
from [kdavis-cloud-audit](https://github.com/KDavisCodeCloud/kdavis-cloud-audit)'s
free one-shot CLI. A customer grants this service read-only, revocable
access to their AWS or Azure account; it scans the account, automatically turns
the findings into a prioritized remediation plan, and every action item
sits in a human-approval queue. **Nothing here ever auto-executes a
remediation** — approving an item is a terminal status change a human
acts on manually; there is no "resume and run this fix" code path
anywhere in this repo, by design.

This service does not reimplement AWS/Azure scanning logic itself. It
depends on `kdavis-cloud-audit` as a package and calls its
`AWSProvider`/`AzureProvider`/`sanitize_findings` directly, injecting a
customer's assumed-role (AWS) or Service Principal (Azure) credentials in
place of a local operator's own.

Both AWS cross-account role onboarding and Azure Service Principal
onboarding are implemented and wired into the API (`api/routes/tenants.py`,
`core/aws_onboarding.py`, `core/azure_onboarding.py`, migration
`002_finops_azure_onboarding.sql`) — despite `CLAUDE.md`'s own status
line still reading "Phase 1 (AWS-only MVP)", that line is stale relative
to the code. A tenant can connect either provider, and re-onboarding with
the other cloud cuts over cleanly (the previous provider's credentials
are nulled out; `connected_provider` always reflects the one active
connection).

## Tech stack

- **Python 3.11+**, **FastAPI**, served via `uvicorn api.main:app`
- **asyncpg** against a shared Postgres instance (Supabase's
  transaction-mode pooler — `statement_cache_size=0` is set for that
  reason), tables prefixed `finops_*`, RLS via the
  `current_setting('app.tenant_id')` idiom
- **boto3** for AWS `sts:AssumeRole` cross-account access
- **azure-identity** + **azure-mgmt-*** (cost management, advisor,
  compute, storage, security, resource, monitor, network) for Azure
  Service Principal onboarding and scanning
- A model provider SDK, called directly through a small provider seam
  (`providers/llm.py`) rather than a full router — the model is
  pinned in one place
- **cryptography** (Fernet, `security/encryption.py`) to encrypt Azure
  client secrets before they're stored
- `kdavis-cloud-audit` as a git dependency, for the actual scanning
  providers and finding sanitizer
- **pytest** / **pytest-asyncio** / **pytest-cov**

There is no workflow engine here — every analysis step is a single model call with no
branching and no resume path (see `agents/finops_analysis.py`'s module
docstring).

## How a customer connects their account

**AWS:**
1. `POST /api/v1/tenants` with `{"company_name": "..."}` — returns a
   tenant token (shown once, save it) plus an AWS trust-policy JSON, an
   AWS permissions-policy JSON, and Azure setup instructions.
2. In AWS: create an IAM role using the trust policy (grants this
   service's AWS account permission to assume it, gated by a unique
   external ID) and attach the permissions policy (read-only, scoped to
   exactly what gets scanned).
3. `PATCH /api/v1/tenants/{id}/aws-role` with `{"role_arn": "..."}` —
   verifies the role actually works before marking the tenant active.

**Azure (alternative to AWS, or a later switch):**
1. Same `POST /api/v1/tenants` call above also returns
   `azure_setup_instructions`.
2. Create an Azure AD App Registration / Service Principal with
   read-only access to the subscription being monitored.
3. `PATCH /api/v1/tenants/{id}/azure-credentials` with
   `{"azure_tenant_id", "client_id", "client_secret", "subscription_id"}`
   — verifies the Service Principal before marking the tenant active.
   The client secret is encrypted at rest.

**Then, either provider:**
4. `POST /api/v1/tenants/{id}/scan` — assumes/authenticates fresh
   credentials for whichever provider is connected, runs the matching
   `kdavis-cloud-audit` provider, sanitizes findings, stores the scan, and
   runs the analysis into a prioritized remediation plan — synchronously.
5. `GET /api/v1/tenants/{id}/dashboard` any time after — latest scan plus
   open HITL items. `GET /api/v1/tenants/{id}/scans` for scan history.
   `POST /api/v1/hitl/{item_id}/approve` or `/dismiss` to act on one item.

Every route except `POST /tenants` requires an `X-Tenant-Token` header
(SHA-256 hashed before lookup — the raw token is never stored).

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Fill in `.env`:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Shared Postgres instance (Supabase pooler connection string) |
| `ANTHROPIC_API_KEY` | Analysis of scan findings |
| `ENCRYPTION_KEY` | Fernet key encrypting stored Azure client secrets |
| `FINOPS_AWS_ACCOUNT_ID` | This service's own AWS account ID, used to build the trust-policy JSON customers paste in |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | This service's **own** AWS identity, scoped to nothing beyond `sts:AssumeRole` — never a customer credential, and never a personal/admin credential |
| `AWS_DEFAULT_REGION` | Region for the assumed-role session (defaults to `us-east-1`) |
| `ALLOWED_ORIGINS` | CORS allowlist, comma-separated |
| `LOG_LEVEL` | Defaults to `INFO` |

Run the Postgres migrations in `db/migrations/` (`001_finops_core.sql`,
`002_finops_azure_onboarding.sql`) against your `DATABASE_URL` before
first run.

## Run

```bash
uvicorn api.main:app --reload --port 8001
```

Health checks: `GET /health`, `GET /health/db`. API docs at `/docs`.

Production start command (`Procfile`):
```
web: python3 -m uvicorn api.main:app --host 0.0.0.0 --port $PORT
```

## Test

```bash
pytest tests/ -v
```

## Directory structure

```
api/
  main.py                # FastAPI app, lifespan-managed asyncpg pool
  middleware/auth.py      # X-Tenant-Token hashing + tenant lookup
  routes/
    tenants.py            # create tenant, connect AWS/Azure, dashboard, scan history
    scans.py               # trigger a scan against whichever provider is connected
    hitl.py                 # approve/dismiss HITL queue items (terminal status only)
agents/
  finops_analysis.py       # single-call analysis: findings -> prioritized plan
providers/
  llm.py                    # model provider SDK call, isolated behind one function
core/
  aws_onboarding.py         # trust/permissions policy builders, assume-role helpers
  azure_onboarding.py       # Service Principal verification, credential builder
  db.py                       # asyncpg JSONB codec registration
security/
  encryption.py              # Fernet encrypt/decrypt for Azure client secrets
db/migrations/                # 001_finops_core.sql, 002_finops_azure_onboarding.sql
tests/                          # pytest, one file per module above
```

---

**Built by** [Kelvin Davis](https://www.linkedin.com/in/kelvin-davis) — flagship product: [Cloud Decoded](https://theclouddecoded.com)
