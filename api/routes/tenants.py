"""Tenant lifecycle: create, connect an AWS account, check status.

POST  /tenants                    -- create a tenant, returns setup instructions
PATCH /tenants/{id}/aws-role      -- verify a customer-created IAM role
GET   /tenants/{id}/dashboard     -- latest scan + open HITL items
GET   /tenants/{id}/scans         -- scan history
"""

import logging
import os
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from api.middleware.auth import _hash_token, get_tenant
from core.aws_onboarding import AssumeRoleError, build_permissions_policy, build_trust_policy, generate_external_id, verify_role

log = logging.getLogger(__name__)
router = APIRouter(prefix="/tenants", tags=["tenants"])

_TOKEN_PREFIX = "fo_t_"


def _generate_raw_token() -> str:
    return f"{_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


# ── Request / response models ─────────────────────────────────────────────────

class CreateTenantRequest(BaseModel):
    company_name: str = Field(..., min_length=1, max_length=255)


class CreateTenantResponse(BaseModel):
    id: str
    tenant_token: str
    warning: str = "Save this token now — it will not be shown again."
    aws_trust_policy: dict
    aws_permissions_policy: dict
    instructions: str


class ConnectAwsRoleRequest(BaseModel):
    role_arn: str = Field(..., min_length=1)


class TenantStatusResponse(BaseModel):
    id: str
    company_name: str
    status: str


class HitlItemResponse(BaseModel):
    id: str
    severity: str
    category: str
    title: str
    description: str
    remediation: str
    estimated_monthly_waste_usd: float
    priority_rank: int
    status: str


class ScanSummary(BaseModel):
    scan_id: str
    provider: str
    status: str
    total_findings: int
    total_estimated_monthly_waste_usd: float
    started_at: str
    completed_at: str | None


class DashboardResponse(BaseModel):
    tenant_id: str
    status: str
    latest_scan: ScanSummary | None
    open_items: list[HitlItemResponse]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("", response_model=CreateTenantResponse, status_code=201)
async def create_tenant(body: CreateTenantRequest, request: Request) -> CreateTenantResponse:
    finops_account_id = os.environ.get("FINOPS_AWS_ACCOUNT_ID")
    if not finops_account_id:
        raise HTTPException(status_code=500, detail="FINOPS_AWS_ACCOUNT_ID not configured on this server")

    raw_token = _generate_raw_token()
    token_hash = _hash_token(raw_token)
    external_id = generate_external_id()

    async with request.app.state.db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO finops_tenants (company_name, tenant_token, aws_external_id)
            VALUES ($1, $2, $3)
            RETURNING id
            """,
            body.company_name,
            token_hash,
            external_id,
        )
    tenant_id = str(row["id"])

    log.info("[Tenants] Created tenant=%s company=%s", tenant_id, body.company_name)

    return CreateTenantResponse(
        id=tenant_id,
        tenant_token=raw_token,
        aws_trust_policy=build_trust_policy(finops_account_id, external_id),
        aws_permissions_policy=build_permissions_policy(),
        instructions=(
            "In AWS: create an IAM role using aws_trust_policy as its trust "
            "relationship, and attach aws_permissions_policy as an inline "
            "policy (read-only, scoped to exactly what gets scanned). Then "
            f"call PATCH /tenants/{tenant_id}/aws-role with the role's ARN."
        ),
    )


@router.patch("/{tenant_id}/aws-role", response_model=TenantStatusResponse)
async def connect_aws_role(
    tenant_id: str,
    body: ConnectAwsRoleRequest,
    request: Request,
    tenant: dict = Depends(get_tenant),
) -> TenantStatusResponse:
    if str(tenant["id"]) != tenant_id:
        raise HTTPException(status_code=404, detail="Tenant not found")

    try:
        verify_role(body.role_arn, tenant["aws_external_id"])
    except AssumeRoleError as exc:
        raise HTTPException(status_code=400, detail=f"Could not assume role: {exc}") from exc

    async with request.app.state.db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE finops_tenants
            SET aws_role_arn = $1, aws_verified_at = NOW(), status = 'active'
            WHERE id = $2
            RETURNING id, company_name, status
            """,
            body.role_arn,
            tenant_id,
        )

    log.info("[Tenants] AWS role verified tenant=%s", tenant_id)
    return TenantStatusResponse(id=str(row["id"]), company_name=row["company_name"], status=row["status"])


@router.get("/{tenant_id}/dashboard", response_model=DashboardResponse)
async def get_dashboard(
    tenant_id: str,
    request: Request,
    tenant: dict = Depends(get_tenant),
) -> DashboardResponse:
    if str(tenant["id"]) != tenant_id:
        raise HTTPException(status_code=404, detail="Tenant not found")

    async with request.app.state.db_pool.acquire() as conn:
        scan_row = await conn.fetchrow(
            "SELECT id, provider, status, total_findings, total_estimated_monthly_waste_usd, "
            "started_at, completed_at FROM finops_scans WHERE tenant_id = $1 "
            "ORDER BY started_at DESC LIMIT 1",
            tenant_id,
        )
        item_rows = await conn.fetch(
            "SELECT id, severity, category, title, description, remediation, "
            "estimated_monthly_waste_usd, priority_rank, status FROM finops_hitl_queue "
            "WHERE tenant_id = $1 AND status = 'pending_approval' ORDER BY priority_rank",
            tenant_id,
        )

    latest_scan = None
    if scan_row:
        latest_scan = ScanSummary(
            scan_id=str(scan_row["id"]),
            provider=scan_row["provider"],
            status=scan_row["status"],
            total_findings=scan_row["total_findings"],
            total_estimated_monthly_waste_usd=float(scan_row["total_estimated_monthly_waste_usd"]),
            started_at=scan_row["started_at"].isoformat(),
            completed_at=scan_row["completed_at"].isoformat() if scan_row["completed_at"] else None,
        )

    return DashboardResponse(
        tenant_id=tenant_id,
        status=tenant["status"],
        latest_scan=latest_scan,
        open_items=[
            HitlItemResponse(
                id=str(r["id"]),
                severity=r["severity"],
                category=r["category"],
                title=r["title"],
                description=r["description"],
                remediation=r["remediation"],
                estimated_monthly_waste_usd=float(r["estimated_monthly_waste_usd"]),
                priority_rank=r["priority_rank"],
                status=r["status"],
            )
            for r in item_rows
        ],
    )


@router.get("/{tenant_id}/scans", response_model=list[ScanSummary])
async def list_scans(
    tenant_id: str,
    request: Request,
    tenant: dict = Depends(get_tenant),
) -> list[ScanSummary]:
    if str(tenant["id"]) != tenant_id:
        raise HTTPException(status_code=404, detail="Tenant not found")

    async with request.app.state.db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, provider, status, total_findings, total_estimated_monthly_waste_usd, "
            "started_at, completed_at FROM finops_scans WHERE tenant_id = $1 "
            "ORDER BY started_at DESC LIMIT 50",
            tenant_id,
        )

    return [
        ScanSummary(
            scan_id=str(r["id"]),
            provider=r["provider"],
            status=r["status"],
            total_findings=r["total_findings"],
            total_estimated_monthly_waste_usd=float(r["total_estimated_monthly_waste_usd"]),
            started_at=r["started_at"].isoformat(),
            completed_at=r["completed_at"].isoformat() if r["completed_at"] else None,
        )
        for r in rows
    ]
