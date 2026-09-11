"""Scan triggering.

POST /tenants/{tenant_id}/scan -- assumes the tenant's stored AWS role
fresh, runs kdavis-cloud-audit's AWSProvider against it, sanitizes,
stores, analyzes, and returns the full result synchronously (same shape
as Cloud Decoded's POST /audit/submit).
"""

import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request

from agents.finops_analysis import run_analysis
from api.middleware.auth import get_tenant
from api.routes.tenants import DashboardResponse, get_dashboard
from core.aws_onboarding import AssumeRoleError, assume_role_session

log = logging.getLogger(__name__)
router = APIRouter(prefix="/tenants", tags=["scans"])


@router.post("/{tenant_id}/scan", response_model=DashboardResponse, status_code=201)
async def trigger_scan(
    tenant_id: str,
    request: Request,
    tenant: dict = Depends(get_tenant),
) -> DashboardResponse:
    if str(tenant["id"]) != tenant_id:
        raise HTTPException(status_code=404, detail="Tenant not found")
    if tenant["status"] != "active" or not tenant["aws_role_arn"]:
        raise HTTPException(status_code=400, detail="Tenant has no verified AWS role yet")

    try:
        session = assume_role_session(tenant["aws_role_arn"], tenant["aws_external_id"])
    except AssumeRoleError as exc:
        raise HTTPException(status_code=400, detail=f"Could not assume role: {exc}") from exc

    from audit.providers.aws import AWSProvider  # deferred: heavy import, only needed on scan
    from audit.sanitizer import sanitize_findings

    start = time.time()
    findings = AWSProvider(session=session).collect()
    duration = time.time() - start
    sanitized = sanitize_findings(findings)
    total_waste = sum(f.estimated_monthly_waste_usd for f in sanitized)

    async with request.app.state.db_pool.acquire() as conn:
        scan_row = await conn.fetchrow(
            """
            INSERT INTO finops_scans (tenant_id, provider, total_findings, total_estimated_monthly_waste_usd)
            VALUES ($1, 'aws', $2, $3)
            RETURNING id
            """,
            tenant_id,
            len(sanitized),
            round(total_waste, 2),
        )
        scan_id = str(scan_row["id"])

        await run_analysis(conn, scan_id, tenant_id, [f.to_dict() for f in sanitized])

    log.info(
        "[Scans] tenant=%s scan=%s findings=%d duration=%.1fs",
        tenant_id, scan_id, len(sanitized), duration,
    )

    return await get_dashboard(tenant_id, request, tenant=tenant)
