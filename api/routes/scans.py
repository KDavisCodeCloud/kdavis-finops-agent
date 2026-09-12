"""Scan triggering.

POST /tenants/{tenant_id}/scan -- builds fresh credentials for whichever
provider the tenant connected (assumed AWS role, or an Azure Service
Principal credential), runs kdavis-cloud-audit's matching Provider
against it, sanitizes, stores, analyzes, and returns the full result
synchronously (same shape as Cloud Decoded's POST /audit/submit).
"""

import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request

from agents.finops_analysis import run_analysis
from api.middleware.auth import get_tenant
from api.routes.tenants import DashboardResponse, get_dashboard
from core.aws_onboarding import AssumeRoleError, assume_role_session
from core.azure_onboarding import build_azure_credential
from security.encryption import decrypt

log = logging.getLogger(__name__)
router = APIRouter(prefix="/tenants", tags=["scans"])


def _collect_findings(tenant: dict) -> list:
    """Builds fresh credentials and runs the matching kdavis-cloud-audit
    Provider for whichever cloud the tenant connected. Raises
    HTTPException on any credential problem -- never returns partial
    findings from a half-authenticated provider."""
    provider = tenant["connected_provider"]

    if provider == "aws":
        if tenant["status"] != "active" or not tenant["aws_role_arn"]:
            raise HTTPException(status_code=400, detail="Tenant has no verified AWS role yet")
        try:
            session = assume_role_session(tenant["aws_role_arn"], tenant["aws_external_id"])
        except AssumeRoleError as exc:
            raise HTTPException(status_code=400, detail=f"Could not assume role: {exc}") from exc

        from audit.providers.aws import AWSProvider  # deferred: heavy import, only needed on scan

        return AWSProvider(session=session).collect()

    if provider == "azure":
        if tenant["status"] != "active" or not tenant["azure_client_secret_encrypted"]:
            raise HTTPException(status_code=400, detail="Tenant has no verified Azure credentials yet")
        credential = build_azure_credential(
            tenant["azure_tenant_id"],
            tenant["azure_client_id"],
            decrypt(tenant["azure_client_secret_encrypted"]),
        )

        from audit.providers.azure import AzureProvider  # deferred: heavy import, only needed on scan

        return AzureProvider(credential=credential, subscription_id=tenant["azure_subscription_id"]).collect()

    raise HTTPException(status_code=400, detail="Tenant has not connected a cloud provider yet")


@router.post("/{tenant_id}/scan", response_model=DashboardResponse, status_code=201)
async def trigger_scan(
    tenant_id: str,
    request: Request,
    tenant: dict = Depends(get_tenant),
) -> DashboardResponse:
    if str(tenant["id"]) != tenant_id:
        raise HTTPException(status_code=404, detail="Tenant not found")

    provider = tenant["connected_provider"]
    start = time.time()
    findings = _collect_findings(tenant)
    duration = time.time() - start

    from audit.sanitizer import sanitize_findings

    sanitized = sanitize_findings(findings)
    total_waste = sum(f.estimated_monthly_waste_usd for f in sanitized)

    async with request.app.state.db_pool.acquire() as conn:
        scan_row = await conn.fetchrow(
            """
            INSERT INTO finops_scans (tenant_id, provider, total_findings, total_estimated_monthly_waste_usd)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            """,
            tenant_id,
            provider,
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
