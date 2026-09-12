from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from api.routes import scans
from audit.findings import Category, Finding, Severity


def _make_request(conn) -> SimpleNamespace:
    pool_ctx = AsyncMock()
    pool_ctx.__aenter__ = AsyncMock(return_value=conn)
    pool_ctx.__aexit__ = AsyncMock(return_value=False)
    pool = MagicMock()
    pool.acquire = MagicMock(return_value=pool_ctx)
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(db_pool=pool)))


def _fake_finding():
    return Finding(
        provider="aws",
        category=Category.WASTE,
        severity=Severity.HIGH,
        service="EC2",
        resource_type="instance",
        resource_id="i-REDACTED",
        title="Stopped instance",
        description="d",
        remediation="r",
        estimated_monthly_waste_usd=42.0,
    )


def _fake_azure_finding():
    return Finding(
        provider="azure",
        category=Category.WASTE,
        severity=Severity.MEDIUM,
        service="VM",
        resource_type="virtual_machine",
        resource_id="vm-REDACTED",
        title="Deallocated VM still paying for disk storage",
        description="d",
        remediation="r",
        estimated_monthly_waste_usd=17.0,
    )


class TestTriggerScan:
    async def test_happy_path_scans_stores_and_analyzes(self):
        tenant_id = uuid4()
        scan_id = uuid4()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"id": scan_id})
        request = _make_request(conn)
        fake_tenant = {
            "id": tenant_id,
            "status": "active",
            "connected_provider": "aws",
            "aws_role_arn": "arn:aws:iam::222222222222:role/x",
            "aws_external_id": "ext-abc",
        }

        with patch("api.routes.scans.assume_role_session", return_value=MagicMock()), \
             patch("audit.providers.aws.AWSProvider") as MockProvider, \
             patch("api.routes.scans.run_analysis", new=AsyncMock()) as mock_run_analysis, \
             patch("api.routes.scans.get_dashboard", new=AsyncMock(return_value="dashboard-result")) as mock_get_dashboard:
            MockProvider.return_value.collect.return_value = [_fake_finding()]

            result = await scans.trigger_scan(str(tenant_id), request, tenant=fake_tenant)

        assert result == "dashboard-result"
        insert_sql, bound_tenant_id, provider, count, waste = conn.fetchrow.await_args.args
        assert bound_tenant_id == str(tenant_id)
        assert provider == "aws"
        assert count == 1
        assert waste == 42.0

        mock_run_analysis.assert_awaited_once()
        analysis_args = mock_run_analysis.await_args.args
        assert analysis_args[1] == str(scan_id)
        assert analysis_args[2] == str(tenant_id)
        assert analysis_args[3][0]["resource_id"] == "i-REDACTED"  # sanitized before storage

        mock_get_dashboard.assert_awaited_once()

    async def test_azure_happy_path_scans_stores_and_analyzes(self):
        tenant_id = uuid4()
        scan_id = uuid4()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"id": scan_id})
        request = _make_request(conn)
        fake_tenant = {
            "id": tenant_id,
            "status": "active",
            "connected_provider": "azure",
            "azure_tenant_id": "tid",
            "azure_client_id": "cid",
            "azure_client_secret_encrypted": "encrypted-secret",
            "azure_subscription_id": "sub-id",
        }

        with patch("api.routes.scans.build_azure_credential", return_value=MagicMock()), \
             patch("api.routes.scans.decrypt", return_value="plaintext-secret"), \
             patch("audit.providers.azure.AzureProvider") as MockProvider, \
             patch("api.routes.scans.run_analysis", new=AsyncMock()), \
             patch("api.routes.scans.get_dashboard", new=AsyncMock(return_value="dashboard-result")):
            MockProvider.return_value.collect.return_value = [_fake_azure_finding()]

            result = await scans.trigger_scan(str(tenant_id), request, tenant=fake_tenant)

        assert result == "dashboard-result"
        insert_sql, bound_tenant_id, provider, count, waste = conn.fetchrow.await_args.args
        assert provider == "azure"
        assert count == 1
        assert waste == 17.0

    async def test_tenant_without_verified_role_rejected(self):
        tenant_id = uuid4()
        request = _make_request(AsyncMock())
        fake_tenant = {
            "id": tenant_id,
            "status": "pending_setup",
            "connected_provider": "aws",
            "aws_role_arn": None,
            "aws_external_id": "ext",
        }

        with pytest.raises(HTTPException) as exc:
            await scans.trigger_scan(str(tenant_id), request, tenant=fake_tenant)
        assert exc.value.status_code == 400

    async def test_tenant_without_verified_azure_credentials_rejected(self):
        tenant_id = uuid4()
        request = _make_request(AsyncMock())
        fake_tenant = {
            "id": tenant_id,
            "status": "pending_setup",
            "connected_provider": "azure",
            "azure_client_secret_encrypted": None,
        }

        with pytest.raises(HTTPException) as exc:
            await scans.trigger_scan(str(tenant_id), request, tenant=fake_tenant)
        assert exc.value.status_code == 400

    async def test_no_provider_connected_rejected(self):
        tenant_id = uuid4()
        request = _make_request(AsyncMock())
        fake_tenant = {"id": tenant_id, "status": "pending_setup", "connected_provider": None}

        with pytest.raises(HTTPException) as exc:
            await scans.trigger_scan(str(tenant_id), request, tenant=fake_tenant)
        assert exc.value.status_code == 400
        assert "not connected a cloud provider" in exc.value.detail

    async def test_assume_role_failure_returns_400(self):
        tenant_id = uuid4()
        request = _make_request(AsyncMock())
        fake_tenant = {
            "id": tenant_id,
            "status": "active",
            "connected_provider": "aws",
            "aws_role_arn": "arn:aws:iam::222222222222:role/x",
            "aws_external_id": "ext-abc",
        }

        with patch("api.routes.scans.assume_role_session", side_effect=scans.AssumeRoleError("denied")):
            with pytest.raises(HTTPException) as exc:
                await scans.trigger_scan(str(tenant_id), request, tenant=fake_tenant)
        assert exc.value.status_code == 400

    async def test_tenant_id_mismatch_404(self):
        request = _make_request(AsyncMock())
        fake_tenant = {"id": uuid4(), "status": "active", "connected_provider": "aws", "aws_role_arn": "arn:x", "aws_external_id": "ext"}
        with pytest.raises(HTTPException) as exc:
            await scans.trigger_scan(str(uuid4()), request, tenant=fake_tenant)
        assert exc.value.status_code == 404
