"""
tests/test_auth.py
Tests for api/middleware/auth.py's get_tenant() -- the real SQL shape,
not a hand-built fake dict. Every other route file's tests pass their
own fake tenant dict directly to the route function, bypassing this
query entirely -- which is exactly how the Azure columns could have
been (and, during development, briefly were) missing from this SELECT
while every other test still passed. This file exists specifically to
catch that class of bug.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from api.middleware.auth import _hash_token, get_tenant

# Every key api/routes/*.py reads off a tenant dict returned by
# get_tenant() -- if the real SELECT stops returning one of these,
# those routes KeyError at runtime despite every route-level test
# passing (they all use hand-built fake dicts, not this function).
_REQUIRED_KEYS = {
    "id", "company_name", "aws_role_arn", "aws_external_id", "status",
    "connected_provider", "azure_tenant_id", "azure_client_id",
    "azure_client_secret_encrypted", "azure_subscription_id",
}


def _make_request(token: str | None, row: dict | None) -> SimpleNamespace:
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value=row)
    pool_ctx = AsyncMock()
    pool_ctx.__aenter__ = AsyncMock(return_value=conn)
    pool_ctx.__aexit__ = AsyncMock(return_value=False)
    pool = MagicMock()
    pool.acquire = MagicMock(return_value=pool_ctx)
    headers = {"X-Tenant-Token": token} if token else {}
    return SimpleNamespace(headers=headers, app=SimpleNamespace(state=SimpleNamespace(db_pool=pool)))


def _fake_row() -> dict:
    return {
        "id": uuid4(),
        "company_name": "Acme",
        "aws_role_arn": None,
        "aws_external_id": "ext-abc",
        "status": "active",
        "connected_provider": "azure",
        "azure_tenant_id": "tid",
        "azure_client_id": "cid",
        "azure_client_secret_encrypted": "encrypted",
        "azure_subscription_id": "sub",
    }


class TestGetTenant:
    async def test_missing_token_401(self):
        request = _make_request(None, None)
        with pytest.raises(HTTPException) as exc:
            await get_tenant(request)
        assert exc.value.status_code == 401

    async def test_invalid_token_403(self):
        request = _make_request("bogus", None)
        with pytest.raises(HTTPException) as exc:
            await get_tenant(request)
        assert exc.value.status_code == 403

    async def test_returns_every_key_downstream_routes_depend_on(self):
        request = _make_request("real-token", _fake_row())
        result = await get_tenant(request)
        assert _REQUIRED_KEYS.issubset(result.keys())

    async def test_select_statement_names_every_required_column(self):
        """Pins the actual SQL text, not just a mocked return value --
        a column silently dropped from the SELECT would still pass
        test_returns_every_key_downstream_routes_depend_on if the mock
        row happened to include it anyway, but would fail this one."""
        request = _make_request("real-token", _fake_row())
        await get_tenant(request)
        conn = request.app.state.db_pool.acquire.return_value.__aenter__.return_value
        sql = conn.fetchrow.await_args.args[0]
        for column in _REQUIRED_KEYS - {"id"}:  # "id" -> selected, not a literal substring match target
            assert column in sql, f"get_tenant()'s SELECT is missing column: {column}"

    async def test_token_is_hashed_before_lookup(self):
        request = _make_request("plaintext-token", _fake_row())
        await get_tenant(request)
        conn = request.app.state.db_pool.acquire.return_value.__aenter__.return_value
        bound_hash = conn.fetchrow.await_args.args[1]
        assert bound_hash == _hash_token("plaintext-token")
        assert bound_hash != "plaintext-token"
