from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from api.routes import hitl


def _make_request(conn) -> SimpleNamespace:
    pool_ctx = AsyncMock()
    pool_ctx.__aenter__ = AsyncMock(return_value=conn)
    pool_ctx.__aexit__ = AsyncMock(return_value=False)
    pool = MagicMock()
    pool.acquire = MagicMock(return_value=pool_ctx)
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(db_pool=pool)))


class TestApproveDismissItem:
    async def test_approve_success(self):
        item_id = uuid4()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"id": item_id, "status": "approved"})
        request = _make_request(conn)

        result = await hitl.approve_item(str(item_id), request, tenant={"id": uuid4()})

        assert result.status == "approved"
        sql, status_arg = conn.fetchrow.await_args.args[0], conn.fetchrow.await_args.args[1]
        assert status_arg == "approved"

    async def test_dismiss_success(self):
        item_id = uuid4()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"id": item_id, "status": "dismissed"})
        request = _make_request(conn)

        result = await hitl.dismiss_item(str(item_id), request, tenant={"id": uuid4()})

        assert result.status == "dismissed"

    async def test_approve_wrong_tenant_404(self):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)
        request = _make_request(conn)

        with pytest.raises(HTTPException) as exc:
            await hitl.approve_item(str(uuid4()), request, tenant={"id": uuid4()})
        assert exc.value.status_code == 404
