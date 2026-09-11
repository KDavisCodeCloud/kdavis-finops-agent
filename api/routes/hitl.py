"""HITL queue actions.

POST /hitl/{item_id}/approve|dismiss -- terminal status change only.
Never triggers execution, by design -- see agents/finops_analysis.py's
module docstring for the full reasoning.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from api.middleware.auth import get_tenant

log = logging.getLogger(__name__)
router = APIRouter(prefix="/hitl", tags=["hitl"])


class ItemActionResponse(BaseModel):
    id: str
    status: str


async def _set_item_status(request: Request, item_id: str, tenant_id, new_status: str) -> ItemActionResponse:
    async with request.app.state.db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE finops_hitl_queue
            SET status = $1, actioned_at = $2
            WHERE id = $3 AND tenant_id = $4
            RETURNING id, status
            """,
            new_status,
            datetime.now(timezone.utc),
            item_id,
            tenant_id,
        )
    if not row:
        raise HTTPException(status_code=404, detail="HITL item not found")
    return ItemActionResponse(id=str(row["id"]), status=row["status"])


@router.post("/{item_id}/approve", response_model=ItemActionResponse)
async def approve_item(item_id: str, request: Request, tenant: dict = Depends(get_tenant)) -> ItemActionResponse:
    result = await _set_item_status(request, item_id, tenant["id"], "approved")
    log.info("[HITL] Item=%s approved tenant=%s", item_id, tenant["id"])
    return result


@router.post("/{item_id}/dismiss", response_model=ItemActionResponse)
async def dismiss_item(item_id: str, request: Request, tenant: dict = Depends(get_tenant)) -> ItemActionResponse:
    result = await _set_item_status(request, item_id, tenant["id"], "dismissed")
    log.info("[HITL] Item=%s dismissed tenant=%s", item_id, tenant["id"])
    return result
