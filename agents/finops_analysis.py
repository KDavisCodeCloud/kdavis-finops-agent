"""FinOps analysis: turns a scan's raw findings into a prioritized,
human-approvable remediation plan.

Deliberately NOT a LangGraph StateGraph, mirroring
kdavis-agentic-platform/agents/audit_analysis/workflow.py's reasoning
exactly: one LLM call, no branching, and no resume path ever needed --
approving a HITL item is a terminal status change a human acts on
manually, nothing here auto-executes. A StateGraph compiled with no
checkpointer would be pure ceremony with zero behavioral benefit.

Flow: analyze (LLM groups/prioritizes raw findings into action items) ->
rank (severity, then dollar impact) -> persist (one row per item in
finops_hitl_queue). Any failure in analyze/parse is caught and recorded
on the scan as status='failed' + error_message -- the findings themselves
are already safely stored by the caller before this runs, so a failed
analysis never loses data.
"""

import json
import logging

from providers.llm import complete

log = logging.getLogger(__name__)

_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
_VALID_SEVERITIES = set(_SEVERITY_ORDER)
_VALID_CATEGORIES = {"WASTE", "SECURITY", "COMPLIANCE"}

_SYSTEM_PROMPT = """You are a cloud cost and security remediation planner.
You will be given a JSON array of findings from an automated cloud audit.
Each finding already has a title, description, remediation, severity,
category, and dollar impact.

Your job: merge closely-related findings into a smaller set of clear,
prioritized action items a human engineer can act on. Only merge findings
that are genuinely the same underlying issue; never merge unrelated
findings just to shorten the list.

Respond with ONLY a JSON array, no prose, no markdown fences. Each item:
{
  "title": "short, specific, plain English",
  "description": "what the problem is, 1-3 sentences",
  "remediation": "what to do about it, 1-3 sentences",
  "severity": "HIGH" | "MEDIUM" | "LOW",
  "category": "WASTE" | "SECURITY" | "COMPLIANCE",
  "estimated_monthly_waste_usd": <sum of the dollar impact of every finding this item covers, 0 if none>
}
"""


def _parse_llm_json(response: str) -> list[dict]:
    clean = response.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        parsed = json.loads(clean)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM did not return valid JSON: {exc}") from exc
    return parsed if isinstance(parsed, list) else parsed.get("items", [])


def analyze_findings(findings: list[dict]) -> list[dict]:
    response = complete(system_prompt=_SYSTEM_PROMPT, user_content=json.dumps(findings))
    items = _parse_llm_json(response)
    if not items:
        raise ValueError("LLM returned no remediation items")

    validated = []
    for item in items:
        severity = str(item.get("severity", "")).upper()
        category = str(item.get("category", "")).upper()
        if severity not in _VALID_SEVERITIES or category not in _VALID_CATEGORIES:
            raise ValueError(f"LLM returned an invalid severity/category: {item}")
        validated.append(
            {
                "title": str(item["title"])[:200],
                "description": str(item["description"])[:2000],
                "remediation": str(item["remediation"])[:2000],
                "severity": severity,
                "category": category,
                "estimated_monthly_waste_usd": float(item.get("estimated_monthly_waste_usd", 0) or 0),
            }
        )
    return validated


def rank_items(items: list[dict]) -> list[dict]:
    ranked = sorted(items, key=lambda i: (_SEVERITY_ORDER[i["severity"]], -i["estimated_monthly_waste_usd"]))
    for i, item in enumerate(ranked):
        item["priority_rank"] = i + 1
    return ranked


async def run_analysis(conn, scan_id: str, tenant_id: str, findings: list[dict]) -> None:
    try:
        items = rank_items(analyze_findings(findings))
    except Exception as exc:  # noqa: BLE001 - convert any analysis failure into a stored, descriptive error
        log.warning("[FinOpsAnalysis] analysis failed for scan=%s: %s", scan_id, exc)
        await conn.execute(
            "UPDATE finops_scans SET status = 'failed', error_message = $1, completed_at = NOW() WHERE id = $2",
            str(exc),
            scan_id,
        )
        return

    for item in items:
        await conn.execute(
            """
            INSERT INTO finops_hitl_queue (
                scan_id, tenant_id, severity, category, title,
                description, remediation, estimated_monthly_waste_usd, priority_rank
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
            scan_id,
            tenant_id,
            item["severity"],
            item["category"],
            item["title"],
            item["description"],
            item["remediation"],
            item["estimated_monthly_waste_usd"],
            item["priority_rank"],
        )

    await conn.execute(
        "UPDATE finops_scans SET status = 'ready', completed_at = NOW() WHERE id = $1",
        scan_id,
    )
