"""
tests/test_finops_analysis.py
Tests for agents/finops_analysis.py -- analyze -> rank -> persist. Plain
sequential async code, not a LangGraph StateGraph (see the module
docstring for why) -- no graph patching needed, just providers.llm.complete
and a mocked asyncpg connection.
"""

import json
from unittest.mock import AsyncMock, patch

from agents.finops_analysis import run_analysis


def _findings():
    return [
        {
            "finding_id": "f1",
            "category": "SECURITY",
            "severity": "HIGH",
            "service": "IAM",
            "title": "No MFA",
            "description": "d",
            "remediation": "r",
            "estimated_monthly_waste_usd": 0.0,
        }
    ]


class TestAnalysisHappyPath:
    async def test_items_persisted_and_ranked(self):
        llm_response = json.dumps(
            [
                {
                    "title": "Enforce MFA",
                    "description": "d",
                    "remediation": "r",
                    "severity": "HIGH",
                    "category": "SECURITY",
                    "estimated_monthly_waste_usd": 0,
                },
                {
                    "title": "Downsize idle EC2",
                    "description": "d",
                    "remediation": "r",
                    "severity": "MEDIUM",
                    "category": "WASTE",
                    "estimated_monthly_waste_usd": 12.5,
                },
            ]
        )
        conn = AsyncMock()
        conn.execute = AsyncMock(return_value=None)

        with patch("agents.finops_analysis.complete", return_value=llm_response):
            await run_analysis(conn, "scan-1", "tenant-1", _findings())

        insert_calls = [c for c in conn.execute.await_args_list if "INSERT INTO finops_hitl_queue" in c.args[0]]
        assert len(insert_calls) == 2
        assert insert_calls[0].args[-1] == 1  # HIGH ranked first
        assert insert_calls[1].args[-1] == 2

        ready_calls = [c for c in conn.execute.await_args_list if "status = 'ready'" in c.args[0]]
        assert len(ready_calls) == 1


class TestAnalysisFailures:
    async def test_invalid_severity_marks_scan_failed(self):
        llm_response = json.dumps(
            [{"title": "x", "description": "d", "remediation": "r", "severity": "CRITICAL", "category": "WASTE"}]
        )
        conn = AsyncMock()

        with patch("agents.finops_analysis.complete", return_value=llm_response):
            await run_analysis(conn, "scan-2", "tenant-1", _findings())

        failed_calls = [c for c in conn.execute.await_args_list if "status = 'failed'" in c.args[0]]
        assert len(failed_calls) == 1
        insert_calls = [c for c in conn.execute.await_args_list if "INSERT INTO finops_hitl_queue" in c.args[0]]
        assert insert_calls == []

    async def test_malformed_json_marks_scan_failed(self):
        conn = AsyncMock()
        with patch("agents.finops_analysis.complete", return_value="not json"):
            await run_analysis(conn, "scan-3", "tenant-1", _findings())

        failed_calls = [c for c in conn.execute.await_args_list if "status = 'failed'" in c.args[0]]
        assert len(failed_calls) == 1

    async def test_empty_items_marks_scan_failed(self):
        conn = AsyncMock()
        with patch("agents.finops_analysis.complete", return_value="[]"):
            await run_analysis(conn, "scan-4", "tenant-1", _findings())

        failed_calls = [c for c in conn.execute.await_args_list if "status = 'failed'" in c.args[0]]
        assert len(failed_calls) == 1
