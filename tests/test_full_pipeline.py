"""
Integration test for full 5-wave VAPT pipeline against local mock testbed.
"""

import asyncio
from pathlib import Path
import httpx

from mock_target.app import app as mock_app
from core.schemas import TargetScope
from core.orchestrator import VAPTOrchestrator


def test_full_pipeline_run():
    async def _run():
        transport = httpx.ASGITransport(app=mock_app)
        scope = TargetScope(target_url="http://127.0.0.1:8877", safe_mode=True)
        orchestrator = VAPTOrchestrator(scope=scope, transport=transport)
        return await orchestrator.run()

    report = asyncio.run(_run())

    assert report is not None
    assert report.summary.total_findings > 0
    assert report.summary.coverage_rate >= 80.0
    assert len(report.quality_gates) >= 2
    # Ensure findings were caught and verified
    finding_titles = [f.title for f in report.findings]
    assert any("Cross-Site Scripting" in t or "SSRF" in t or "Admin" in t for t in finding_titles)
