"""
Unit tests for Security Regression Engine.
"""

import asyncio
from core.regression_engine import SecurityRegressionEngine, RegressionStatus
from core.schemas import VulnerabilityFinding, EvidenceArtifact, ConfidenceLevel
from core.cvss_engine import CVSSEngine


def test_regression_detects_remediation():
    async def _test():
        engine = SecurityRegressionEngine()

        ev = EvidenceArtifact(
            evidence_id="EVD-TEST-001",
            request_method="GET",
            request_url="https://example.com/api/test?id=1",
            response_status_code=500,
            response_body_sample="sqlite3.OperationalError",
            payload_applied="' OR 1=1 --",
            curl_reproduction="curl https://example.com/api/test?id=1",
            proof_hash="fakehash12345678"
        )

        finding = VulnerabilityFinding(
            finding_id="VULN-001",
            title="SQL Injection",
            severity=CVSSEngine.get_template_metrics("sqli").severity,
            category="INJECTION",
            affected_url="https://example.com/api/test",
            cvss=CVSSEngine.get_template_metrics("sqli"),
            confidence=ConfidenceLevel.CERTAIN,
            description="SQL injection in id param",
            evidence=ev,
            remediation_advice="Parametrize query",
            discovered_by_agent="WebVulnAgent"
        )

        # Mock client simulation
        class MockClient:
            async def request(self, *args, **kwargs):
                class MockResponse:
                    status_code = 200
                    text = '{"status": "ok", "results": []}'
                    headers = {}
                return MockResponse()

        res = await engine.verify_finding(MockClient(), finding)
        assert res["status"] == RegressionStatus.REMEDIATED.value

    asyncio.run(_test())
