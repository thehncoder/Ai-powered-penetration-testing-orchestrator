"""
Comprehensive Unit Tests for Security Regression Engine.
Verifies request replay fidelity, target_override URL rewriting, vulnerability-specific condition checks,
and distinction between confirmed fixes, still-vulnerable findings, and inconclusive results.
"""

import pytest
import httpx
from core.regression_engine import SecurityRegressionEngine, RegressionStatus, apply_target_override
from core.schemas import VulnerabilityFinding, EvidenceArtifact, ConfidenceLevel
from core.cvss_engine import CVSSEngine


def _create_finding(
    category: str = "INJECTION",
    title: str = "SQL Injection in 'q'",
    url: str = "http://localhost:8000/api/search?q=test",
    method: str = "GET",
    payload: str = "' OR 1=1 --",
    request_headers: dict = None,
    request_body: str = None
) -> VulnerabilityFinding:
    ev = EvidenceArtifact(
        evidence_id="EVD-TEST-REG-01",
        request_method=method,
        request_url=url,
        request_headers=request_headers or {"Authorization": "Bearer test-token"},
        request_body=request_body,
        response_status_code=500,
        response_body_sample="sqlite3.OperationalError: near '': syntax error",
        payload_applied=payload,
        curl_reproduction=f"curl -X {method} '{url}'",
        proof_hash="a1b2c3d4e5f60718"
    )
    cvss = CVSSEngine.get_template_metrics("sqli")
    return VulnerabilityFinding(
        finding_id="VULN-REG-001",
        title=title,
        severity=cvss.severity,
        category=category,
        affected_url=url.split("?")[0],
        cvss=cvss,
        confidence=ConfidenceLevel.CERTAIN,
        description="Regression test finding",
        evidence=ev,
        remediation_advice="Apply parameterization",
        discovered_by_agent="WebVulnAgent"
    )


def test_target_override_url_rewriting():
    """Verify target_override correctly substitutes host, scheme, and port while keeping path and query."""
    orig = "http://prod.example.com:8080/api/v1/search?q=admin&limit=10#section"
    
    # Override with standard URL
    new_url = apply_target_override(orig, "http://127.0.0.1:9090")
    assert new_url == "http://127.0.0.1:9090/api/v1/search?q=admin&limit=10#section"

    # Override with https domain
    new_url_ssl = apply_target_override(orig, "https://staging.internal.net")
    assert new_url_ssl == "https://staging.internal.net/api/v1/search?q=admin&limit=10#section"

    # Override with plain host:port
    new_url_plain = apply_target_override(orig, "localhost:5000")
    assert new_url_plain == "http://localhost:5000/api/v1/search?q=admin&limit=10#section"

    # None override returns original
    assert apply_target_override(orig, None) == orig


@pytest.mark.anyio
async def test_sqli_regression_distinguishes_fix_vulnerable_and_inconclusive():
    """Verify SQLi retest correctly flags CONFIRMED_FIX, STILL_VULNERABLE, and INCONCLUSIVE."""
    finding = _create_finding(category="INJECTION", title="SQL Injection in search")

    # 1. Confirmed fix: returns 200 with normal results, no SQL errors
    async def handler_fixed(request: httpx.Request):
        return httpx.Response(200, json={"items": []})

    transport_fixed = httpx.MockTransport(handler_fixed)
    engine = SecurityRegressionEngine(transport=transport_fixed)
    report_fixed = await engine.run_regression_audit([finding])
    assert report_fixed.remediated_count == 1
    assert report_fixed.regressed_count == 0
    assert report_fixed.results[0]["status"] == RegressionStatus.CONFIRMED_FIX.value

    # 2. Still vulnerable: returns 500 with sqlite3 error
    async def handler_vulnerable(request: httpx.Request):
        return httpx.Response(500, text="sqlite3.OperationalError: near '': syntax error")

    transport_vuln = httpx.MockTransport(handler_vulnerable)
    engine_vuln = SecurityRegressionEngine(transport=transport_vuln)
    report_vuln = await engine_vuln.run_regression_audit([finding])
    assert report_vuln.regressed_count == 1
    assert report_vuln.results[0]["status"] == RegressionStatus.STILL_VULNERABLE.value

    # 3. Inconclusive: returns 503 Service Unavailable
    async def handler_inconclusive_503(request: httpx.Request):
        return httpx.Response(503, text="Service Unavailable: database undergoing maintenance")

    transport_503 = httpx.MockTransport(handler_inconclusive_503)
    engine_503 = SecurityRegressionEngine(transport=transport_503)
    report_503 = await engine_503.run_regression_audit([finding])
    assert report_503.inconclusive_count == 1
    assert report_503.results[0]["status"] == RegressionStatus.INCONCLUSIVE.value

    # 4. Inconclusive: Cloudflare WAF Challenge
    async def handler_inconclusive_waf(request: httpx.Request):
        return httpx.Response(403, text="<html><title>Just a moment...</title>challenges.cloudflare.com</html>")

    transport_waf = httpx.MockTransport(handler_inconclusive_waf)
    engine_waf = SecurityRegressionEngine(transport=transport_waf)
    report_waf = await engine_waf.run_regression_audit([finding])
    assert report_waf.inconclusive_count == 1
    assert report_waf.results[0]["status"] == RegressionStatus.INCONCLUSIVE.value


@pytest.mark.anyio
async def test_idor_admin_regression_checks():
    """Verify authorization regression properly validates HTTP 401/403 or credential disclosure."""
    finding = _create_finding(category="BROKEN_ACCESS_CONTROL", title="Admin Dashboard Unauthenticated Bypass", url="http://test/api/admin/metrics")

    # Access now denied with 403 Forbidden -> CONFIRMED_FIX
    async def handler_denied(request: httpx.Request):
        return httpx.Response(403, json={"error": "Access denied: admin credentials required"})

    engine_denied = SecurityRegressionEngine(transport=httpx.MockTransport(handler_denied))
    res_denied = await engine_denied.run_regression_audit([finding])
    assert res_denied.results[0]["status"] == RegressionStatus.CONFIRMED_FIX.value

    # Returns 200 with admin credentials -> STILL_VULNERABLE
    async def handler_still_leaking(request: httpx.Request):
        return httpx.Response(200, json={"admin_dashboard": True, "secret_key": "SUPER_SECRET_123"})

    engine_leaking = SecurityRegressionEngine(transport=httpx.MockTransport(handler_still_leaking))
    res_leaking = await engine_leaking.run_regression_audit([finding])
    assert res_leaking.results[0]["status"] == RegressionStatus.STILL_VULNERABLE.value


@pytest.mark.anyio
async def test_regression_engine_replays_headers_body_and_uses_target_override():
    """Verify that retests replay request headers, request bodies, and use target_override."""
    captured_request = {}

    async def mock_handler(request: httpx.Request):
        captured_request["url"] = str(request.url)
        captured_request["method"] = request.method
        captured_request["headers"] = dict(request.headers)
        captured_request["body"] = request.read().decode("utf-8")
        return httpx.Response(200, json={"status": "ok"})

    transport = httpx.MockTransport(mock_handler)
    engine = SecurityRegressionEngine(transport=transport)

    finding = _create_finding(
        category="INJECTION",
        title="SQL Injection in POST body",
        url="http://original-server.com:8000/api/users",
        method="POST",
        payload="' OR 1=1 --",
        request_headers={"Authorization": "Bearer secret-token-xyz", "X-Custom-Trace": "trace-999"},
        request_body='{"username": "admin\' OR 1=1 --"}'
    )

    report = await engine.run_regression_audit(
        findings=[finding],
        target_override="http://10.0.0.5:9090"
    )

    # 1. Target override was applied to the URL
    assert captured_request["url"] == "http://10.0.0.5:9090/api/users"
    assert report.target_url == "http://10.0.0.5:9090"

    # 2. Method was replayed
    assert captured_request["method"] == "POST"

    # 3. Custom headers were replayed
    assert captured_request["headers"]["authorization"] == "Bearer secret-token-xyz"
    assert captured_request["headers"]["x-custom-trace"] == "trace-999"

    # 4. Request body was replayed
    assert 'admin\' OR 1=1 --' in captured_request["body"]

    # 5. Result is confirmed fix
    assert report.results[0]["status"] == RegressionStatus.CONFIRMED_FIX.value
