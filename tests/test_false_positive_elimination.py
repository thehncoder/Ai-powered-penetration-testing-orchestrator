"""
Tests verifying that SPA catch-all fallbacks, soft 404s, and unverified metadata
are eliminated as false positives.
"""

from core.schemas import ServiceEndpoint, VulnerabilityFinding, ConfidenceLevel, SeverityLevel
from core.cvss_engine import CVSSEngine
from core.evidence_vault import EvidenceVault
from core.quality_gate import QualityGateEngine
from core.llm_brain import AIBrain


def test_quality_gate_rejects_spa_catch_all_ssrf_false_positive():
    vault = EvidenceVault()
    # Simulate an SPA returning React index.html for an SSRF probe
    fake_spa_html = "<!doctype html><html lang='en'><head><title>Portal</title><meta name='description' content='Web site created using create-react-app'/></head><body><div id='root'></div></body></html>"
    ev = vault.record_evidence(
        request_method="GET",
        request_url="https://portal.example.edu/api/fetch?url=http://169.254.169.254/latest/meta-data/",
        response_status_code=200,
        payload_applied="http://169.254.169.254/latest/meta-data/",
        response_body=fake_spa_html
    )
    cvss = CVSSEngine.get_template_metrics("ssrf")

    finding = VulnerabilityFinding(
        finding_id="VULN-SSRF-001",
        title="Server-Side Request Forgery",
        severity=cvss.severity,
        category="SSRF",
        affected_url="https://portal.example.edu/api/fetch",
        http_method="GET",
        affected_parameter="url",
        cvss=cvss,
        confidence=ConfidenceLevel.CERTAIN,
        description="SSRF finding hypothesis",
        evidence=ev,
        remediation_advice="Filter private IPs",
        discovered_by_agent="WebVulnAgent"
    )

    qg_engine = QualityGateEngine()
    gate_res, verified, _ = qg_engine.evaluate_testing_gate(
        endpoints=[ServiceEndpoint(url="https://portal.example.edu/api/fetch", method="GET")],
        findings=[finding],
        vault=vault
    )

    # Must be rejected because evidence is an SPA index.html, NOT cloud metadata!
    assert len(verified) == 0
    assert gate_res.findings_rejected == 1
    assert "spa_catch_all_fallback_false_positive" in gate_res.rejection_reasons or "unverified_ssrf_metadata_proof" in gate_res.rejection_reasons


def test_quality_gate_rejects_admin_login_page_false_positive():
    vault = EvidenceVault()
    login_html = "<html><body><h2>Admin Portal</h2><form action='/login'><input type='password' name='pass'/><button>Sign In</button></form></body></html>"
    ev = vault.record_evidence(
        request_method="GET",
        request_url="https://portal.example.edu/admin",
        response_status_code=200,
        payload_applied="No Auth Header Probe",
        response_body=login_html
    )
    cvss = CVSSEngine.get_template_metrics("auth")

    finding = VulnerabilityFinding(
        finding_id="VULN-ADMIN-001",
        title="Unauthenticated Access to Administrative Endpoint",
        severity=cvss.severity,
        category="BROKEN_ACCESS_CONTROL",
        affected_url="https://portal.example.edu/admin",
        http_method="GET",
        affected_parameter=None,
        cvss=cvss,
        confidence=ConfidenceLevel.CERTAIN,
        description="Admin bypass finding hypothesis",
        evidence=ev,
        remediation_advice="Enforce RBAC",
        discovered_by_agent="AuthSecAgent"
    )

    qg_engine = QualityGateEngine()
    gate_res, verified, _ = qg_engine.evaluate_testing_gate(
        endpoints=[ServiceEndpoint(url="https://portal.example.edu/admin", method="GET")],
        findings=[finding],
        vault=vault
    )

    # Must be rejected because it's a login form, not an admin bypass!
    assert len(verified) == 0
    assert gate_res.findings_rejected == 1
    assert "admin_route_is_login_page" in gate_res.rejection_reasons


def test_ai_brain_rejects_unverified_metadata_for_ssrf():
    brain = AIBrain()
    # Response is 200 OK but body is generic HTML
    res = brain.analyze_vulnerability_hypothesis(
        endpoint_url="https://portal.example.edu/api/fetch",
        param="url",
        payload="http://169.254.169.254/latest/meta-data/",
        status_code=200,
        response_body="<!doctype html><html><body><h1>Welcome</h1></body></html>",
        category="SSRF"
    )
    assert res["is_vulnerable"] is False

    # Response is 200 OK and contains genuine AWS IMDS token
    res_valid = brain.analyze_vulnerability_hypothesis(
        endpoint_url="https://portal.example.edu/api/fetch",
        param="url",
        payload="http://169.254.169.254/latest/meta-data/",
        status_code=200,
        response_body="ami-id\ninstance-id\nsecurity-credentials",
        category="SSRF"
    )
    assert res_valid["is_vulnerable"] is True
