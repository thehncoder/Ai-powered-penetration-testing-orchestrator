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


def test_quality_gate_and_brain_reject_waf_challenge_sqli_false_positive():
    """Verify that Cloudflare / WAF 403 challenge pages echoing query params are never flagged as SQLi."""
    brain = AIBrain()
    cloudflare_challenge_html = """
    <!DOCTYPE html><html lang="en-US"><head><title>Just a moment...</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
    <script>cUPMDTk: "/?id=1' UNION SELECT 1, 'vapt', 3 --"</script>
    </head><body><div id="cf-chl-widget">Please stand by while we verify your browser</div></body></html>
    """
    
    # 1. AIBrain must reject WAF challenge
    res = brain.analyze_vulnerability_hypothesis(
        endpoint_url="https://protected-portal.example.com",
        param="id",
        payload="1' UNION SELECT 1, 'vapt', 3 --",
        status_code=403,
        response_body=cloudflare_challenge_html,
        category="SQLI"
    )
    assert res["is_vulnerable"] is False
    assert "WAF challenge" in res["reasoning"]

    # 2. Quality Gate must reject findings with WAF challenge proofs
    vault = EvidenceVault()
    ev = vault.record_evidence(
        request_method="GET",
        request_url="https://protected-portal.example.com?id=1'%20UNION%20SELECT%201,%20'vapt',%203%20--",
        response_status_code=403,
        payload_applied="1' UNION SELECT 1, 'vapt', 3 --",
        response_body=cloudflare_challenge_html
    )
    cvss = CVSSEngine.get_template_metrics("sqli")
    finding = VulnerabilityFinding(
        finding_id="VULN-SQLI-001",
        title="SQL Injection in parameter 'id'",
        severity=cvss.severity,
        category="INJECTION",
        owasp_top10="A03:2021-Injection",
        cwe_id="CWE-89",
        affected_url="https://protected-portal.example.com",
        http_method="GET",
        affected_parameter="id",
        cvss=cvss,
        confidence=ConfidenceLevel.CERTAIN,
        description="Hypothetical false positive SQLi",
        evidence=ev,
        remediation_advice="Enforce parameterized queries",
        discovered_by_agent="WebVulnAgent"
    )

    qg_engine = QualityGateEngine()
    gate_res, verified, _ = qg_engine.evaluate_testing_gate(
        endpoints=[ServiceEndpoint(url="https://protected-portal.example.com", method="GET")],
        findings=[finding],
        vault=vault
    )
    assert len(verified) == 0
    assert "waf_challenge_block_false_positive" in gate_res.rejection_reasons

