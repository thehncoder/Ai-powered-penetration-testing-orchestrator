"""
Tests specifically verifying that the Differential Oracle Engine and Quality Gate
do NOT produce FALSE NEGATIVES when evaluating genuine, real-world vulnerabilities.
"""

import pytest
from core.schemas import (
    ServiceEndpoint,
    VulnerabilityFinding,
    ConfidenceLevel,
    TargetScope
)
from core.evidence_vault import EvidenceVault
from core.llm_brain import AIBrain
from core.quality_gate import QualityGateEngine
from core.cvss_engine import CVSSEngine
from agents.surface_mapper_agent import SurfaceMapperAgent


def test_ssrf_multi_cloud_and_internal_services_not_missed():
    """Verify that SSRF across AWS, GCP, Azure, DigitalOcean, Redis, Docker, and Elasticsearch are all recognized."""
    brain = AIBrain(provider="autonomous")
    vault = EvidenceVault()
    qg_engine = QualityGateEngine()

    test_vectors = [
        ("AWS IMDSv1", "ami-12345678\ninstance-id: i-abcdef1234567890\nsecurity-credentials/admin-role"),
        ("GCP Metadata", '{"computeMetadata": {"v1": {"project-id": "corporate-prod-cluster-99", "zone": "us-central1-a"}}}'),
        ("Azure IMDS", '{"compute": {"vmId": "12345678-abcd-1234-abcd-1234567890ab", "subscriptionId": "sub-9876", "osType": "Linux"}}'),
        ("DigitalOcean Metadata", '{"droplet_id": 98765432, "vendor_data": "secret_startup_script", "public_keys": ["ssh-rsa AAA..."]}'),
        ("Redis Internal Service", "+PONG\r\n$25\r\nredis_version:7.0.12\r\n"),
        ("Elasticsearch Cluster", '{\n  "cluster_name" : "prod-elastic-search",\n  "tagline" : "You Know, for Search"\n}'),
        ("Docker Daemon", '{"ApiVersion": "1.41", "Components": [{"Name": "Engine", "Version": "24.0.5"}]}'),
        ("Localhost /etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
    ]

    for label, payload_proof in test_vectors:
        analysis = brain.analyze_vulnerability_hypothesis(
            endpoint_url="https://target.corp/api/fetch",
            param="url",
            payload="http://127.0.0.1/internal",
            status_code=200,
            response_body=payload_proof,
            category="SSRF"
        )
        assert analysis["is_vulnerable"] is True, f"False Negative in AIBrain for {label}: was erroneously marked safe!"
        assert analysis["cwe_id"] == "CWE-918"

        ev = vault.record_evidence(
            request_method="GET",
            request_url="https://target.corp/api/fetch?url=http://127.0.0.1/internal",
            response_status_code=200,
            payload_applied="http://127.0.0.1/internal",
            response_body=payload_proof
        )
        cvss = CVSSEngine.get_template_metrics("ssrf")
        finding = VulnerabilityFinding(
            finding_id=f"VULN-SSRF-{abs(hash(label)) % 1000:03d}",
            title=f"SSRF to {label}",
            severity=cvss.severity,
            category="SSRF",
            owasp_top10="A10:2021-Server-Side Request Forgery",
            cwe_id="CWE-918",
            affected_url="https://target.corp/api/fetch",
            http_method="GET",
            affected_parameter="url",
            cvss=cvss,
            confidence=ConfidenceLevel.CERTAIN,
            description=f"SSRF verified reaching {label}",
            evidence=ev,
            remediation_advice="Deploy IMDSv2 and egress firewalls",
            discovered_by_agent="WebVulnAgent"
        )

        _, verified, _ = qg_engine.evaluate_testing_gate(
            endpoints=[ServiceEndpoint(url="https://target.corp/api/fetch", method="GET")],
            findings=[finding],
            vault=vault
        )
        assert len(verified) == 1, f"False Negative in Quality Gate: {label} proof was rejected!"


def test_idor_html_rendered_view_not_missed():
    """Verify that IDOR returning an HTML user account page is NOT discarded as a false negative."""
    brain = AIBrain(provider="autonomous")
    profile_html = """
    <!DOCTYPE html>
    <html>
    <head><title>User Profile View</title></head>
    <body>
        <div class="user-card">
            <h2>Customer Profile</h2>
            <p><strong>Email:</strong> victim_ceo@target.corp</p>
            <p><strong>Phone Number:</strong> +1-555-0199</p>
            <p><strong>Account Balance:</strong> $842,500.00</p>
            <p><strong>Billing Address:</strong> 100 Corporate Blvd, Suite 400</p>
        </div>
    </body>
    </html>
    """
    analysis = brain.analyze_vulnerability_hypothesis(
        endpoint_url="https://target.corp/user/profile",
        param="id",
        payload="2",
        status_code=200,
        response_body=profile_html,
        category="IDOR"
    )
    assert analysis["is_vulnerable"] is True, "False Negative: HTML profile view with sensitive PII was discarded!"
    assert analysis["cwe_id"] == "CWE-639"


def test_admin_route_diverse_keywords_not_missed():
    """Verify that Admin route bypass with varied enterprise terminology is recognized by Quality Gate."""
    vault = EvidenceVault()
    admin_dashboards = [
        "<html><body><h1>Site Administration</h1><nav><a href='/users'>Manage Roles</a><a href='/audit'>Audit Logs</a></nav></body></html>",
        "<html><body><div id='admin-console'><h2>System Configuration</h2><p>Server Status: Active</p><p>Active Sessions: 142</p></div></body></html>",
        '{"status": "success", "panel": "administrator", "cluster_topology": {"nodes": 8}, "debug_mode": true}'
    ]

    qg_engine = QualityGateEngine()

    for idx, body in enumerate(admin_dashboards):
        ev = vault.record_evidence(
            request_method="GET",
            request_url=f"https://target.corp/admin/panel_{idx}",
            response_status_code=200,
            payload_applied="No Auth Probe",
            response_body=body
        )
        cvss = CVSSEngine.get_template_metrics("auth")
        finding = VulnerabilityFinding(
            finding_id=f"VULN-ADMIN-{idx}",
            title=f"Unauthenticated Access to Admin Endpoint {idx}",
            severity=cvss.severity,
            category="BROKEN_ACCESS_CONTROL",
            affected_url=f"https://target.corp/admin/panel_{idx}",
            http_method="GET",
            affected_parameter=None,
            cvss=cvss,
            confidence=ConfidenceLevel.CERTAIN,
            description="Exposed privileged dashboard",
            evidence=ev,
            remediation_advice="Enforce RBAC",
            discovered_by_agent="AuthSecAgent"
        )
        _, verified, _ = qg_engine.evaluate_testing_gate(
            endpoints=[ServiceEndpoint(url=f"https://target.corp/admin/panel_{idx}", method="GET")],
            findings=[finding],
            vault=vault
        )
        assert len(verified) == 1, f"False Negative: Admin panel variant {idx} was rejected by Quality Gate!"


def test_union_based_sqli_reflection_not_missed():
    """Verify that UNION-based SQL injection with canary reflection is recognized even if error messages are off."""
    brain = AIBrain(provider="autonomous")
    union_response = """
    {"status": "ok", "items": [{"id": 1, "name": "Standard Item"}, {"id": 99, "name": "vapt"}]}
    """
    analysis = brain.analyze_vulnerability_hypothesis(
        endpoint_url="https://target.corp/api/search",
        param="q",
        payload="1' UNION SELECT 1, 'vapt' --",
        status_code=200,
        response_body=union_response,
        category="SQLI"
    )
    assert analysis["is_vulnerable"] is True, "False Negative: UNION-based SQLi canary reflection was missed!"
    assert analysis["cwe_id"] == "CWE-89"


@pytest.mark.anyio
async def test_surface_mapper_does_not_drop_real_api_html_documentation():
    """Verify that an API documentation route (like /api/docs Swagger) returning HTML is NOT dropped by soft-404."""
    import httpx

    # Mock response returning Swagger UI HTML (not React catch-all)
    swagger_html = """
    <!DOCTYPE html>
    <html>
    <head><title>Swagger UI</title></head>
    <body><div id="swagger-ui">API Documentation for v1 services</div></body>
    </html>
    """

    class MockTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=swagger_html, headers={"content-type": "text/html"})

    scope = TargetScope(target_url="https://target.corp")
    vault = EvidenceVault()
    brain = AIBrain()
    mapper = SurfaceMapperAgent(scope, vault, brain, transport=MockTransport())

    client = httpx.AsyncClient(transport=MockTransport())
    endpoint = await mapper._fuzz_path(
        client=client,
        base_url="https://target.corp",
        route="/api/docs",
        spa_baseline_hash="different_hash_from_canary_404",
        spa_baseline_len=500
    )
    assert endpoint is not None, "False Negative: /api/docs Swagger UI was incorrectly dropped as a catch-all 404!"
    assert endpoint.url == "https://target.corp/api/docs"
