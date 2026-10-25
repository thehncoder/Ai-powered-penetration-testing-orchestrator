"""
Unit tests for Quality Gate Engine.
"""

from core.quality_gate import QualityGateEngine
from core.evidence_vault import EvidenceVault
from core.cvss_engine import CVSSEngine
from core.schemas import (
    ServiceEndpoint,
    VulnerabilityFinding,
    EvidenceArtifact,
    ConfidenceLevel,
    QualityGateStatus
)


def test_quality_gate_rejects_hallucination_without_evidence():
    engine = QualityGateEngine(min_coverage_threshold=80.0)
    vault = EvidenceVault()

    endpoints = [
        ServiceEndpoint(url="http://test.local/api/search", method="GET", tested_by_agents=["AgentA"]),
        ServiceEndpoint(url="http://test.local/api/users", method="GET", tested_by_agents=["AgentA"])
    ]

    # Finding with fake/tampered evidence
    fake_evidence = EvidenceArtifact(
        evidence_id="EVD-FAKE",
        request_method="GET",
        request_url="http://test.local/api/search",
        response_status_code=200,
        response_body_sample="fake response",
        payload_applied="' OR 1=1 --",
        curl_reproduction="curl http://test.local/api/search",
        proof_hash="deadbeef12345678" # Tampered hash!
    )

    fake_finding = VulnerabilityFinding(
        finding_id="VULN-001",
        title="Fake SQLi",
        severity=CVSSEngine.get_template_metrics("sqli").severity,
        category="INJECTION",
        affected_url="http://test.local/api/search",
        cvss=CVSSEngine.get_template_metrics("sqli"),
        confidence=ConfidenceLevel.TENTATIVE,
        description="Hallucinated finding with forged hash",
        evidence=fake_evidence,
        remediation_advice="None",
        discovered_by_agent="AgentA"
    )

    gate_result, verified, under_tested = engine.evaluate_testing_gate(endpoints, [fake_finding], vault)

    assert len(verified) == 0 # Rejected!
    assert gate_result.findings_rejected == 1
    assert "tampered_or_invalid_proof_hash" in gate_result.rejection_reasons


def test_quality_gate_accepts_valid_evidence():
    engine = QualityGateEngine(min_coverage_threshold=80.0)
    vault = EvidenceVault()

    endpoints = [
        ServiceEndpoint(url="http://test.local/api/search", method="GET", tested_by_agents=["AgentA"])
    ]

    # Genuine evidence recorded in vault
    valid_evidence = vault.record_evidence(
        request_method="GET",
        request_url="http://test.local/api/search",
        response_status_code=500,
        payload_applied="' OR 1=1 --",
        response_body="sqlite3.OperationalError: syntax error near 'OR'"
    )

    valid_finding = VulnerabilityFinding(
        finding_id="VULN-SQLI-001",
        title="Genuine SQLi",
        severity=CVSSEngine.get_template_metrics("sqli").severity,
        category="INJECTION",
        affected_url="http://test.local/api/search",
        cvss=CVSSEngine.get_template_metrics("sqli"),
        confidence=ConfidenceLevel.CERTAIN,
        description="Genuine finding",
        evidence=valid_evidence,
        remediation_advice="Use parameterized queries",
        discovered_by_agent="AgentA"
    )

    gate_result, verified, under_tested = engine.evaluate_testing_gate(endpoints, [valid_finding], vault)

    assert len(verified) == 1
    assert verified[0].verified_by_gate is True
    assert gate_result.status == QualityGateStatus.PASSED
