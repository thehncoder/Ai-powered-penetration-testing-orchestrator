"""
Comprehensive Unit Tests for Architectural STRIDE Threat Modeling Engine.
Verifies explicit representation of Assets, Trust Boundaries, Data Flows,
STRIDE Threat mappings, Risk Rationales, and Structured Mitigations.
"""

from core.threat_model import ThreatModelingEngine, STRIDECategory
from core.schemas import ReconData, ServiceEndpoint, DiscoveredService


def test_stride_threat_modeling_synthesis():
    engine = ThreatModelingEngine()

    recon = ReconData(
        target_domain="api.banking-target.com",
        ip_addresses=["10.0.0.1"],
        open_ports=[DiscoveredService(port=443, service_name="https")],
        technologies={"framework": "FastAPI", "server": "Nginx"},
        endpoints=[]
    )

    endpoints = [
        ServiceEndpoint(url="https://api.banking-target.com/auth/login", method="POST", surface_category="AUTH", parameters=["username", "password"]),
        ServiceEndpoint(url="https://api.banking-target.com/admin/settings", method="GET", surface_category="ADMIN", parameters=[]),
        ServiceEndpoint(url="https://api.banking-target.com/api/v1/transfer", method="POST", surface_category="DATA", parameters=["recipient", "amount"]),
        ServiceEndpoint(url="https://api.banking-target.com/api/ai/assistant", method="POST", surface_category="API", parameters=["prompt"]),
    ]

    report = engine.generate_threat_model(recon, endpoints)

    # 1. Report Overview
    assert report is not None
    assert report.total_threats >= 5
    categories = list(report.threats_by_category.keys())
    assert STRIDECategory.SPOOFING.value in categories
    assert STRIDECategory.ELEVATION_OF_PRIVILEGE.value in categories
    assert STRIDECategory.TAMPERING.value in categories

    # 2. Architectural Assets explicitly represented
    asset_ids = [a.asset_id for a in report.assets]
    assert "ASSET-AUTH-TOKENS" in asset_ids
    assert "ASSET-DB-STORAGE" in asset_ids
    assert "ASSET-ADMIN-CONFIG" in asset_ids
    assert "ASSET-AI-TOOLS" in asset_ids
    for a in report.assets:
        assert a.name and a.asset_type and a.classification and a.description

    # 3. Trust Boundaries explicitly modeled
    boundary_ids = [tb.boundary_id for tb in report.trust_boundaries]
    assert "TB-01-INGRESS" in boundary_ids
    assert "TB-02-IDENTITY" in boundary_ids
    assert "TB-03-DATASTORE" in boundary_ids
    assert "TB-05-AI-PLANE" in boundary_ids
    for tb in report.trust_boundaries:
        assert tb.from_zone and tb.to_zone and tb.enforced_controls

    # 4. Data Flows explicitly mapped
    flow_ids = [df.flow_id for df in report.data_flows]
    assert "DF-01-HTTP-INGRESS" in flow_ids
    assert "DF-02-AUTH-EXCHANGE" in flow_ids
    assert "DF-03-DB-QUERY" in flow_ids
    assert "DF-05-TOOL-EXEC" in flow_ids
    for df in report.data_flows:
        assert df.source and df.destination and df.crosses_trust_boundary

    # 5. Threats contain explicit Risk Rationale and Mitigations
    for threat in report.threats:
        assert threat.threat_id.startswith("THREAT-STRIDE-")
        assert threat.asset_at_risk
        assert threat.traversed_trust_boundary
        assert threat.associated_data_flow
        assert len(threat.risk_rationale) > 10, f"Threat {threat.threat_id} missing risk rationale!"
        assert len(threat.mitigations) >= 1, f"Threat {threat.threat_id} missing structured mitigations!"
        assert threat.owasp_mapping.startswith("A") or "LLM" in threat.owasp_mapping
        assert threat.cwe_id.startswith("CWE-")
