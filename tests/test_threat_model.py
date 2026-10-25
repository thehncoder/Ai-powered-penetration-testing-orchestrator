"""
Unit tests for STRIDE Threat Modeling Engine.
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
    ]

    report = engine.generate_threat_model(recon, endpoints)

    assert report is not None
    assert report.total_threats >= 4
    categories = list(report.threats_by_category.keys())
    assert STRIDECategory.SPOOFING.value in categories
    assert STRIDECategory.ELEVATION_OF_PRIVILEGE.value in categories
    assert STRIDECategory.TAMPERING.value in categories
    assert len(report.high_risk_surfaces) >= 2
