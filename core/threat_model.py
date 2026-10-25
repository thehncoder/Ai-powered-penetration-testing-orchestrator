"""
STRIDE Threat Modeling Engine for AI Penetration Testing Orchestrator.
Analyzes mapped attack surfaces, architectural components, and data flows to synthesize
comprehensive STRIDE threat profiles and defensive mitigation blueprints.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from core.schemas import ServiceEndpoint, ReconData


class STRIDECategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class ThreatItem(BaseModel):
    threat_id: str
    category: STRIDECategory
    title: str
    description: str
    affected_components: List[str]
    potential_impact: str
    risk_level: str = "HIGH" # CRITICAL, HIGH, MEDIUM, LOW
    mitigation_strategy: str
    owasp_mapping: str
    cwe_id: str


class ThreatModelReport(BaseModel):
    target_host: str
    total_threats: int
    threats_by_category: Dict[str, int]
    high_risk_surfaces: List[str]
    threats: List[ThreatItem]
    architectural_summary: str


class ThreatModelingEngine:
    """Evaluates application attack surfaces using Microsoft STRIDE methodology."""

    def __init__(self):
        pass

    def generate_threat_model(self, recon: ReconData, endpoints: List[ServiceEndpoint]) -> ThreatModelReport:
        threats: List[ThreatItem] = []
        host = recon.target_domain

        auth_endpoints = [ep for ep in endpoints if ep.surface_category == "AUTH"]
        admin_endpoints = [ep for ep in endpoints if ep.surface_category == "ADMIN"]
        data_endpoints = [ep for ep in endpoints if ep.surface_category == "DATA"]
        api_endpoints = [ep for ep in endpoints if ep.surface_category == "API"]

        # =====================================================================
        # 1. SPOOFING (S)
        # =====================================================================
        if auth_endpoints:
            threats.append(ThreatItem(
                threat_id="THREAT-STRIDE-S01",
                category=STRIDECategory.SPOOFING,
                title="Authentication Token Forgery & Identity Spoofing",
                description="Adversaries may forge or tamper with authentication bearer tokens or session cookies to impersonate legitimate users.",
                affected_components=[ep.url for ep in auth_endpoints],
                potential_impact="Full account takeover and unauthorized transactional capability.",
                risk_level="HIGH",
                mitigation_strategy="Enforce cryptographically strong asymmetric signatures (RS256/Ed25519) on all JWTs, strictly forbid 'none' algorithm, and rotate signing keys periodically.",
                owasp_mapping="A07:2021-Identification and Authentication Failures",
                cwe_id="CWE-287"
            ))

        # =====================================================================
        # 2. TAMPERING (T)
        # =====================================================================
        param_endpoints = [ep for ep in endpoints if ep.parameters]
        if param_endpoints:
            threats.append(ThreatItem(
                threat_id="THREAT-STRIDE-T01",
                category=STRIDECategory.TAMPERING,
                title="Input Parameter Manipulation & Query Tampering",
                description="Unsanitized query parameters or request bodies could allow adversaries to tamper with database queries or application state.",
                affected_components=[ep.url for ep in param_endpoints[:5]],
                potential_impact="Unauthorized data modification, unauthorized balance alteration, or state corruption.",
                risk_level="HIGH",
                mitigation_strategy="Enforce strict Pydantic/JSON schema validation on all inputs; utilize parameterized ORM queries; apply cryptographic HMACs for stateful parameters.",
                owasp_mapping="A03:2021-Injection",
                cwe_id="CWE-20"
            ))

        # =====================================================================
        # 3. REPUDIATION (R)
        # =====================================================================
        mutation_endpoints = [ep for ep in endpoints if ep.method in ["POST", "PUT", "DELETE"] or ep.surface_category in ["AUTH", "DATA"]]
        if mutation_endpoints:
            threats.append(ThreatItem(
                threat_id="THREAT-STRIDE-R01",
                category=STRIDECategory.REPUDIATION,
                title="Insufficient Transaction Audit Logging & Non-Repudiation Deficit",
                description="State-altering API calls may lack tamper-evident forensic logging, allowing malicious actors to deny performing actions.",
                affected_components=[ep.url for ep in mutation_endpoints[:5]],
                potential_impact="Inability to trace forensic origin of data manipulation, failed compliance audits, disputed chargebacks.",
                risk_level="MEDIUM",
                mitigation_strategy="Implement append-only, cryptographically hashed audit trails for sensitive operations capturing timestamp, user ID, client IP, and request digest.",
                owasp_mapping="A09:2021-Security Logging and Monitoring Failures",
                cwe_id="CWE-778"
            ))

        # =====================================================================
        # 4. INFORMATION DISCLOSURE (I)
        # =====================================================================
        if recon.server_headers or any("debug" in ep.url.lower() or "config" in ep.url.lower() for ep in endpoints):
            threats.append(ThreatItem(
                threat_id="THREAT-STRIDE-I01",
                category=STRIDECategory.INFORMATION_DISCLOSURE,
                title="Technology Stack Fingerprinting & Verbose Error Leakage",
                description="Server response headers, stack traces, and unauthenticated metadata endpoints disclose underlying framework and runtime versions.",
                affected_components=[recon.target_domain],
                potential_impact="Assists attackers in tailoring zero-day exploits targeting exact component versions.",
                risk_level="MEDIUM",
                mitigation_strategy="Strip 'Server' and 'X-Powered-By' headers in reverse proxy configs; disable detailed exception stack dumps in production environments.",
                owasp_mapping="A05:2021-Security Misconfiguration",
                cwe_id="CWE-200"
            ))

        # =====================================================================
        # 5. DENIAL OF SERVICE (D)
        # =====================================================================
        threats.append(ThreatItem(
            threat_id="THREAT-STRIDE-D01",
            category=STRIDECategory.DENIAL_OF_SERVICE,
            title="Unthrottled API Resource Exhaustion & Heavy Query DoS",
            description="Lack of explicit rate-limiting tokens allows concurrent high-frequency queries to exhaust backend threads and database connection pools.",
            affected_components=[ep.url for ep in (api_endpoints or endpoints)[:5]],
            potential_impact="Application downtime, degraded SLA, resource starvation for legitimate users.",
            risk_level="HIGH",
            mitigation_strategy="Deploy leaky-bucket or token-bucket rate limiting (e.g. Redis sliding window) at the API gateway layer.",
            owasp_mapping="A04:2021-Insecure Design",
            cwe_id="CWE-400"
        ))

        # =====================================================================
        # 6. ELEVATION OF PRIVILEGE (E)
        # =====================================================================
        if admin_endpoints or any("admin" in ep.url.lower() for ep in endpoints):
            threats.append(ThreatItem(
                threat_id="THREAT-STRIDE-E01",
                category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
                title="Horizontal & Vertical Role Authorization Bypass",
                description="Administrative endpoints or object identifiers may not consistently enforce server-side Role-Based Access Control (RBAC).",
                affected_components=[ep.url for ep in admin_endpoints],
                potential_impact="Unprivileged actors executing administrative actions, data wiping, and system reconfiguration.",
                risk_level="CRITICAL",
                mitigation_strategy="Adopt centralized authorization policy middleware; enforce Principle of Least Privilege across all route handlers.",
                owasp_mapping="A01:2021-Broken Access Control",
                cwe_id="CWE-285"
            ))

        # Summary statistics
        category_counts: Dict[str, int] = {}
        for t in threats:
            category_counts[t.category.value] = category_counts.get(t.category.value, 0) + 1

        high_surfaces = list(set([ep.url for ep in endpoints if ep.surface_category in ["AUTH", "ADMIN", "DATA"]]))

        summary = (
            f"STRIDE Threat Analysis for {host} identified {len(threats)} structural threat vectors across "
            f"{len(endpoints)} mapped attack surfaces. Priority attention is required for "
            f"{len(high_surfaces)} high-risk data and administrative endpoints."
        )

        return ThreatModelReport(
            target_host=host,
            total_threats=len(threats),
            threats_by_category=category_counts,
            high_risk_surfaces=high_surfaces[:10],
            threats=threats,
            architectural_summary=summary
        )
