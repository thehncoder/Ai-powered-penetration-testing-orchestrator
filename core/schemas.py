"""
Core Data Schemas and JSON Schema Validators for AI Penetration Testing Orchestrator.
Enforces strict contracts between pipeline waves, autonomous agents, and quality gates.
"""

from enum import Enum
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
import hashlib
from pydantic import BaseModel, Field, HttpUrl, field_validator


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class QualityGateStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"
    CONDITIONAL_PASS = "CONDITIONAL_PASS"


class ConfidenceLevel(str, Enum):
    CERTAIN = "CERTAIN"      # 100% verified with deterministic exploit evidence
    FIRM = "FIRM"            # Strong payload reflection / response delta
    TENTATIVE = "TENTATIVE"  # Heuristic inference, requires manual triage


class TargetScope(BaseModel):
    target_url: str = Field(..., description="Target base URL or domain")
    allowed_domains: List[str] = Field(default_factory=list, description="Domains within testing scope")
    excluded_paths: List[str] = Field(default_factory=lambda: ["/logout", "/delete-account", "/admin/wipe"], description="Forbidden paths")
    safe_mode: bool = Field(default=True, description="Enforce non-destructive payloads")
    max_depth: int = Field(default=3, description="Crawl & spider depth")
    concurrency_limit: int = Field(default=5, description="Concurrent agent workers")
    custom_headers: Dict[str, str] = Field(default_factory=dict, description="Headers for authenticated testing")

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: str) -> str:
        v = v.strip().strip('"').strip("'").rstrip("/")
        if not (v.startswith("http://") or v.startswith("https://")):
            v = f"http://{v}"
        return v


class DiscoveredService(BaseModel):
    port: int
    protocol: str = "tcp"
    service_name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None


class ServiceEndpoint(BaseModel):
    url: str
    method: str = "GET"
    parameters: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    auth_required: bool = False
    content_type: Optional[str] = None
    surface_category: str = "API" # e.g., AUTH, ADMIN, DATA, GENERAL, STATIC
    tested_by_agents: List[str] = Field(default_factory=list)
    tested_vectors: List[str] = Field(default_factory=list)


class ReconData(BaseModel):
    target_domain: str
    ip_addresses: List[str] = Field(default_factory=list)
    subdomains: List[str] = Field(default_factory=list)
    open_ports: List[DiscoveredService] = Field(default_factory=list)
    technologies: Dict[str, str] = Field(default_factory=dict) # e.g. {"server": "nginx", "framework": "fastapi"}
    endpoints: List[ServiceEndpoint] = Field(default_factory=list)
    server_headers: Dict[str, str] = Field(default_factory=dict)
    waf_detected: Optional[str] = None
    timestamp: datetime = Field(default_factory=_utc_now)


class EvidenceArtifact(BaseModel):
    evidence_id: str = Field(..., description="Unique evidence tracking hash")
    timestamp: datetime = Field(default_factory=_utc_now)
    request_method: str
    request_url: str
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    response_status_code: int
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body_sample: str = Field(..., description="Truncated proof of vulnerability reflection/execution")
    payload_applied: str = Field(..., description="The probe or exploit payload")
    curl_reproduction: str = Field(..., description="Executable curl command for verification")
    proof_hash: str = Field(..., description="SHA-256 fingerprint of the request/response proof")

    @classmethod
    def generate_proof_hash(cls, url: str, payload: str, response_snippet: str) -> str:
        raw = f"{url}:{payload}:{response_snippet}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16]


class CVSSMetrics(BaseModel):
    version: str = "3.1"
    vector_string: str = Field(..., description="Full CVSS vector string, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    base_score: float = Field(..., ge=0.0, le=10.0)
    severity: SeverityLevel
    attack_vector: str = "NETWORK"
    attack_complexity: str = "LOW"
    privileges_required: str = "NONE"
    user_interaction: str = "NONE"
    scope: str = "UNCHANGED"
    confidentiality: str = "HIGH"
    integrity: str = "HIGH"
    availability: str = "HIGH"


class VulnerabilityFinding(BaseModel):
    finding_id: str
    title: str
    severity: SeverityLevel
    category: str
    owasp_top10: str = "A01:2021-Broken Access Control"
    cwe_id: str = "CWE-200"
    affected_url: str
    http_method: str = "GET"
    affected_parameter: Optional[str] = None
    cvss: CVSSMetrics
    confidence: ConfidenceLevel
    description: str
    plain_english_summary: str = Field(default="", description="Non-technical ELI5 breakdown of what this vulnerability means")
    where_is_the_flaw: str = Field(default="", description="Exact endpoint, parameter, and architectural weak spot")
    how_attacker_exploits: str = Field(default="", description="Step-by-step real-world adversary exploit scenario")
    real_world_impact: str = Field(default="", description="Business risk, user data theft, or financial damage")
    reproduction_steps: List[str] = Field(default_factory=list)
    evidence: EvidenceArtifact
    remediation_advice: str
    remediation_code_sample: Optional[str] = None
    discovered_by_agent: str
    verified_by_gate: bool = False


class QualityGateResult(BaseModel):
    wave_name: str
    gate_timestamp: datetime = Field(default_factory=_utc_now)
    status: QualityGateStatus
    coverage_score: float = Field(..., ge=0.0, le=100.0, description="Percentage of surface covered")
    total_attack_surfaces: int
    attack_surfaces_tested: int
    under_tested_surfaces: List[str] = Field(default_factory=list)
    findings_submitted: int
    findings_verified: int
    findings_rejected: int
    rejection_reasons: Dict[str, int] = Field(default_factory=dict)
    quality_notes: List[str] = Field(default_factory=list)


class VAPTSummary(BaseModel):
    total_findings: int
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    mean_cvss: float = 0.0
    coverage_rate: float = 0.0


class AssessmentReport(BaseModel):
    report_id: str
    generated_at: datetime = Field(default_factory=_utc_now)
    target: TargetScope
    summary: VAPTSummary
    executive_overview: str
    reconnaissance: ReconData
    quality_gates: List[QualityGateResult]
    threat_model: Optional[Dict[str, Any]] = None
    findings: List[VulnerabilityFinding]
    remediation_plan: List[Dict[str, Any]]
