"""
Architectural STRIDE Threat Modeling Engine for AI Penetration Testing Orchestrator.
Explicitly models assets, trust boundaries, data flows, threats, risk rationales,
and mitigations mapped to STRIDE and relevant OWASP guidance.
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


class Asset(BaseModel):
    asset_id: str
    name: str
    asset_type: str  # e.g., "Credentials", "PII / User Data", "Database Store", "Compute Host", "AI Execution Plane"
    classification: str  # "Confidential", "Restricted", "Internal"
    description: str
    associated_endpoints: List[str] = Field(default_factory=list)


class TrustBoundary(BaseModel):
    boundary_id: str
    name: str
    from_zone: str
    to_zone: str
    description: str
    enforced_controls: str


class DataFlow(BaseModel):
    flow_id: str
    name: str
    source: str
    destination: str
    protocol: str
    data_assets: List[str] = Field(default_factory=list)
    crosses_trust_boundary: str


class ThreatItem(BaseModel):
    threat_id: str
    category: STRIDECategory
    title: str
    description: str
    affected_components: List[str]
    asset_at_risk: str
    traversed_trust_boundary: str
    associated_data_flow: str
    potential_impact: str
    risk_level: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    risk_rationale: str
    mitigation_strategy: str
    mitigations: List[str] = Field(default_factory=list)
    owasp_mapping: str
    cwe_id: str


class ThreatModelReport(BaseModel):
    target_host: str
    assets: List[Asset] = Field(default_factory=list)
    trust_boundaries: List[TrustBoundary] = Field(default_factory=list)
    data_flows: List[DataFlow] = Field(default_factory=list)
    threats: List[ThreatItem] = Field(default_factory=list)
    total_threats: int
    threats_by_category: Dict[str, int] = Field(default_factory=dict)
    high_risk_surfaces: List[str] = Field(default_factory=list)
    architectural_summary: str


class ThreatModelingEngine:
    """Evaluates application attack surfaces using architectural Microsoft STRIDE methodology."""

    def __init__(self):
        pass

    def generate_threat_model(self, recon: ReconData, endpoints: List[ServiceEndpoint]) -> ThreatModelReport:
        host = recon.target_domain or "target.system"

        auth_endpoints = [ep for ep in endpoints if ep.surface_category == "AUTH" or any(k in ep.url.lower() for k in ["login", "auth", "token", "session"])]
        admin_endpoints = [ep for ep in endpoints if ep.surface_category == "ADMIN" or any(k in ep.url.lower() for k in ["admin", "manage", "control", "dashboard"])]
        data_endpoints = [ep for ep in endpoints if ep.surface_category == "DATA" or any(k in ep.url.lower() for k in ["user", "profile", "account", "order"])]
        api_endpoints = [ep for ep in endpoints if ep.surface_category == "API" or "/api/" in ep.url.lower()]
        param_endpoints = [ep for ep in endpoints if ep.parameters]
        ai_endpoints = [ep for ep in endpoints if any(k in ep.url.lower() for k in ["ai", "chat", "llm", "completion", "agent", "tool"])]

        # =====================================================================
        # 1. ARCHITECTURAL ASSETS
        # =====================================================================
        assets: List[Asset] = [
            Asset(
                asset_id="ASSET-AUTH-TOKENS",
                name="Identity Tokens & Session State",
                asset_type="Credentials",
                classification="Confidential",
                description="JWT bearer tokens, session identifiers, and user password hashes governing authenticated access.",
                associated_endpoints=[ep.url for ep in auth_endpoints[:5]]
            ),
            Asset(
                asset_id="ASSET-USER-PII",
                name="User Account & Profile Records",
                asset_type="PII / User Data",
                classification="Confidential",
                description="Personally Identifiable Information (PII), customer profile data, and identity records stored in backend tables.",
                associated_endpoints=[ep.url for ep in (data_endpoints or endpoints)[:5]]
            ),
            Asset(
                asset_id="ASSET-DB-STORAGE",
                name="Relational Database & Business State",
                asset_type="Data Store",
                classification="Restricted",
                description="Primary relational database tables storing application state, transactional records, and access permissions.",
                associated_endpoints=[ep.url for ep in param_endpoints[:5]]
            ),
            Asset(
                asset_id="ASSET-ADMIN-CONFIG",
                name="Administrative Configuration & Access Controls",
                asset_type="Configuration",
                classification="Restricted",
                description="System-level configuration flags, administrative privileges, and role definitions.",
                associated_endpoints=[ep.url for ep in admin_endpoints[:5]]
            ),
            Asset(
                asset_id="ASSET-INFRA-HOST",
                name="Host System & Cloud Metadata Fabric",
                asset_type="Compute Infrastructure",
                classification="Internal",
                description="Underlying Linux/Windows runtime environment, process tree, and Cloud Instance Metadata Service (IMDS).",
                associated_endpoints=[recon.target_domain]
            )
        ]

        if ai_endpoints:
            assets.append(Asset(
                asset_id="ASSET-AI-TOOLS",
                name="AI Model Prompts & Autonomous System Tools",
                asset_type="AI Execution Plane",
                classification="Confidential",
                description="Proprietary system prompts, model reasoning context, and backend tool execution interfaces.",
                associated_endpoints=[ep.url for ep in ai_endpoints[:5]]
            ))

        # =====================================================================
        # 2. TRUST BOUNDARIES
        # =====================================================================
        trust_boundaries: List[TrustBoundary] = [
            TrustBoundary(
                boundary_id="TB-01-INGRESS",
                name="Public Internet to API Gateway / Ingress",
                from_zone="Untrusted Public Internet",
                to_zone="Ingress Controller / Reverse Proxy",
                description="Demarcation line separating external public client requests from perimeter routing infrastructure.",
                enforced_controls="TLS Termination, WAF filtering, IP rate limiting"
            ),
            TrustBoundary(
                boundary_id="TB-02-IDENTITY",
                name="Unauthenticated Client to Authenticated Context",
                from_zone="Public Client Web Tier",
                to_zone="Authenticated Application Business Logic",
                description="Enforces cryptographic authentication (JWT / session validation) before granting access to user context.",
                enforced_controls="Asymmetric JWT signature verification (RS256), session cookie validation"
            ),
            TrustBoundary(
                boundary_id="TB-03-DATASTORE",
                name="Application Logic to Database Tier",
                from_zone="Application Service Layer",
                to_zone="Internal Database Storage Engine",
                description="Separates untrusted user-supplied parameter inputs from direct SQL query evaluation on disk.",
                enforced_controls="Parameterized ORM query compilation, database user least privilege"
            ),
            TrustBoundary(
                boundary_id="TB-04-CLOUD-METADATA",
                name="Application Container to Cloud Infrastructure",
                from_zone="Application Container Process",
                to_zone="Cloud Provider IMDS & Internal Network Daemons",
                description="Boundary separating application network egress from sensitive link-local metadata (169.254.169.254) and internal ports.",
                enforced_controls="Outbound egress firewall rules, IMDSv2 token enforcement, URL scheme allowlisting"
            )
        ]

        if ai_endpoints:
            trust_boundaries.append(TrustBoundary(
                boundary_id="TB-05-AI-PLANE",
                name="User Prompt Input to Autonomous Tool Execution",
                from_zone="Uncontrolled User Input Prompt",
                to_zone="Autonomous LLM Tool / System Execution Plane",
                description="Boundary separating natural language prompt processing from executable server tools and shell processes.",
                enforced_controls="Prompt guardrails, strict tool allowlists, human-in-the-loop authorization gates"
            ))

        # =====================================================================
        # 3. DATA FLOWS
        # =====================================================================
        data_flows: List[DataFlow] = [
            DataFlow(
                flow_id="DF-01-HTTP-INGRESS",
                name="Inbound User HTTP Request",
                source="External Web Browser / API Client",
                destination="Ingress Gateway / FastAPI Router",
                protocol="HTTPS / HTTP 1.1",
                data_assets=["Query Parameters", "HTTP Headers", "POST Request Bodies"],
                crosses_trust_boundary="TB-01-INGRESS"
            ),
            DataFlow(
                flow_id="DF-02-AUTH-EXCHANGE",
                name="Authentication Token Handshake & RBAC Verification",
                source="API Gateway",
                destination="Authentication Middleware / Identity Provider",
                protocol="Internal In-Memory / HTTP",
                data_assets=["JWT Bearer Tokens", "Session Identifiers"],
                crosses_trust_boundary="TB-02-IDENTITY"
            ),
            DataFlow(
                flow_id="DF-03-DB-QUERY",
                name="Dynamic SQL Query Evaluation",
                source="Application Route Handler",
                destination="Relational Database Server (SQLite / PostgreSQL / MySQL)",
                protocol="Database Wire Protocol / Unix Socket",
                data_assets=["User Records", "Account Profiles", "Configuration Tables"],
                crosses_trust_boundary="TB-03-DATASTORE"
            ),
            DataFlow(
                flow_id="DF-04-OUTBOUND-FETCH",
                name="Outbound HTTP Request Dispatch",
                source="Application Backend Egress Client",
                destination="External APIs / Internal Services",
                protocol="HTTP / HTTPS",
                data_assets=["URL Parameters", "Webhook Payloads"],
                crosses_trust_boundary="TB-04-CLOUD-METADATA"
            )
        ]

        if ai_endpoints:
            data_flows.append(DataFlow(
                flow_id="DF-05-TOOL-EXEC",
                name="Autonomous Tool Command Invocation",
                source="LLM Orchestration Layer",
                destination="System OS / Backend Utilities",
                protocol="Process IPC / Subprocess Shell",
                data_assets=["Tool Arguments", "OS Command Strings", "Execution Output"],
                crosses_trust_boundary="TB-05-AI-PLANE"
            ))

        # =====================================================================
        # 4. THREATS (STRIDE) WITH RISK RATIONALE & MITIGATIONS
        # =====================================================================
        threats: List[ThreatItem] = []

        # -----------------------------------------------------------------
        # SPOOFING (S)
        # -----------------------------------------------------------------
        if auth_endpoints or not auth_endpoints:
            threats.append(ThreatItem(
                threat_id="THREAT-STRIDE-S01",
                category=STRIDECategory.SPOOFING,
                title="Authentication Token Forgery & Identity Spoofing",
                description="Adversaries may forge or tamper with authentication bearer tokens (e.g. JWT algorithm 'none' or weak HMAC secrets) to impersonate legitimate users.",
                affected_components=[ep.url for ep in auth_endpoints] if auth_endpoints else [f"{host}/api/auth"],
                asset_at_risk="ASSET-AUTH-TOKENS",
                traversed_trust_boundary="TB-02-IDENTITY",
                associated_data_flow="DF-02-AUTH-EXCHANGE",
                potential_impact="Full account takeover and unauthorized transactional capability across all user accounts.",
                risk_level="HIGH",
                risk_rationale="High Risk: Authentication bypass allows adversaries to circumvent all downstream authorization controls without requiring valid credentials.",
                mitigation_strategy="Enforce cryptographically strong asymmetric signatures (RS256/Ed25519) on all JWTs, strictly forbid 'none' algorithm, and rotate signing keys periodically.",
                mitigations=[
                    "Enforce RS256/Ed25519 asymmetric signature verification and reject tokens specifying 'alg': 'none'.",
                    "Store JWT signing keys in a dedicated Hardware Security Module (HSM) or Secret Manager with automated rotation.",
                    "Verify standard claims ('exp', 'nbf', 'iss', 'aud') on every incoming authenticated request."
                ],
                owasp_mapping="A07:2021-Identification and Authentication Failures",
                cwe_id="CWE-287"
            ))

        # -----------------------------------------------------------------
        # TAMPERING (T)
        # -----------------------------------------------------------------
        if param_endpoints:
            threats.append(ThreatItem(
                threat_id="THREAT-STRIDE-T01",
                category=STRIDECategory.TAMPERING,
                title="Input Parameter Manipulation & SQL Query Tampering",
                description="Unsanitized user inputs concatenated into dynamic database queries or state operations permit adversaries to alter database queries or corrupt business state.",
                affected_components=[ep.url for ep in param_endpoints[:5]],
                asset_at_risk="ASSET-DB-STORAGE",
                traversed_trust_boundary="TB-03-DATASTORE",
                associated_data_flow="DF-03-DB-QUERY",
                potential_impact="Unauthorized modification of sensitive records, balance manipulation, or total database destruction.",
                risk_level="CRITICAL",
                risk_rationale="Critical Risk: Arbitrary query modification directly crosses the database trust boundary and can compromise the integrity of the entire persistence tier.",
                mitigation_strategy="Enforce strict parameterized queries or ORM bind variables on all database interactions; apply Pydantic schema validation for all parameters.",
                mitigations=[
                    "Mandate parameterized ORM queries (e.g., SQLAlchemy select/bind) across all database interactions.",
                    "Enforce strict Pydantic/JSON schema validation on all incoming query parameters and request bodies.",
                    "Restrict database connection pool permissions following the Principle of Least Privilege (e.g. read-only where appropriate)."
                ],
                owasp_mapping="A03:2021-Injection",
                cwe_id="CWE-89"
            ))

        # -----------------------------------------------------------------
        # REPUDIATION (R)
        # -----------------------------------------------------------------
        mutation_endpoints = [ep for ep in endpoints if ep.method in ["POST", "PUT", "DELETE"] or ep.surface_category in ["AUTH", "DATA"]]
        if mutation_endpoints:
            threats.append(ThreatItem(
                threat_id="THREAT-STRIDE-R01",
                category=STRIDECategory.REPUDIATION,
                title="Insufficient Transaction Audit Logging & Non-Repudiation Deficit",
                description="State-altering API calls may lack tamper-evident forensic logging, allowing malicious actors to deny performing actions or leaving incidents uninvestigable.",
                affected_components=[ep.url for ep in mutation_endpoints[:5]],
                asset_at_risk="ASSET-USER-PII",
                traversed_trust_boundary="TB-01-INGRESS",
                associated_data_flow="DF-01-HTTP-INGRESS",
                potential_impact="Inability to trace forensic origin of data manipulation, failed compliance audits, disputed chargebacks.",
                risk_level="MEDIUM",
                risk_rationale="Medium Risk: Missing audit records do not directly compromise data confidentiality, but prevent forensic attribution and non-repudiation.",
                mitigation_strategy="Implement append-only, cryptographically hashed audit trails for sensitive operations capturing timestamp, user ID, client IP, and request digest.",
                mitigations=[
                    "Implement centralized, append-only audit logging for all authentication and state-altering operations.",
                    "Capture structured forensic metadata: user ID, client IP, timestamp (UTC), action type, and cryptographic request digest.",
                    "Stream logs in real-time to an immutable, write-once-read-many (WORM) storage bucket."
                ],
                owasp_mapping="A09:2021-Security Logging and Monitoring Failures",
                cwe_id="CWE-778"
            ))

        # -----------------------------------------------------------------
        # INFORMATION DISCLOSURE (I)
        # -----------------------------------------------------------------
        threats.append(ThreatItem(
            threat_id="THREAT-STRIDE-I01",
            category=STRIDECategory.INFORMATION_DISCLOSURE,
            title="Technology Stack Fingerprinting & Verbose Error Leakage",
            description="Server response headers, runtime error exceptions, and unauthenticated metadata endpoints disclose underlying framework and runtime versions.",
            affected_components=[recon.target_domain],
            asset_at_risk="ASSET-INFRA-HOST",
            traversed_trust_boundary="TB-01-INGRESS",
            associated_data_flow="DF-01-HTTP-INGRESS",
            potential_impact="Assists attackers in tailoring known CVE exploits targeting exact component and framework versions.",
            risk_level="MEDIUM",
            risk_rationale="Medium Risk: Information leakage reduces adversary effort during reconnaissance by revealing exact patch levels and unhardened dependencies.",
            mitigation_strategy="Strip 'Server' and 'X-Powered-By' headers in reverse proxy configs; disable detailed exception stack dumps in production environments.",
            mitigations=[
                "Strip 'Server', 'X-Powered-By', and technology banners in reverse proxy (Nginx / Cloudflare) configs.",
                "Disable debug mode and exception stack dumps in production application runtimes.",
                "Deploy custom error pages returning generic correlation IDs rather than internal tracebacks."
            ],
            owasp_mapping="A05:2021-Security Misconfiguration",
            cwe_id="CWE-200"
        ))

        # -----------------------------------------------------------------
        # DENIAL OF SERVICE (D)
        # -----------------------------------------------------------------
        threats.append(ThreatItem(
            threat_id="THREAT-STRIDE-D01",
            category=STRIDECategory.DENIAL_OF_SERVICE,
            title="Unthrottled API Resource Exhaustion & Heavy Query DoS",
            description="Lack of explicit rate-limiting tokens allows concurrent high-frequency queries to exhaust backend threads and database connection pools.",
            affected_components=[ep.url for ep in (api_endpoints or endpoints)[:5]],
            asset_at_risk="ASSET-INFRA-HOST",
            traversed_trust_boundary="TB-01-INGRESS",
            associated_data_flow="DF-01-HTTP-INGRESS",
            potential_impact="Application downtime, degraded SLA, resource starvation for legitimate users.",
            risk_level="HIGH",
            risk_rationale="High Risk: Unthrottled API endpoints allow low-bandwidth attackers to consume database connection pools and starve legitimate traffic.",
            mitigation_strategy="Deploy leaky-bucket or token-bucket rate limiting (e.g. Redis sliding window) at the API gateway layer.",
            mitigations=[
                "Deploy token-bucket or sliding-window rate limiting at the API gateway layer (e.g. 60 requests/minute per client IP/user).",
                "Enforce pagination limits (e.g. max 'limit=100') and query timeouts on all database-backed endpoints.",
                "Implement asynchronous background workers for computationally intensive processing."
            ],
            owasp_mapping="A04:2021-Insecure Design",
            cwe_id="CWE-400"
        ))

        # -----------------------------------------------------------------
        # ELEVATION OF PRIVILEGE (E)
        # -----------------------------------------------------------------
        if admin_endpoints or any("admin" in ep.url.lower() for ep in endpoints):
            threats.append(ThreatItem(
                threat_id="THREAT-STRIDE-E01",
                category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
                title="Horizontal & Vertical Role Authorization Bypass",
                description="Administrative endpoints or object identifiers may not consistently enforce server-side Role-Based Access Control (RBAC).",
                affected_components=[ep.url for ep in admin_endpoints],
                asset_at_risk="ASSET-ADMIN-CONFIG",
                traversed_trust_boundary="TB-02-IDENTITY",
                associated_data_flow="DF-02-AUTH-EXCHANGE",
                potential_impact="Unprivileged actors executing administrative actions, data wiping, and system reconfiguration.",
                risk_level="CRITICAL",
                risk_rationale="Critical Risk: Elevation of privilege directly violates the principle of least privilege, granting unprivileged callers full administrative control.",
                mitigation_strategy="Adopt centralized authorization policy middleware; enforce Principle of Least Privilege across all route handlers.",
                mitigations=[
                    "Implement centralized authorization policy middleware (e.g., Open Policy Agent or RBAC dependency guards).",
                    "Validate user roles and permissions on the server side on every request, never trusting client-supplied headers.",
                    "Audit object-level ownership checks on all entity endpoints to eliminate horizontal IDOR."
                ],
                owasp_mapping="A01:2021-Broken Access Control",
                cwe_id="CWE-285"
            ))

        # -----------------------------------------------------------------
        # AI / LLM EXTENSION (If AI endpoints present)
        # -----------------------------------------------------------------
        if ai_endpoints:
            threats.append(ThreatItem(
                threat_id="THREAT-STRIDE-AI01",
                category=STRIDECategory.TAMPERING,
                title="Direct Prompt Injection & System Persona Hijacking",
                description="Untrusted user input injected into LLM context overrides base system instructions and guardrail policies.",
                affected_components=[ep.url for ep in ai_endpoints[:5]],
                asset_at_risk="ASSET-AI-TOOLS",
                traversed_trust_boundary="TB-05-AI-PLANE",
                associated_data_flow="DF-05-TOOL-EXEC",
                potential_impact="Extraction of confidential system prompts, evasion of safety filters, and hijacked agent responses.",
                risk_level="HIGH",
                risk_rationale="High Risk: Prompt injection bypasses application logic at the LLM reasoning boundary, potentially commanding integrated tools.",
                mitigation_strategy="Implement input/output guardrails (e.g. NeMo Guardrails, Llama Guard), delimiter isolation, and avoid embedding secrets in system prompts.",
                mitigations=[
                    "Implement multi-layer input and output guardrails to detect adversarial prompt override attempts.",
                    "Isolate untrusted user input within strict delimiters (e.g. XML tags or Markdown blocks) and instruct models to treat them as data only.",
                    "Remove secret API keys and confidential instructions from model system prompts entirely."
                ],
                owasp_mapping="OWASP LLM01:2025-Prompt Injection",
                cwe_id="CWE-77"
            ))

        # Category Counts
        category_counts: Dict[str, int] = {}
        for t in threats:
            category_counts[t.category.value] = category_counts.get(t.category.value, 0) + 1

        high_surfaces = list(set([ep.url for ep in endpoints if ep.surface_category in ["AUTH", "ADMIN", "DATA"]]))

        summary = (
            f"Architectural STRIDE Threat Model for {host}: Identified {len(assets)} core data/compute assets, "
            f"{len(trust_boundaries)} trust boundaries, and {len(data_flows)} active data flows. "
            f"Mapped {len(threats)} structural threats across {len(endpoints)} attack surfaces, requiring priority "
            f"safeguards on {len(high_surfaces)} high-risk data and administrative endpoints."
        )

        return ThreatModelReport(
            target_host=host,
            assets=assets,
            trust_boundaries=trust_boundaries,
            data_flows=data_flows,
            threats=threats,
            total_threats=len(threats),
            threats_by_category=category_counts,
            high_risk_surfaces=high_surfaces[:10],
            architectural_summary=summary
        )
