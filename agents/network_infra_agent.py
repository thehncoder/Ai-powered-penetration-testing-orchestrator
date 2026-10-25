"""
Wave 3: Infrastructure, Network & Configuration Specialist Agent.
Probes for CORS misconfigurations, directory path traversal, sensitive file exposure,
and missing security hardening headers.
"""

from typing import List, Dict, Any, Optional
import httpx
from agents.base_agent import BaseAgent
from core.schemas import ServiceEndpoint, VulnerabilityFinding, ConfidenceLevel, TargetScope
from core.evidence_vault import EvidenceVault
from core.llm_brain import AIBrain
from core.cvss_engine import CVSSEngine


class NetworkInfraAgent(BaseAgent):
    """Specialist agent targeting Infrastructure, Configuration, and Path Traversal flaws."""

    def __init__(
        self,
        scope: TargetScope,
        vault: EvidenceVault,
        brain: AIBrain,
        transport: Optional[httpx.AsyncBaseTransport] = None
    ):
        super().__init__("NetworkInfraAgent", scope, vault, brain, transport=transport)

    async def execute(self, endpoints: List[ServiceEndpoint]) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []

        async with self.get_client(timeout=5.0) as client:
            # Test 1: Global Security Headers on Base Target
            base_url = self.scope.target_url
            res = await self._send_request(client, "GET", base_url)
            if res is not None:
                headers = {k.lower(): v for k, v in res.headers.items()}
                missing_headers = []
                if "content-security-policy" not in headers:
                    missing_headers.append("Content-Security-Policy (CSP)")
                if "x-frame-options" not in headers:
                    missing_headers.append("X-Frame-Options")
                if "x-content-type-options" not in headers:
                    missing_headers.append("X-Content-Type-Options")

                if missing_headers:
                    evidence = self.record_finding_evidence(
                        method="GET",
                        url=base_url,
                        status_code=res.status_code,
                        payload="Header Audit Probe",
                        response_body="\n".join([f"{k}: {v}" for k, v in res.headers.items()])
                    )
                    cvss = CVSSEngine.get_template_metrics("misconfig")
                    finding = VulnerabilityFinding(
                        finding_id=f"VULN-HDR-{len(findings)+1:03d}",
                        title=f"Missing Critical Security Hardening Headers: {', '.join(missing_headers)}",
                        severity=cvss.severity,
                        category="SECURITY_MISCONFIG",
                        owasp_top10="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-16",
                        affected_url=base_url,
                        http_method="GET",
                        affected_parameter="HTTP Response Headers",
                        cvss=cvss,
                        confidence=ConfidenceLevel.CERTAIN,
                        description=f"The application responds without critical security defenses ({', '.join(missing_headers)}), increasing susceptibility to clickjacking and MIME-type sniffing.",
                        plain_english_summary="The server is missing browser security shield instructions. These headers tell browsers not to allow other websites to frame your site inside an invisible window (clickjacking) or guess file types dangerously.",
                        where_is_the_flaw=f"HTTP response headers on base URL '{base_url}'. The web server configuration is missing defensive HTTP headers: {', '.join(missing_headers)}.",
                        how_attacker_exploits="1. Attacker embeds your website in an invisible iframe on a malicious webpage (Clickjacking).\n2. The attacker tricks a logged-in user into clicking buttons on the overlay, unknowingly performing transactions or altering account settings.",
                        real_world_impact="Clickjacking & MIME Spoofing: Users can be tricked into performing unintended state changes, or browsers can be tricked into executing malicious scripts via MIME confusion.",
                        reproduction_steps=[
                            f"Send GET request to {base_url}",
                            "Inspect response headers to verify absence of CSP, X-Frame-Options, or X-Content-Type-Options"
                        ],
                        evidence=evidence,
                        remediation_advice="Configure reverse proxy or web application middleware to return defensive security headers.",
                        remediation_code_sample="""# Secure Nginx Configuration:
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Content-Security-Policy "default-src 'self';" always;""",
                        discovered_by_agent=self.name,
                        verified_by_gate=False
                    )
                    findings.append(finding)

            # Test 2: CORS Misconfiguration (Insecure Origin Reflection)
            test_origin = "https://evil-attacker-domain.com"
            cors_res = await self._send_request(client, "GET", base_url, headers={"Origin": test_origin})
            if cors_res is not None:
                cors_h = {k.lower(): v for k, v in cors_res.headers.items()}
                allow_origin = cors_h.get("access-control-allow-origin", "")
                allow_creds = cors_h.get("access-control-allow-credentials", "").lower() == "true"

                if (allow_origin == "*" and allow_creds) or (allow_origin == test_origin):
                    evidence = self.record_finding_evidence(
                        method="GET",
                        url=base_url,
                        status_code=cors_res.status_code,
                        payload=f"Origin: {test_origin}",
                        response_body=f"Access-Control-Allow-Origin: {allow_origin}\nAccess-Control-Allow-Credentials: {allow_creds}"
                    )
                    cvss = CVSSEngine.get_template_metrics("cors")
                    finding = VulnerabilityFinding(
                        finding_id=f"VULN-CORS-{len(findings)+1:03d}",
                        title="Permissive Cross-Origin Resource Sharing (CORS) Misconfiguration",
                        severity=cvss.severity,
                        category="SECURITY_MISCONFIG",
                        owasp_top10="A05:2021-Security Misconfiguration",
                        cwe_id="CWE-942",
                        affected_url=base_url,
                        http_method="GET",
                        affected_parameter="Origin Header",
                        cvss=cvss,
                        confidence=ConfidenceLevel.CERTAIN,
                        description="The CORS policy dynamically reflects arbitrary origins with credential sharing allowed, enabling cross-origin data theft.",
                        plain_english_summary="The server has an overly permissive Cross-Origin policy that accepts requests from any external website and shares private user cookies. This breaks the browser's standard security boundaries.",
                        where_is_the_flaw=f"CORS response headers on '{base_url}'. The server dynamically mirrors the untrusted incoming 'Origin' header ({test_origin}) into 'Access-Control-Allow-Origin' alongside 'Access-Control-Allow-Credentials: true'.",
                        how_attacker_exploits="1. Attacker hosts a malicious webpage that executes a background fetch request to your API.\n2. When a logged-in user visits the attacker's page, the browser attaches their private session cookies.\n3. Because the server allows any origin with credentials, the attacker's script reads and exfiltrates the user's private data.",
                        real_world_impact="Silent User Data Theft: Malicious third-party sites can read personal user profiles, private messages, account balances, and sensitive transaction histories.",
                        reproduction_steps=[
                            f"Issue request with header 'Origin: {test_origin}'",
                            "Verify reflection in Access-Control-Allow-Origin response header"
                        ],
                        evidence=evidence,
                        remediation_advice="Enforce a strict server-side whitelist of trusted domains and avoid echoing arbitrary Origin headers.",
                        remediation_code_sample="""# Secure FastAPI CORS Setup:
origins = ["https://trusted-domain.com"]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True)""",
                        discovered_by_agent=self.name,
                        verified_by_gate=False
                    )
                    findings.append(finding)

            # Test 3: Path Traversal / Arbitrary File Read
            for ep in endpoints:
                if ep.surface_category == "STATIC":
                    continue
                ep.tested_by_agents.append(self.name)

                traversal_params = ep.parameters if ep.parameters else ["file", "path", "filename", "doc", "view", "page"]
                traversal_payloads = [
                    "../../../../etc/passwd",
                    "..\\..\\..\\..\\windows\\win.ini"
                ]

                for p in traversal_params[:3]:
                    for payload in traversal_payloads:
                        probe_params = {p: payload}
                        res = await self._send_request(client, ep.method, ep.url, params=probe_params)
                        if res is not None and res.status_code == 200:
                            if "root:x:0:0:" in res.text or "[extensions]" in res.text.lower() or "[fonts]" in res.text.lower():
                                evidence = self.record_finding_evidence(
                                    method=ep.method,
                                    url=f"{ep.url}?{p}={payload}",
                                    status_code=res.status_code,
                                    payload=payload,
                                    response_body=res.text[:1000]
                                )
                                cvss = CVSSEngine.create_metrics(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N")
                                finding = VulnerabilityFinding(
                                    finding_id=f"VULN-TRAV-{len(findings)+1:03d}",
                                    title=f"Path Traversal Arbitrary File Read in '{p}'",
                                    severity=cvss.severity,
                                    category="SENSITIVE_DATA_EXPOSURE",
                                    owasp_top10="A01:2021-Broken Access Control",
                                    cwe_id="CWE-22",
                                    affected_url=ep.url,
                                    http_method=ep.method,
                                    affected_parameter=p,
                                    cvss=cvss,
                                    confidence=ConfidenceLevel.CERTAIN,
                                    description="Arbitrary file system paths can be read due to insufficient validation of path traversal dot-dot-slash sequence.",
                                    plain_english_summary="The application takes a filename from the user and looks it up on the hard drive without verifying that it stays in the allowed folder. Using '../' (dot-dot-slash), an attacker can escape the web folder and read any system file on the server.",
                                    where_is_the_flaw=f"Endpoint '{ep.method} {ep.url}' at parameter '{p}'. The backend file loading function opens file paths directly without verifying if the resolved canonical path is confined to the base directory.",
                                    how_attacker_exploits=f"1. Attacker sends a path containing traversal sequences like '{payload}'.\n2. The operating system navigates up the directory hierarchy to the root filesystem.\n3. The server reads and returns sensitive files such as operating system accounts, environment variables, or secret keys.",
                                    real_world_impact="Severe File System & Secret Exposure: Direct read access to server configuration files, database credentials, environment variables, and password hashes.",
                                    reproduction_steps=[
                                        f"Send {ep.method} request with parameter {p}={payload}",
                                        "Observe server host file contents returned in response"
                                    ],
                                    evidence=evidence,
                                    remediation_advice="Resolve canonical paths and verify the normalized path is strictly confined to the designated base directory.",
                                    remediation_code_sample="""# Secure File Resolution (Python pathlib):
safe_dir = Path("/safe/storage/").resolve()
target_path = (safe_dir / user_input).resolve()
if not target_path.is_relative_to(safe_dir):
    raise PermissionError("Path traversal attempt detected")""",
                                    discovered_by_agent=self.name,
                                    verified_by_gate=False
                                )
                                findings.append(finding)
                                ep.tested_vectors.append("PATH_TRAVERSAL")
                                break

        return findings
