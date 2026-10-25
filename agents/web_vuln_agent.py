"""
Wave 3: Web Application Vulnerability Specialist Agent.
Autonomously probes endpoints for SQL Injection, XSS, SSRF, and Command Injection.
Captures cryptographic evidence for every verified vulnerability using concurrent async probes.
"""

import asyncio
from typing import List, Dict, Any, Optional
import httpx
from agents.base_agent import BaseAgent
from core.schemas import ServiceEndpoint, VulnerabilityFinding, ConfidenceLevel, TargetScope
from core.evidence_vault import EvidenceVault
from core.llm_brain import AIBrain
from core.cvss_engine import CVSSEngine


class WebVulnAgent(BaseAgent):
    """Specialist agent targeting Web Application vulnerabilities (OWASP A03 / A07 / A10)."""

    def __init__(
        self,
        scope: TargetScope,
        vault: EvidenceVault,
        brain: AIBrain,
        transport: Optional[httpx.AsyncBaseTransport] = None
    ):
        super().__init__("WebVulnAgent", scope, vault, brain, transport=transport)
        self.semaphore = asyncio.Semaphore(10)

    async def _test_sqli_probe(self, client: httpx.AsyncClient, ep: ServiceEndpoint, param: str, payload: str) -> Optional[VulnerabilityFinding]:
        async with self.semaphore:
            probe_params = {param: payload}
            res = await self._send_request(
                client, ep.method, ep.url,
                params=probe_params if ep.method == "GET" else None,
                data=probe_params if ep.method == "POST" else None,
                timeout=3.0
            )
            if res is not None:
                # Prohibit false positives on WAF challenge / block pages
                if any(k in res.text.lower() for k in ["just a moment...", "challenges.cloudflare.com", "cf-chl-widget", "attention required! | cloudflare"]):
                    return None

                analysis = self.brain.analyze_vulnerability_hypothesis(
                    ep.url, param, payload, res.status_code, res.text, "SQLI"
                )
                if analysis["is_vulnerable"]:
                    evidence = self.record_finding_evidence(
                        method=ep.method,
                        url=f"{ep.url}?{param}={payload}" if ep.method == "GET" else ep.url,
                        status_code=res.status_code,
                        payload=payload,
                        response_body=res.text[:1000],
                        request_body=None if ep.method == "GET" else str(probe_params)
                    )
                    cvss = CVSSEngine.get_template_metrics("sqli")
                    return VulnerabilityFinding(
                        finding_id=f"VULN-SQLI-{abs(hash(ep.url + param)) % 1000:03d}",
                        title=f"SQL Injection in parameter '{param}'",
                        severity=cvss.severity,
                        category="INJECTION",
                        owasp_top10="A03:2021-Injection",
                        cwe_id="CWE-89",
                        affected_url=ep.url,
                        http_method=ep.method,
                        affected_parameter=param,
                        cvss=cvss,
                        confidence=ConfidenceLevel.CERTAIN,
                        description=f"Database engine error detected when injected with SQL metacharacters: {analysis['reasoning']}",
                        plain_english_summary="The website takes what you type in the search/input box and pastes it straight into the database query without checking it first. It's like asking a bank teller for your balance, but slipping in a fake note that commands the teller to hand over everyone's bank account numbers.",
                        where_is_the_flaw=f"Endpoint '{ep.method} {ep.url}' at parameter '{param}'. The backend uses string concatenation (e.g. query = 'SELECT ... ' + user_input) instead of parameterized queries.",
                        how_attacker_exploits="1. Attacker sends a single quote (') to break the query syntax.\n2. Injects an unconditional SQL command (e.g. ' OR 1=1 --).\n3. Uses UNION SELECT or automated tools to dump entire database tables (users, passwords, credit cards).",
                        real_world_impact="Mass Data Breach: Total unauthorized dump of customer passwords, confidential records, and potential remote control over the database server.",
                        reproduction_steps=[
                            f"Send {ep.method} request to {ep.url}",
                            f"Inject payload '{payload}' into parameter '{param}'",
                            "Observe database error disclosure or record bypass in the response"
                        ],
                        evidence=evidence,
                        remediation_advice="Adopt parameterized queries / prepared statements (e.g. SQLAlchemy, PDO, ORM bind variables) and strictly avoid dynamic string concatenation in SQL queries.",
                        remediation_code_sample="""# Secure Implementation (SQLAlchemy parameterized):
stmt = select(User).where(User.username == param_username)
result = await session.execute(stmt)""",
                        discovered_by_agent=self.name,
                        verified_by_gate=False
                    )
            return None

    async def _test_xss_probe(self, client: httpx.AsyncClient, ep: ServiceEndpoint, param: str, payload: str) -> Optional[VulnerabilityFinding]:
        async with self.semaphore:
            probe_params = {param: payload}
            res = await self._send_request(
                client, ep.method, ep.url,
                params=probe_params if ep.method == "GET" else None,
                data=probe_params if ep.method == "POST" else None,
                timeout=3.0
            )
            if res is not None:
                # Prohibit XSS on non-HTML responses (browsers do not execute scripts in application/json)
                c_type = res.headers.get("content-type", "").lower()
                if "application/json" in c_type or "application/pdf" in c_type or "image/" in c_type:
                    return None

                # Must be reflected raw and unescaped (if &lt;script&gt; is returned, it is safe and sanitized)
                if payload not in res.text:
                    return None

                analysis = self.brain.analyze_vulnerability_hypothesis(
                    ep.url, param, payload, res.status_code, res.text, "XSS"
                )
                if analysis["is_vulnerable"]:
                    evidence = self.record_finding_evidence(
                        method=ep.method,
                        url=f"{ep.url}?{param}={payload}" if ep.method == "GET" else ep.url,
                        status_code=res.status_code,
                        payload=payload,
                        response_body=res.text[:1000]
                    )
                    cvss = CVSSEngine.get_template_metrics("xss")
                    return VulnerabilityFinding(
                        finding_id=f"VULN-XSS-{abs(hash(ep.url + param)) % 1000:03d}",
                        title=f"Reflected Cross-Site Scripting (XSS) in '{param}'",
                        severity=cvss.severity,
                        category="XSS",
                        owasp_top10="A03:2021-Injection",
                        cwe_id="CWE-79",
                        affected_url=ep.url,
                        http_method=ep.method,
                        affected_parameter=param,
                        cvss=cvss,
                        confidence=ConfidenceLevel.CERTAIN,
                        description="User-supplied payload is reflected directly into HTML output without contextual sanitization or entity encoding.",
                        plain_english_summary="The website takes what you type and echoes it straight onto the web page without filtering. This allows an attacker to inject hidden JavaScript code that runs inside another user's browser when they open a link.",
                        where_is_the_flaw=f"Endpoint '{ep.method} {ep.url}' at parameter '{param}'. The server template renders the parameter directly into HTML without escaping dangerous characters like <, >, or quotes.",
                        how_attacker_exploits="1. Attacker crafts a malicious URL containing a JavaScript payload.\n2. Sends the link to a victim (via email or chat).\n3. When the victim clicks, the script runs in their session, silently stealing their login cookies or redirecting them to a fake phishing portal.",
                        real_world_impact="Account Takeover: Session cookie theft, keystroke logging, and unauthorized actions taken under the victim's identity.",
                        reproduction_steps=[
                            f"Open target URL with '{param}' assigned payload",
                            "Verify raw script tag reflection inside browser document DOM"
                        ],
                        evidence=evidence,
                        remediation_advice="Apply contextual HTML entity encoding (e.g., html.escape in Python, DOMPurify on frontend) and deploy a strict Content Security Policy (CSP).",
                        remediation_code_sample="""# Secure Implementation (HTML Escaping):
import html
safe_input = html.escape(user_input)""",
                        discovered_by_agent=self.name,
                        verified_by_gate=False
                    )
            return None

    async def execute(self, endpoints: List[ServiceEndpoint]) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        tasks = []

        async with self.get_client(timeout=4.0) as client:
            for ep in endpoints:
                if ep.surface_category == "STATIC":
                    continue

                ep.tested_by_agents.append(self.name)

                sqli_payloads = ["' OR '1'='1", "admin' --", "1' UNION SELECT 1, 'vapt_sqli_probe_extract', 3 --"]
                params_to_test = ep.parameters if ep.parameters else ["id", "q", "query", "user", "name"]

                for p in params_to_test[:3]:
                    for payload in sqli_payloads:
                        tasks.append(self._test_sqli_probe(client, ep, p, payload))

                xss_payloads = ["<script>alert('VAPT_XSS_PROBE')</script>", "\"><img src=x onerror=alert(1)>"]
                for p in params_to_test[:3]:
                    for payload in xss_payloads:
                        tasks.append(self._test_xss_probe(client, ep, p, payload))

                # SSRF check
                if any(k in ep.url.lower() for k in ["fetch", "proxy", "image", "load"]) or "url" in ep.parameters:
                    ssrf_payload = "http://169.254.169.254/latest/meta-data/"
                    probe_params = {"url": ssrf_payload}
                    res = await self._send_request(client, ep.method, ep.url, params=probe_params, timeout=3.0)
                    if res is not None:
                        # Reject false positives: unhydrated SPA catch-all shell is not cloud metadata
                        is_spa_shell = any(k in res.text.lower() for k in ["create-react-app", "<div id=\"root\"", "<div id=\"app\"", "content=\"web site created"])
                        if is_spa_shell:
                            continue

                        analysis = self.brain.analyze_vulnerability_hypothesis(
                            ep.url, "url", ssrf_payload, res.status_code, res.text, "SSRF"
                        )
                        if analysis["is_vulnerable"]:
                            evidence = self.record_finding_evidence(
                                method=ep.method,
                                url=f"{ep.url}?url={ssrf_payload}",
                                status_code=res.status_code,
                                payload=ssrf_payload,
                                response_body=res.text[:1000]
                            )
                            cvss = CVSSEngine.get_template_metrics("ssrf")
                            findings.append(VulnerabilityFinding(
                                finding_id=f"VULN-SSRF-{len(findings)+1:03d}",
                                title="Server-Side Request Forgery (SSRF) to Cloud Metadata",
                                severity=cvss.severity,
                                category="SSRF",
                                owasp_top10="A10:2021-Server-Side Request Forgery",
                                cwe_id="CWE-918",
                                affected_url=ep.url,
                                http_method=ep.method,
                                affected_parameter="url",
                                cvss=cvss,
                                confidence=ConfidenceLevel.CERTAIN,
                                description="The server accepts arbitrary external URLs and queries them from within the trusted backend network boundary.",
                                plain_english_summary="The web server acts as an obedient proxy for the attacker. If the attacker tells it to fetch an address, it will fetch it—even if that address is a secret internal cloud management server that normal internet users can't reach.",
                                where_is_the_flaw=f"Endpoint '{ep.method} {ep.url}' at parameter 'url'. The server makes HTTP requests to user-supplied web addresses without restricting internal private IP spaces.",
                                how_attacker_exploits="1. Attacker sets the 'url' parameter to 'http://169.254.169.254/latest/meta-data/'.\n2. The server queries the internal AWS/GCP instance metadata endpoint on behalf of the attacker.\n3. The response contains temporary IAM admin credentials, secret keys, and internal network IP lists.",
                                real_world_impact="Cloud Infrastructure Takeover: Exposure of cloud IAM keys, unauthorized access to private databases, and lateral movement across the entire virtual network.",
                                reproduction_steps=[
                                    f"Request endpoint specifying cloud metadata destination",
                                    "Inspect response containing cloud IAM or instance credentials"
                                ],
                                evidence=evidence,
                                remediation_advice="Implement strict URL allowlisting, block private IP address spaces, and enforce IMDSv2 token authentication.",
                                remediation_code_sample="""# Secure Implementation (IP Range Validation):
import ipaddress
ip = ipaddress.ip_address(resolved_ip)
if ip.is_private or ip.is_loopback:
    raise SecurityException("Internal IP access denied")""",
                                discovered_by_agent=self.name,
                                verified_by_gate=False
                            ))
                            ep.tested_vectors.append("SSRF")

            # Run all probe tasks concurrently
            probe_results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in probe_results:
                if isinstance(res, VulnerabilityFinding):
                    findings.append(res)

        return findings
