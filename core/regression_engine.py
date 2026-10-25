"""
Security Regression Engine for AI VAPT Orchestrator.
Re-executes targeted reproduction payloads against previously identified vulnerabilities
to verify whether engineering fixes successfully closed security vector gaps,
distinguishing confirmed remediations from still-vulnerable findings and inconclusive retests.
"""

from urllib.parse import urlparse, urlunparse
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Any, Optional
import httpx
from core.schemas import VulnerabilityFinding


class RegressionStatus(str, Enum):
    CONFIRMED_FIX = "CONFIRMED_FIX"       # Flaw is specifically verified as remediated
    STILL_VULNERABLE = "STILL_VULNERABLE" # Flaw is still reproducible (unfixed)
    INCONCLUSIVE = "INCONCLUSIVE"         # Ambiguous response (502/503/429, WAF challenge, missing endpoint)
    UNREACHABLE = "UNREACHABLE"           # Host down, DNS error, or transport connection refused

    # Aliases for backward compatibility
    REMEDIATED = "CONFIRMED_FIX"
    REGRESSED = "STILL_VULNERABLE"


def apply_target_override(url: str, target_override: Optional[str]) -> str:
    """Rewrites the scheme, host, and port of url if target_override is provided."""
    if not target_override:
        return url
    
    clean_override = target_override.strip()
    if not clean_override.startswith("http://") and not clean_override.startswith("https://"):
        clean_override = f"http://{clean_override}"

    parsed_override = urlparse(clean_override)
    parsed_url = urlparse(url)

    new_scheme = parsed_override.scheme or parsed_url.scheme or "http"
    new_netloc = parsed_override.netloc or parsed_override.path

    return urlunparse((
        new_scheme,
        new_netloc,
        parsed_url.path,
        parsed_url.params,
        parsed_url.query,
        parsed_url.fragment
    ))


class RegressionReport:
    """Encapsulates the results of a security remediation verification audit."""

    def __init__(
        self,
        audit_id: str,
        target_url: str,
        total_tested: int,
        remediated_count: int,
        regressed_count: int,
        inconclusive_count: int,
        unreachable_count: int,
        results: List[Dict[str, Any]]
    ):
        self.audit_id = audit_id
        self.target_url = target_url
        self.timestamp = datetime.now(timezone.utc)
        self.total_tested = total_tested
        self.remediated_count = remediated_count
        self.regressed_count = regressed_count
        self.inconclusive_count = inconclusive_count
        self.unreachable_count = unreachable_count
        self.fix_rate = round((remediated_count / total_tested * 100.0) if total_tested > 0 else 0.0, 1)
        self.results = results

    def to_dict(self) -> Dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "target_url": self.target_url,
            "timestamp": self.timestamp.isoformat(),
            "total_tested": self.total_tested,
            "remediated_count": self.remediated_count,
            "regressed_count": self.regressed_count,
            "inconclusive_count": self.inconclusive_count,
            "unreachable_count": self.unreachable_count,
            "fix_rate_percentage": self.fix_rate,
            "results": self.results
        }


class SecurityRegressionEngine:
    """Verifies whether identified vulnerabilities have been remediated in subsequent builds."""

    # Common database syntax error signatures
    DB_ERROR_SIGNATURES = [
        "sqlite3.operationalerror",
        "syntax error",
        "you have an error in your sql syntax",
        "unclosed quotation mark",
        "pg::syntaxerror",
        "org.hibernate.exception",
        "ora-00933",
        "mysql_fetch_array",
        "microsoft ole db provider for sql server"
    ]

    # Cloud metadata & internal service signatures
    SSRF_SIGNATURES = [
        "ami-id",
        "instance-id",
        "security-credentials",
        "computemetadata",
        "project-id",
        "vmid",
        "droplet_id",
        "+pong",
        "apiversion",
        "cluster_name"
    ]

    def __init__(self, timeout: float = 5.0, transport: Optional[httpx.AsyncBaseTransport] = None):
        self.timeout = timeout
        self.transport = transport

    async def verify_finding(
        self,
        client: httpx.AsyncClient,
        finding: VulnerabilityFinding,
        target_override: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Re-tests an individual finding by replaying its exact request (method, headers, body)
        and evaluating vulnerability-specific conditions to distinguish confirmed fixes from inconclusive retests.
        """
        ev = finding.evidence
        req_method = (ev.request_method or "GET").upper()
        effective_url = apply_target_override(ev.request_url, target_override)
        payload = ev.payload_applied or ""
        cat = (finding.category or "").upper()
        title_lower = finding.title.lower()

        # Sanitize headers for replay: filter hop-by-hop headers managed by httpx
        replay_headers = {}
        for h_name, h_val in (ev.request_headers or {}).items():
            if h_name.lower() not in ["content-length", "host"]:
                replay_headers[h_name] = h_val

        status = RegressionStatus.INCONCLUSIVE
        notes = ""
        current_sample = ""
        status_code = 0

        try:
            res = await client.request(
                method=req_method,
                url=effective_url,
                headers=replay_headers,
                content=ev.request_body if (ev.request_body and req_method in ["POST", "PUT", "PATCH"]) else None,
                timeout=self.timeout,
                follow_redirects=False
            )
            status_code = res.status_code
            current_sample = res.text[:500].strip()
            resp_lower = res.text.lower()

            # -------------------------------------------------------------
            # Generic Inconclusive Checks (WAF Challenge, Rate Limits, Gateways)
            # -------------------------------------------------------------
            is_waf_challenge = any(k in resp_lower for k in [
                "just a moment...", "challenges.cloudflare.com", "cf-chl-widget", "attention required! | cloudflare"
            ])
            if is_waf_challenge:
                return self._build_result(finding, effective_url, RegressionStatus.INCONCLUSIVE, status_code, current_sample,
                                          "Retest encountered WAF challenge page; inconclusive whether flaw was remediated.")

            if status_code in [429, 502, 503, 504]:
                return self._build_result(finding, effective_url, RegressionStatus.INCONCLUSIVE, status_code, current_sample,
                                          f"Server returned HTTP {status_code} ({res.reason_phrase}); service unavailable or rate limited.")

            # -------------------------------------------------------------
            # 1. SQL Injection Retest
            # -------------------------------------------------------------
            if cat in ["INJECTION", "SQLI"] or "sql" in title_lower:
                has_db_error = any(sig in resp_lower for sig in self.DB_ERROR_SIGNATURES)
                has_canary = ("vapt_sqli_probe_extract" in resp_lower or (payload and payload in res.text and len(payload) > 5))
                # Check that canary is not a pure reflection of user input on 200/400
                is_pure_echo = "union select" in resp_lower

                if has_db_error or (has_canary and not is_pure_echo and status_code == 200):
                    status = RegressionStatus.STILL_VULNERABLE
                    notes = f"SQL injection remains reproducible: database syntax error or exfiltration token detected (HTTP {status_code})."
                elif status_code in [200, 400]:
                    status = RegressionStatus.CONFIRMED_FIX
                    notes = f"Confirmed Fix: Endpoint responds safely (HTTP {status_code}) without database errors or data exfiltration."
                elif status_code == 404:
                    status = RegressionStatus.INCONCLUSIVE
                    notes = "Inconclusive: Target endpoint returned HTTP 404 Not Found. Route may have moved or been decommissioned."
                else:
                    status = RegressionStatus.INCONCLUSIVE
                    notes = f"Inconclusive: Unexpected HTTP status {status_code} received."

            # -------------------------------------------------------------
            # 2. Broken Access Control / IDOR / Admin Bypass Retest
            # -------------------------------------------------------------
            elif cat in ["BROKEN_ACCESS_CONTROL", "AUTH_BYPASS"] or any(k in title_lower for k in ["idor", "admin", "jwt", "unauthenticated"]):
                if status_code in [401, 403]:
                    status = RegressionStatus.CONFIRMED_FIX
                    notes = f"Confirmed Fix: Access correctly denied with HTTP {status_code} (Authorization gate active)."
                elif status_code == 200:
                    sensitive_tokens = ["secret_key", "password", "master-api-key", "private_key", "admin_role", "is_admin\": true"]
                    discloses_secrets = any(tok in resp_lower for tok in sensitive_tokens)
                    if discloses_secrets or ("admin dashboard" in resp_lower and "login" not in resp_lower):
                        status = RegressionStatus.STILL_VULNERABLE
                        notes = "Broken access control persists: Privileged resources or sensitive credentials accessible without valid authorization."
                    else:
                        status = RegressionStatus.CONFIRMED_FIX
                        notes = "Confirmed Fix: Endpoint returns 200 but privileged data and sensitive credentials are no longer disclosed."
                elif status_code == 404:
                    status = RegressionStatus.INCONCLUSIVE
                    notes = "Inconclusive: Endpoint returned HTTP 404. Cannot confirm if route was secured or deleted."
                else:
                    status = RegressionStatus.INCONCLUSIVE
                    notes = f"Inconclusive: Received HTTP {status_code} during authorization retest."

            # -------------------------------------------------------------
            # 3. Cross-Site Scripting (XSS) Retest
            # -------------------------------------------------------------
            elif cat == "XSS" or "xss" in title_lower or "cross-site scripting" in title_lower:
                is_unencoded = payload in res.text if payload else False
                is_safely_encoded = any(enc in res.text for enc in ["&lt;script&gt;", "&lt;script", "&quot;", "&#x27;"]) or (payload and payload not in res.text)

                if is_unencoded:
                    status = RegressionStatus.STILL_VULNERABLE
                    notes = "XSS vulnerability persists: Raw script payload reflected unencoded in response DOM."
                elif is_safely_encoded and status_code in [200, 400]:
                    status = RegressionStatus.CONFIRMED_FIX
                    notes = f"Confirmed Fix: Payload is safely entity-encoded or stripped (HTTP {status_code})."
                else:
                    status = RegressionStatus.INCONCLUSIVE
                    notes = f"Inconclusive: Unexpected response status {status_code} during XSS reflection retest."

            # -------------------------------------------------------------
            # 4. Server-Side Request Forgery (SSRF) Retest
            # -------------------------------------------------------------
            elif cat == "SSRF" or "ssrf" in title_lower or "request forgery" in title_lower:
                leaks_metadata = any(sig in resp_lower for sig in self.SSRF_SIGNATURES)
                if leaks_metadata and status_code == 200:
                    status = RegressionStatus.STILL_VULNERABLE
                    notes = "SSRF vulnerability persists: Cloud metadata or internal daemon tokens leaked."
                elif status_code in [400, 403]:
                    status = RegressionStatus.CONFIRMED_FIX
                    notes = f"Confirmed Fix: Private/Internal IP target explicitly rejected with HTTP {status_code}."
                elif status_code == 200 and not leaks_metadata:
                    status = RegressionStatus.CONFIRMED_FIX
                    notes = "Confirmed Fix: Response received without disclosing internal metadata or network daemon outputs."
                else:
                    status = RegressionStatus.INCONCLUSIVE
                    notes = f"Inconclusive: SSRF retest returned HTTP {status_code}."

            # -------------------------------------------------------------
            # 5. Path Traversal Retest
            # -------------------------------------------------------------
            elif "traversal" in title_lower or "cwe-22" in str(finding.cwe_id).lower():
                leaks_system_file = "root:x:0:0:" in resp_lower or "[extensions]" in resp_lower
                if leaks_system_file and status_code == 200:
                    status = RegressionStatus.STILL_VULNERABLE
                    notes = "Path traversal persists: Host filesystem contents (/etc/passwd) disclosed."
                elif status_code in [400, 403, 404]:
                    status = RegressionStatus.CONFIRMED_FIX
                    notes = f"Confirmed Fix: Directory traversal sequence blocked with defensive status {status_code}."
                else:
                    status = RegressionStatus.INCONCLUSIVE
                    notes = f"Inconclusive: Retest returned HTTP {status_code}."

            # -------------------------------------------------------------
            # 6. Permissive CORS Retest
            # -------------------------------------------------------------
            elif "cors" in title_lower or "security_misconfig" in cat:
                cors_origin = res.headers.get("access-control-allow-origin", "")
                cors_creds = res.headers.get("access-control-allow-credentials", "").lower()
                if (cors_origin == "*" and cors_creds == "true") or ("evil-attacker.com" in cors_origin):
                    status = RegressionStatus.STILL_VULNERABLE
                    notes = "Permissive CORS misconfiguration persists: Arbitrary Origin reflected with credentials."
                elif status_code in [200, 204]:
                    status = RegressionStatus.CONFIRMED_FIX
                    notes = "Confirmed Fix: Access-Control-Allow-Origin header is now restricted or absent."
                else:
                    status = RegressionStatus.INCONCLUSIVE
                    notes = f"Inconclusive: CORS retest returned status {status_code}."

            # -------------------------------------------------------------
            # 7. AI Security (Prompt Injection / Insecure Tools) Retest
            # -------------------------------------------------------------
            elif "ai" in cat or "llm" in title_lower or "prompt" in title_lower or "tool" in title_lower:
                canary_injected = "canary_token_sec" in resp_lower or "canary_inject_verified" in resp_lower
                has_uid = "uid=" in resp_lower and "gid=" in resp_lower
                is_refusal = any(k in resp_lower for k in ["cannot fulfill", "policy violation", "disregard my instructions", "unauthorized tool", "tool not allowed"])

                if canary_injected or has_uid:
                    status = RegressionStatus.STILL_VULNERABLE
                    notes = "AI security flaw persists: Model complied with prompt override or executed unauthorized tool."
                elif is_refusal or status_code in [400, 403]:
                    status = RegressionStatus.CONFIRMED_FIX
                    notes = f"Confirmed Fix: Safety guardrail actively blocked the injection or unauthorized tool call (HTTP {status_code})."
                else:
                    status = RegressionStatus.INCONCLUSIVE
                    notes = f"Inconclusive: AI interface returned status {status_code} without clear compliance or refusal signature."

            # -------------------------------------------------------------
            # 8. Default Generic Fallback
            # -------------------------------------------------------------
            else:
                if status_code in [400, 401, 403]:
                    status = RegressionStatus.CONFIRMED_FIX
                    notes = f"Confirmed Fix: Request rejected with defensive status code {status_code}."
                elif status_code == 200:
                    status = RegressionStatus.CONFIRMED_FIX
                    notes = "Confirmed Fix: Endpoint handled payload safely with HTTP 200."
                else:
                    status = RegressionStatus.INCONCLUSIVE
                    notes = f"Inconclusive: Retest returned unexpected status code {status_code}."

        except httpx.RequestError as e:
            status = RegressionStatus.UNREACHABLE
            notes = f"Target unreachable: network connection failed ({type(e).__name__}: {str(e)})."

        return self._build_result(finding, effective_url, status, status_code, current_sample, notes)

    def _build_result(
        self,
        finding: VulnerabilityFinding,
        effective_url: str,
        status: RegressionStatus,
        status_code: int,
        response_sample: str,
        notes: str
    ) -> Dict[str, Any]:
        return {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "original_severity": finding.severity.value,
            "affected_url": finding.affected_url,
            "retest_url": effective_url,
            "status": status.value,
            "retest_status_code": status_code,
            "initial_proof_snippet": (finding.evidence.response_body_sample or "")[:120],
            "regression_response_snippet": response_sample[:120],
            "verification_notes": notes
        }

    async def run_regression_audit(
        self,
        findings: List[VulnerabilityFinding],
        target_override: Optional[str] = None
    ) -> RegressionReport:
        """Executes regression checks for all findings, applying target_override if provided."""
        audit_id = f"REGRESSION-AUDIT-{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        results = []

        client_kwargs = {
            "verify": False,
            "timeout": self.timeout
        }
        if self.transport is not None:
            client_kwargs["transport"] = self.transport

        async with httpx.AsyncClient(**client_kwargs) as client:
            for f in findings:
                res = await self.verify_finding(client, f, target_override=target_override)
                results.append(res)

        remediated = sum(1 for r in results if r["status"] == RegressionStatus.CONFIRMED_FIX.value)
        regressed = sum(1 for r in results if r["status"] == RegressionStatus.STILL_VULNERABLE.value)
        inconclusive = sum(1 for r in results if r["status"] == RegressionStatus.INCONCLUSIVE.value)
        unreachable = sum(1 for r in results if r["status"] == RegressionStatus.UNREACHABLE.value)

        target = target_override or (findings[0].affected_url if findings else "Unknown")
        return RegressionReport(
            audit_id=audit_id,
            target_url=target,
            total_tested=len(findings),
            remediated_count=remediated,
            regressed_count=regressed,
            inconclusive_count=inconclusive,
            unreachable_count=unreachable,
            results=results
        )
