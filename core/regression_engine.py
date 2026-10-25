"""
Security Regression Engine for AI VAPT Orchestrator.
Re-executes targeted reproduction payloads against previously identified vulnerabilities
to verify whether engineering fixes successfully closed security vector gaps.
"""

import json
from pathlib import Path
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Any, Optional
import httpx
from core.schemas import VulnerabilityFinding, AssessmentReport


class RegressionStatus(str, Enum):
    REMEDIATED = "REMEDIATED"       # Flaw is completely fixed
    REGRESSED = "REGRESSED"         # Flaw is STILL reproducible (unfixed)
    PARTIALLY_FIXED = "PARTIAL"     # Behavior changed, but still anomalous
    UNREACHABLE = "UNREACHABLE"     # Endpoint no longer exists / down


class FindingRegressionResult(BaseModel := type('BaseModel', (), {})):
    finding_id: str
    title: str
    original_severity: str
    endpoint: str
    status: RegressionStatus
    initial_proof_snippet: str
    regression_proof_snippet: str
    verification_notes: str


class RegressionReport:
    """Encapsulates the results of a security remediation verification audit."""

    def __init__(
        self,
        audit_id: str,
        target_url: str,
        total_tested: int,
        remediated_count: int,
        regressed_count: int,
        results: List[Dict[str, Any]]
    ):
        self.audit_id = audit_id
        self.target_url = target_url
        self.timestamp = datetime.now(timezone.utc)
        self.total_tested = total_tested
        self.remediated_count = remediated_count
        self.regressed_count = regressed_count
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
            "fix_rate_percentage": self.fix_rate,
            "results": self.results
        }


class SecurityRegressionEngine:
    """Verifies whether identified vulnerabilities have been remediated in subsequent builds."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def verify_finding(self, client: httpx.AsyncClient, finding: VulnerabilityFinding) -> Dict[str, Any]:
        """Re-tests an individual finding using its recorded payload and method."""
        ev = finding.evidence
        req_method = ev.request_method.upper()
        req_url = ev.request_url
        payload = ev.payload_applied
        cat = finding.category

        status = RegressionStatus.REGRESSED
        notes = ""
        current_sample = ""

        try:
            res = await client.request(
                method=req_method,
                url=req_url,
                timeout=self.timeout,
                follow_redirects=False
            )
            current_sample = res.text[:500].strip()

            # Analyze based on category
            if cat == "INJECTION" or "SQL" in finding.title:
                if res.status_code != 500 and "error" not in res.text.lower() and "syntax" not in res.text.lower():
                    status = RegressionStatus.REMEDIATED
                    notes = "SQL syntax errors and unconditional record disclosures are no longer reflected."
                else:
                    status = RegressionStatus.REGRESSED
                    notes = "SQL syntax or runtime database exception remains reproducible."

            elif cat == "BROKEN_ACCESS_CONTROL" or "IDOR" in finding.title or "Admin" in finding.title:
                if res.status_code in [401, 403]:
                    status = RegressionStatus.REMEDIATED
                    notes = f"Access denied with HTTP {res.status_code}. Server-side authorization check now active."
                elif res.status_code == 200 and ("secret_key" not in res.text and "password" not in res.text and "MASTER-API-KEY" not in res.text):
                    status = RegressionStatus.REMEDIATED
                    notes = "Endpoint returns 200 but sensitive credentials and unauthorized records are no longer disclosed."
                else:
                    status = RegressionStatus.REGRESSED
                    notes = "Sensitive resource or administrative panel remains accessible without credentials."

            elif cat == "XSS":
                if payload not in res.text or ("&lt;script&gt;" in res.text or "&quot;" in res.text):
                    status = RegressionStatus.REMEDIATED
                    notes = "Payload is either absent or safely HTML-entity encoded."
                else:
                    status = RegressionStatus.REGRESSED
                    notes = "Raw script tags continue to reflect unencoded in response DOM."

            elif cat == "SECURITY_MISCONFIG":
                if "Access-Control-Allow-Origin: *" not in res.headers.get("access-control-allow-origin", ""):
                    status = RegressionStatus.REMEDIATED
                    notes = "Permissive CORS reflection has been removed."
                else:
                    status = RegressionStatus.REGRESSED
                    notes = "Permissive CORS configuration remains present."

            else:
                if res.status_code in [400, 401, 403, 404]:
                    status = RegressionStatus.REMEDIATED
                    notes = f"Request now rejected with defensive status code {res.status_code}."
                else:
                    status = RegressionStatus.REGRESSED
                    notes = "Original vulnerable behavior persists."

        except httpx.RequestError as e:
            status = RegressionStatus.UNREACHABLE
            notes = f"Network connection failed: {str(e)}"

        return {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "original_severity": finding.severity.value,
            "affected_url": finding.affected_url,
            "status": status.value,
            "initial_proof_snippet": ev.response_body_sample[:120],
            "regression_response_snippet": current_sample[:120],
            "verification_notes": notes
        }

    async def run_regression_audit(
        self,
        findings: List[VulnerabilityFinding],
        target_override: Optional[str] = None
    ) -> RegressionReport:
        """Executes regression checks for all findings in a previous audit report."""
        audit_id = f"REGRESSION-AUDIT-{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        results = []

        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            for f in findings:
                res = await self.verify_finding(client, f)
                results.append(res)

        remediated = sum(1 for r in results if r["status"] == RegressionStatus.REMEDIATED.value)
        regressed = sum(1 for r in results if r["status"] == RegressionStatus.REGRESSED.value)

        target = target_override or (findings[0].affected_url if findings else "Unknown")
        return RegressionReport(
            audit_id=audit_id,
            target_url=target,
            total_tested=len(findings),
            remediated_count=remediated,
            regressed_count=regressed,
            results=results
        )
