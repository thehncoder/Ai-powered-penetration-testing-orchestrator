"""
Quality Gate Engine for AI VAPT Orchestrator.
Performs autonomous coverage audits, catches under-tested attack surfaces,
and rigorously verifies that all vulnerability findings have genuine cryptographic evidence.
"""

from typing import List, Dict, Set, Tuple
from core.schemas import (
    ReconData,
    ServiceEndpoint,
    VulnerabilityFinding,
    QualityGateResult,
    QualityGateStatus,
    ConfidenceLevel
)
from core.evidence_vault import EvidenceVault


class QualityGateEngine:
    """Enforces coverage thresholds and eliminates LLM hallucinations before report synthesis."""

    def __init__(self, min_coverage_threshold: float = 85.0):
        self.min_coverage_threshold = min_coverage_threshold

    def evaluate_recon_gate(self, recon: ReconData) -> QualityGateResult:
        """Quality gate for Wave 1 (Reconnaissance)."""
        rejection_reasons = {}
        notes = []

        total_surfaces = len(recon.endpoints) + len(recon.open_ports)
        if total_surfaces == 0:
            notes.append("Critical: No ports or endpoints discovered. Target might be down or heavily firewalled.")
            return QualityGateResult(
                wave_name="Wave 1: Surface Reconnaissance",
                status=QualityGateStatus.FAILED,
                coverage_score=0.0,
                total_attack_surfaces=0,
                attack_surfaces_tested=0,
                under_tested_surfaces=[],
                findings_submitted=0,
                findings_verified=0,
                findings_rejected=0,
                rejection_reasons={"no_surfaces_found": 1},
                quality_notes=notes
            )

        notes.append(f"Discovered {len(recon.open_ports)} services and {len(recon.endpoints)} endpoints.")
        if recon.technologies:
            notes.append(f"Identified stack technologies: {', '.join(recon.technologies.keys())}")
        if recon.waf_detected:
            notes.append(f"WAF detected: {recon.waf_detected}. Rate-limiting throttles advised.")

        return QualityGateResult(
            wave_name="Wave 1: Surface Reconnaissance",
            status=QualityGateStatus.PASSED,
            coverage_score=100.0,
            total_attack_surfaces=total_surfaces,
            attack_surfaces_tested=total_surfaces,
            under_tested_surfaces=[],
            findings_submitted=0,
            findings_verified=0,
            findings_rejected=0,
            rejection_reasons={},
            quality_notes=notes
        )

    def evaluate_testing_gate(
        self,
        endpoints: List[ServiceEndpoint],
        findings: List[VulnerabilityFinding],
        vault: EvidenceVault
    ) -> Tuple[QualityGateResult, List[VulnerabilityFinding], List[ServiceEndpoint]]:
        """
        Quality gate for Wave 3/4 (Specialist Execution & Coverage Audit).
        Returns:
          - QualityGateResult
          - Verified list of findings (hallucinations/unproven rejected)
          - List of under-tested endpoints requiring re-dispatch
        """
        total_endpoints = len(endpoints)
        tested_endpoints = [ep for ep in endpoints if len(ep.tested_by_agents) > 0]
        untested_endpoints = [ep for ep in endpoints if len(ep.tested_by_agents) == 0]

        coverage_rate = (len(tested_endpoints) / total_endpoints * 100.0) if total_endpoints > 0 else 100.0

        under_tested_surfaces = [
            f"{ep.method} {ep.url} (Category: {ep.surface_category})"
            for ep in untested_endpoints
        ]

        # Prioritize high-risk under-tested surfaces (auth, admin, data mutation)
        high_risk_misses = [
            ep for ep in untested_endpoints
            if ep.surface_category in ["AUTH", "ADMIN", "DATA"] or ep.method in ["POST", "PUT", "DELETE"]
        ]

        # Verify findings against Evidence Vault
        verified_findings: List[VulnerabilityFinding] = []
        rejection_reasons: Dict[str, int] = {}
        notes: List[str] = []

        seen_fingerprints: Set[str] = set()

        for finding in findings:
            # 1. Check for genuine proof artifact
            if not finding.evidence or not finding.evidence.proof_hash:
                rejection_reasons["missing_cryptographic_proof"] = rejection_reasons.get("missing_cryptographic_proof", 0) + 1
                continue

            # 2. Check hash integrity via EvidenceVault
            if not vault.verify_evidence(finding.evidence):
                rejection_reasons["tampered_or_invalid_proof_hash"] = rejection_reasons.get("tampered_or_invalid_proof_hash", 0) + 1
                continue

            # 3. Check for hollow responses (preventing hallucinated findings with 0 byte proof)
            if len(finding.evidence.response_body_sample.strip()) < 5:
                rejection_reasons["insufficient_response_evidence"] = rejection_reasons.get("insufficient_response_evidence", 0) + 1
                continue

            body_sample = finding.evidence.response_body_sample.lower()
            is_spa_catch_all = any(marker in body_sample for marker in [
                "create-react-app", "<div id=\"root\"", "<div id=\"app\"",
                "content=\"web site created using create-react-app\"", "you need to enable javascript to run this app"
            ])
            is_waf_block = any(marker in body_sample for marker in [
                "just a moment...", "challenges.cloudflare.com", "cf-chl-widget",
                "attention required! | cloudflare", "access denied - cloudflare",
                "security check by cloudflare", "request blocked by aws waf"
            ]) or (finding.evidence.response_status_code in [403, 429] and "cloudflare" in body_sample)

            # 4. Filter WAF Challenge & Security Block False Positives
            if is_waf_block:
                rejection_reasons["waf_challenge_block_false_positive"] = rejection_reasons.get("waf_challenge_block_false_positive", 0) + 1
                continue

            # 5. Filter SPA / Catch-all Fallback False Positives on API routes (unhydrated client-side shell)
            if is_spa_catch_all and finding.category in ["SSRF", "BROKEN_ACCESS_CONTROL", "BROKEN_AUTH", "INJECTION"]:
                rejection_reasons["spa_catch_all_fallback_false_positive"] = rejection_reasons.get("spa_catch_all_fallback_false_positive", 0) + 1
                continue

            # 6. Verify SQL Injection Evidence (must contain verified DB error or strict non-reflected canary)
            if finding.category == "INJECTION" and finding.cwe_id == "CWE-89":
                db_error_sigs = [
                    "sql syntax", "mysql_fetch", "sqlite3.operationalerror", "sqlite3.databaseerror",
                    "psycopg2.operationalerror", "syntax error at or near", "unterminated quoted string",
                    "unclosed quotation mark", "quoted string not properly terminated", "microsoft ole db provider",
                    "ora-00933", "ora-01756", "ora-00936", "sqlgrammarexception", "programmingerror"
                ]
                has_db_error = any(sig in body_sample for sig in db_error_sigs)
                has_strict_canary = "vapt_sqli_probe_extract" in body_sample and "union select" not in body_sample
                if not has_db_error and not has_strict_canary:
                    rejection_reasons["unverified_sqli_no_db_error"] = rejection_reasons.get("unverified_sqli_no_db_error", 0) + 1
                    continue

            # 5. Verify SSRF Evidence across Multi-Cloud IMDS & Internal Infrastructure daemons
            if finding.category == "SSRF":
                verified_ssrf_signatures = [
                    # AWS IMDSv1 & IMDSv2
                    "ami-id", "instance-id", "security-credentials", "iam/security-credentials",
                    "instance-type", "local-ipv4", "placement/availability-zone", "latest/meta-data", "latest/user-data",
                    # GCP Metadata
                    "computemetadata", "metadata-flavor", "project-id", "service-accounts", "instance/zone",
                    # Azure IMDS
                    "vmid", "subscriptionid", "resourcegroupname", "vmscalesetname", "ostype", "compute/vmid",
                    # DigitalOcean
                    "droplet_id", "vendor_data", "public_keys", "interfaces/public",
                    # Alibaba Cloud & OCI
                    "instance/instance-id", "oracle/opc/",
                    # Internal services (Redis, Elasticsearch, Docker, Kubernetes, Consul)
                    "+pong", "redis_version", "-err unknown command",
                    "\"cluster_name\"", "\"tagline\": \"you know, for search\"", "\"tagline\":\"you know, for search\"",
                    "apiversion\":", "\"apiversions\"", "\"kind\": \"pod\"", "serviceaccount",
                    "apache server status", "active connections",
                    # Local host system files (LFI via SSRF)
                    "root:x:0:0:", "[boot loader]", "daemon:x:"
                ]
                has_ssrf_proof = any(sig in body_sample for sig in verified_ssrf_signatures)
                if not has_ssrf_proof or is_spa_catch_all:
                    rejection_reasons["unverified_ssrf_metadata_proof"] = rejection_reasons.get("unverified_ssrf_metadata_proof", 0) + 1
                    continue

            # 6. Verify Unauthenticated Admin Bypass (must disclose active administrative controls or configs)
            if finding.category == "BROKEN_ACCESS_CONTROL" and "admin" in finding.title.lower():
                # Rejects pure login/password prompts without active administrative access
                is_pure_login_prompt = any(k in body_sample for k in ['type="password"', "type='password'", "sign in", "login", "please log in", "authenticate"])
                if is_pure_login_prompt:
                    rejection_reasons["admin_route_is_login_page"] = rejection_reasons.get("admin_route_is_login_page", 0) + 1
                    continue

                admin_verified_keywords = [
                    "jwt_signing_key", "system_env", "database_backend", "admin console", "user management",
                    "insecure_dev_secret", "cluster_topology", "debug_mode", "\"is_admin\": true", "\"role\": \"admin\"",
                    "\"is_superuser\": true", "admin dashboard", "server status: active", "manage users",
                    "admin panel", "administrator", "control panel", "site administration", "audit logs",
                    "system configuration", "manage roles", "admin portal", "cluster status", "active sessions"
                ]
                has_admin_proof = any(k in body_sample for k in admin_verified_keywords)
                if is_spa_catch_all or not has_admin_proof:
                    rejection_reasons["generic_html_not_admin_bypass"] = rejection_reasons.get("generic_html_not_admin_bypass", 0) + 1
                    continue

            # 7. Deduplicate across agents by url + parameter + cwe
            dedup_key = f"{finding.affected_url}::{finding.affected_parameter}::{finding.cwe_id}"
            if dedup_key in seen_fingerprints:
                rejection_reasons["duplicate_finding_across_agents"] = rejection_reasons.get("duplicate_finding_across_agents", 0) + 1
                continue

            seen_fingerprints.add(dedup_key)
            finding.verified_by_gate = True
            verified_findings.append(finding)

        rejected_count = len(findings) - len(verified_findings)

        # Gate status determination
        if coverage_rate < self.min_coverage_threshold or len(high_risk_misses) > 0:
            status = QualityGateStatus.WARNING if coverage_rate >= 60.0 else QualityGateStatus.FAILED
            notes.append(f"Coverage audit: {coverage_rate:.1f}% meets/misses threshold ({self.min_coverage_threshold}%).")
            if high_risk_misses:
                notes.append(f"Attention: {len(high_risk_misses)} high-risk attack surfaces remained under-tested.")
        else:
            status = QualityGateStatus.PASSED
            notes.append(f"Coverage audit passed with {coverage_rate:.1f}% attack surface test density.")

        if rejected_count > 0:
            notes.append(f"Rejected {rejected_count} finding(s) due to lack of reproducible cryptographic evidence.")

        notes.append(f"Verified {len(verified_findings)} evidence-backed findings across all specialist agents.")

        gate_result = QualityGateResult(
            wave_name="Wave 4: Coverage Verification & Quality Gate",
            status=status,
            coverage_score=round(coverage_rate, 1),
            total_attack_surfaces=total_endpoints,
            attack_surfaces_tested=len(tested_endpoints),
            under_tested_surfaces=under_tested_surfaces,
            findings_submitted=len(findings),
            findings_verified=len(verified_findings),
            findings_rejected=rejected_count,
            rejection_reasons=rejection_reasons,
            quality_notes=notes
        )

        return gate_result, verified_findings, untested_endpoints
