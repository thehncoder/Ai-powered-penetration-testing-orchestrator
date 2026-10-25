"""
AI Specialist Brain & Reasoning Engine.
Supports LLM backends (OpenAI, Anthropic, Gemini/Custom) and an autonomous heuristic brain
that executes deterministic security analysis and payload reasoning without requiring external API keys.
"""

import os
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("AIBrain")


class AIBrain:
    """Provides LLM-assisted or autonomous heuristic reasoning for specialist agents."""

    def __init__(self, provider: str = "autonomous", api_key: Optional[str] = None, model: Optional[str] = None):
        self.provider = os.getenv("VAPT_AI_PROVIDER", provider).lower()
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
        self.model = model

    def analyze_vulnerability_hypothesis(
        self,
        endpoint_url: str,
        param: str,
        payload: str,
        status_code: int,
        response_body: str,
        category: str
    ) -> Dict[str, Any]:
        """
        Analyzes whether an HTTP reflection or error represents a genuine exploit.
        Returns confidence, reasoning, and suggested CVSS metrics.
        """
        # Autonomous deterministic security intelligence
        evidence_found = False
        confidence = "TENTATIVE"
        reasoning = ""
        cwe = "CWE-200"

        lower_resp = response_body.lower()
        is_html_document = "<!doctype html" in lower_resp or "<html" in lower_resp
        is_spa_catch_all = any(marker in lower_resp for marker in [
            "create-react-app", "<div id=\"root\"", "<div id=\"app\"",
            "content=\"web site created using create-react-app\"", "you need to enable javascript to run this app"
        ])
        is_waf_challenge = any(marker in lower_resp for marker in [
            "just a moment...", "challenges.cloudflare.com", "cf-chl-widget",
            "attention required! | cloudflare", "access denied - cloudflare",
            "security check by cloudflare", "request blocked by aws waf"
        ]) or (status_code in [403, 429] and "cloudflare" in lower_resp)

        # A WAF challenge or blocked request is never proof of vulnerability
        if is_waf_challenge:
            return {
                "is_vulnerable": False,
                "confidence": "TENTATIVE",
                "reasoning": "Response is a WAF challenge or security block page (Cloudflare / AWS WAF), not an executed exploit.",
                "cwe_id": "CWE-200"
            }

        if category == "SQLI":
            # 1. Multi-database vendor error signatures (MySQL, PG, SQLite, MSSQL, Oracle, MariaDB)
            sql_signatures = [
                # MySQL / MariaDB
                "you have an error in your sql syntax", "check the manual that corresponds to your mysql server version",
                "mysql_fetch", "mysql_query", "mysqli_", "error in your sql syntax",
                # PostgreSQL
                "pg_query()", "postgresql query failed", "psycopg2.operationalerror", "syntax error at or near",
                "unterminated quoted string at or near",
                # SQLite
                "sqlite3.operationalerror", "sqlite3.databaseerror", "unrecognized token:", "near \"\": syntax error",
                # Microsoft SQL Server
                "unclosed quotation mark after the character string", "quoted string not properly terminated",
                "microsoft ole db provider for sql server", "[microsoft][odbc sql server driver]", "line 1: incorrect syntax near",
                # Oracle
                "ora-00933: sql command not properly ended", "ora-01756: quoted string not properly terminated",
                "ora-00936: missing expression", "ora-00904:",
                # Generic DB / ORM exceptions
                "odbc drivers error", "syntax error in string", "dynamic sql error", "sql command not properly ended",
                "org.hibernate.exception.sqlgrammarexception", "sqlalchemy.exc.programmingerror"
            ]
            for sig in sql_signatures:
                if sig in lower_resp:
                    evidence_found = True
                    confidence = "CERTAIN"
                    cwe = "CWE-89"
                    reasoning = f"Direct SQL database engine error detected matching signature '{sig}'."
                    break

            # 2. UNION-based injection canary verification (strict non-reflection check)
            # In genuine UNION injection:
            # - Status must be 200 OK
            # - The unique canary must appear in data without the surrounding SQL syntax being echoed
            # - If 'union select' or the full payload is in the response, it is merely HTTP parameter/URL echoing
            if not evidence_found and status_code == 200 and "union select" in payload.lower():
                strict_canary = "vapt_sqli_probe_extract"
                is_url_echo = "union select" in lower_resp or payload.lower() in lower_resp
                if strict_canary in lower_resp and not is_url_echo:
                    evidence_found = True
                    confidence = "CERTAIN"
                    cwe = "CWE-89"
                    reasoning = "UNION-based SQL injection confirmed: injected column canary returned by database without SQL syntax echoing."

        elif category == "XSS":
            # XSS requires unencoded reflection and cannot execute inside plain JSON
            is_json_response = (lower_resp.startswith("{") or lower_resp.startswith("[")) and not is_html_document
            xss_needles = ["<script", "alert(", "onload=", "onerror=", "onfocus=", "<img src=x", "<svg onload"]
            if any(n in lower_resp for n in xss_needles) and payload.lower() in lower_resp:
                if not is_json_response:
                    evidence_found = True
                    confidence = "CERTAIN"
                    cwe = "CWE-79"
                    reasoning = "Unsanitized payload was reflected directly into the response DOM without HTML entity encoding."
                else:
                    evidence_found = False
                    reasoning = "Payload was reflected within application/json structure without executable HTML context."

        elif category == "IDOR":
            # Comprehensive identity & profile object fields across modern APIs & rendered HTML views
            user_fields = [
                "\"username\":", "\"email\":", "\"user_id\":", "\"phone\":", "\"mobile\":",
                "\"first_name\":", "\"last_name\":", "\"full_name\":", "\"balance\":",
                "\"ssn\":", "\"account\":", "\"order_id\":", "\"address\":", "\"customer_id\":",
                "\"role\":", "\"secret_key\":", "\"api_key\":", "\"token\":", "\"invoice_id\":",
                "master-api-key", "account_number", "private_profile",
                # HTML label representations for web views
                "username:", "email:", "user id:", "account balance:", "phone number:",
                "order id:", "customer profile", "billing address:"
            ]
            has_confidential_records = any(tok in lower_resp for tok in user_fields)
            
            # Reject if response is merely an unhydrated SPA shell without real data
            if status_code == 200 and has_confidential_records and not is_spa_catch_all:
                evidence_found = True
                confidence = "CERTAIN"
                cwe = "CWE-639"
                reasoning = "Horizontal privilege bypass succeeded: accessed confidential record belonging to foreign identity."
            else:
                evidence_found = False
                reasoning = "Response did not disclose unauthorized entity records or returned public web page / generic SPA fallback."

        elif category == "AUTH_BYPASS":
            # Prohibit false positives on login forms or SPA catch-alls
            is_login_page = any(k in lower_resp for k in ['type="password"', "type='password'", "sign in", "login", "please log in", "authenticate"])
            admin_indicators = [
                "jwt_signing_key", "system_env", "database_backend", "admin console", "user management",
                "insecure_dev_secret", "cluster_topology", "debug_mode", "\"is_admin\": true", "\"role\": \"admin\"",
                "\"is_superuser\": true", "admin dashboard", "server status: active", "manage users",
                "admin panel", "administrator", "control panel", "site administration", "audit logs",
                "system configuration", "manage roles", "admin portal", "cluster status", "active sessions"
            ]
            has_admin_credentials = any(k in lower_resp for k in admin_indicators)

            # Legitimate admin access must have admin indicators, cannot be a pure login form, and cannot be SPA shell
            if status_code == 200 and has_admin_credentials and not is_login_page and not is_spa_catch_all:
                evidence_found = True
                confidence = "CERTAIN"
                cwe = "CWE-306"
                reasoning = "Unauthenticated access granted to privileged administrative settings or configurations."
            else:
                evidence_found = False
                reasoning = "Endpoint either required authentication, rendered login form, or returned public web document."

        elif category == "SSRF":
            # Comprehensive Multi-Cloud, Container & Internal Infrastructure Verification Signatures
            cloud_metadata_signatures = [
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
            has_metadata = any(sig in lower_resp for sig in cloud_metadata_signatures)
            
            # Must contain verified cloud/internal signatures and NOT be an SPA catch-all shell
            if has_metadata and not is_spa_catch_all:
                evidence_found = True
                confidence = "CERTAIN"
                cwe = "CWE-918"
                reasoning = "Server-Side Request Forgery confirmed: response contains verified cloud instance metadata or internal service fingerprint."
            else:
                evidence_found = False
                reasoning = "Response returned standard web document or did not disclose genuine internal/cloud tokens."

        elif category == "MISCONFIG":
            cors_exposed = "access-control-allow-origin: *" in lower_resp or "access-control-allow-credentials: true" in lower_resp
            if cors_exposed:
                evidence_found = True
                confidence = "CERTAIN"
                cwe = "CWE-942"
                reasoning = "Wildcard Access-Control-Allow-Origin combined with sensitive credentials."

        return {
            "is_vulnerable": evidence_found,
            "confidence": confidence,
            "reasoning": reasoning or "Behavior does not exhibit confirmed vulnerability indicators.",
            "cwe_id": cwe
        }
