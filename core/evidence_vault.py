"""
Evidence Vault for Multi-Agent Penetration Testing.
Cryptographically records, hashes, and validates raw HTTP wire artifacts to ensure evidence integrity and reproducibility.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional
from core.schemas import EvidenceArtifact


class EvidenceVault:
    """Secure, tamper-resistant store for attack payloads and HTTP responses."""

    def __init__(self):
        self._vault: Dict[str, EvidenceArtifact] = {}

    def record_evidence(
        self,
        request_method: str,
        request_url: str,
        response_status_code: int,
        payload_applied: str,
        response_body: str,
        request_headers: Optional[Dict[str, str]] = None,
        response_headers: Optional[Dict[str, str]] = None,
        request_body: Optional[str] = None
    ) -> EvidenceArtifact:
        """Records an HTTP attack proof, hashes it, and builds a reproducible curl command."""
        request_headers = request_headers or {}
        response_headers = response_headers or {}

        # Truncate response sample to 1024 characters for clean evidence artifact
        sample = response_body.strip()[:1024]
        proof_hash = EvidenceArtifact.generate_proof_hash(request_url, payload_applied, sample)
        evidence_id = f"EVD-{proof_hash[:10].upper()}"

        # Construct deterministic curl reproduction command
        curl_parts = [f"curl -s -i -X {request_method.upper()} '{request_url}'"]
        for k, v in request_headers.items():
            if k.lower() not in ["content-length", "host"]:
                curl_parts.append(f"-H '{k}: {v}'")
        if request_body:
            # Escape single quotes in body
            safe_body = request_body.replace("'", "'\\''")
            curl_parts.append(f"--data '{safe_body}'")

        curl_cmd = " \\\n  ".join(curl_parts)

        artifact = EvidenceArtifact(
            evidence_id=evidence_id,
            timestamp=datetime.now(timezone.utc),
            request_method=request_method.upper(),
            request_url=request_url,
            request_headers=request_headers,
            request_body=request_body,
            response_status_code=response_status_code,
            response_headers=response_headers,
            response_body_sample=sample,
            payload_applied=payload_applied,
            curl_reproduction=curl_cmd,
            proof_hash=proof_hash,
        )

        self._vault[evidence_id] = artifact
        return artifact

    def get_evidence(self, evidence_id: str) -> Optional[EvidenceArtifact]:
        return self._vault.get(evidence_id)

    def verify_evidence(self, evidence: EvidenceArtifact) -> bool:
        """Validates that evidence has not been tampered with and contains genuine proof."""
        expected_hash = EvidenceArtifact.generate_proof_hash(
            evidence.request_url,
            evidence.payload_applied,
            evidence.response_body_sample
        )
        return expected_hash == evidence.proof_hash

    def list_all(self) -> List[EvidenceArtifact]:
        return list(self._vault.values())
