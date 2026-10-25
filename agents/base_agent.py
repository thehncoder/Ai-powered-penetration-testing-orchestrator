"""
Base Specialist Agent for AI VAPT Orchestrator.
Provides async HTTP interaction, evidence harvesting, and schema validation.
"""

import asyncio
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
import httpx
from core.schemas import TargetScope, ServiceEndpoint, VulnerabilityFinding, EvidenceArtifact
from core.evidence_vault import EvidenceVault
from core.llm_brain import AIBrain


class BaseAgent(ABC):
    """Abstract class for specialist AI penetration testing agents."""

    def __init__(
        self,
        name: str,
        scope: TargetScope,
        vault: EvidenceVault,
        brain: AIBrain,
        transport: Optional[httpx.AsyncBaseTransport] = None
    ):
        self.name = name
        self.scope = scope
        self.vault = vault
        self.brain = brain
        self.transport = transport
        self.findings: List[VulnerabilityFinding] = []

    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    def get_client(self, timeout: float = 8.0) -> httpx.AsyncClient:
        """Returns an AsyncClient using the custom transport if provided."""
        if self.transport:
            return httpx.AsyncClient(transport=self.transport, headers=self.DEFAULT_HEADERS, verify=False, timeout=timeout)
        return httpx.AsyncClient(headers=self.DEFAULT_HEADERS, verify=False, timeout=timeout, follow_redirects=True)

    async def _send_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json_body: Optional[Any] = None,
        timeout: float = 10.0
    ) -> Optional[httpx.Response]:
        """Safely executes HTTP request with timeout and error handling."""
        req_headers = dict(self.scope.custom_headers)
        if headers:
            req_headers.update(headers)

        try:
            resp = await client.request(
                method=method.upper(),
                url=url,
                params=params,
                headers=req_headers,
                data=data,
                json=json_body,
                timeout=timeout,
                follow_redirects=True
            )
            return resp
        except (httpx.RequestError, httpx.TimeoutException):
            return None

    def record_finding_evidence(
        self,
        method: str,
        url: str,
        status_code: int,
        payload: str,
        response_body: str,
        headers: Optional[Dict[str, str]] = None,
        request_body: Optional[str] = None
    ) -> EvidenceArtifact:
        """Helper to register genuine vulnerability proof into the immutable Evidence Vault."""
        return self.vault.record_evidence(
            request_method=method,
            request_url=url,
            response_status_code=status_code,
            payload_applied=payload,
            response_body=response_body,
            request_headers=headers,
            request_body=request_body
        )

    @abstractmethod
    async def execute(self, endpoints: List[ServiceEndpoint]) -> List[VulnerabilityFinding]:
        """Executes specialist testing logic against target endpoints."""
        pass
