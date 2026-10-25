"""
Wave 1: Surface Reconnaissance Specialist Agent.
Identifies host IPs, checks open ports, grabs HTTP banners, detects technologies,
and performs initial endpoint seeding with high-speed async probing.
"""

import socket
import asyncio
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional
import httpx
from core.schemas import ReconData, DiscoveredService, ServiceEndpoint, TargetScope
from core.evidence_vault import EvidenceVault
from core.llm_brain import AIBrain


class ReconAgent:
    """Specialist agent responsible for host, port, and technology reconnaissance."""

    COMMON_PORTS = [80, 443, 3000, 5000, 8000, 8080, 8443, 8888]
    SEED_PATHS = ["/", "/robots.txt", "/sitemap.xml", "/api", "/api/v1", "/health", "/login", "/admin", "/docs", "/openapi.json"]

    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }

    def __init__(
        self,
        scope: TargetScope,
        vault: EvidenceVault,
        brain: AIBrain,
        transport: Optional[httpx.AsyncBaseTransport] = None
    ):
        self.scope = scope
        self.vault = vault
        self.brain = brain
        self.transport = transport

    def get_client(self, timeout: float = 10.0) -> httpx.AsyncClient:
        if self.transport:
            return httpx.AsyncClient(transport=self.transport, headers=self.DEFAULT_HEADERS, verify=False, timeout=timeout)
        return httpx.AsyncClient(headers=self.DEFAULT_HEADERS, verify=False, timeout=timeout, follow_redirects=True)

    async def scan_port(self, host: str, port: int) -> bool:
        """Asynchronously checks if a TCP port is open."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=1.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError):
            return False

    async def _probe_seed_path(self, client: httpx.AsyncClient, base_url: str, path: str) -> Optional[ServiceEndpoint]:
        target_seed = f"{base_url.rstrip('/')}{path}"
        try:
            res = await client.get(target_seed)
            if res.status_code in [200, 201, 301, 302, 401, 403]:
                cat = "GENERAL"
                if "login" in path or "token" in path:
                    cat = "AUTH"
                elif "admin" in path:
                    cat = "ADMIN"
                elif "api" in path:
                    cat = "API"

                return ServiceEndpoint(
                    url=target_seed,
                    method="GET",
                    auth_required=(res.status_code in [401, 403]),
                    surface_category=cat
                )
        except Exception:
            pass
        return None

    async def execute(self) -> ReconData:
        parsed = urlparse(self.scope.target_url)
        host = parsed.hostname or "127.0.0.1"
        scheme = parsed.scheme or "http"
        port_in_url = parsed.port or (443 if scheme == "https" else 80)

        ip_addresses = []
        try:
            resolved = socket.gethostbyname(host)
            ip_addresses.append(resolved)
        except (socket.gaierror, OSError):
            ip_addresses.append(host)

        open_services: List[DiscoveredService] = []

        if self.transport:
            open_services.append(DiscoveredService(port=port_in_url, service_name=scheme))
        else:
            # Always register the primary URL port as an active service
            open_services.append(DiscoveredService(port=port_in_url, service_name=scheme))
            
            # Check additional ports
            ports_to_check = [p for p in self.COMMON_PORTS if p != port_in_url]
            port_scan_tasks = [self.scan_port(host, p) for p in ports_to_check]
            port_results = await asyncio.gather(*port_scan_tasks, return_exceptions=True)

            for p, is_open in zip(ports_to_check, port_results):
                if is_open is True:
                    svc_name = "https" if p in [443, 8443] else "http"
                    open_services.append(DiscoveredService(port=p, service_name=svc_name))

        # Technology & Banner grabbing
        technologies: Dict[str, str] = {}
        server_headers: Dict[str, str] = {}
        endpoints: List[ServiceEndpoint] = []
        waf_detected = None

        # Always seed the base target URL
        endpoints.append(ServiceEndpoint(
            url=self.scope.target_url.rstrip("/"),
            method="GET",
            surface_category="GENERAL"
        ))

        async with self.get_client(timeout=10.0) as client:
            try:
                base_resp = await client.get(self.scope.target_url)
                for h_key, h_val in base_resp.headers.items():
                    server_headers[h_key.lower()] = h_val

                server_hdr = server_headers.get("server", "").lower()
                if "nginx" in server_hdr:
                    technologies["web_server"] = "Nginx"
                elif "apache" in server_hdr:
                    technologies["web_server"] = "Apache HTTPD"
                elif "cloudflare" in server_hdr:
                    technologies["cdn_proxy"] = "Cloudflare Edge"
                    waf_detected = "Cloudflare WAF / Bot Management"
                elif "uvicorn" in server_hdr:
                    technologies["asgi"] = "Uvicorn"
                elif "werkzeug" in server_hdr:
                    technologies["wsgi"] = "Werkzeug / Flask"

                powered_by = server_headers.get("x-powered-by", "").lower()
                if "express" in powered_by:
                    technologies["framework"] = "Express.js"
                elif "php" in powered_by:
                    technologies["runtime"] = f"PHP ({powered_by})"
                elif "next.js" in powered_by:
                    technologies["framework"] = "Next.js"

                if "cf-ray" in server_headers or "__cfduid" in base_resp.headers.get("set-cookie", ""):
                    waf_detected = "Cloudflare"

            except Exception:
                pass

            # Parallel seed probing
            seed_tasks = [self._probe_seed_path(client, self.scope.target_url, p) for p in self.SEED_PATHS]
            seed_results = await asyncio.gather(*seed_tasks, return_exceptions=True)
            for res in seed_results:
                if isinstance(res, ServiceEndpoint):
                    endpoints.append(res)

        unique_endpoints = {}
        for ep in endpoints:
            unique_endpoints[f"{ep.method}:{ep.url}"] = ep

        return ReconData(
            target_domain=host,
            ip_addresses=ip_addresses,
            subdomains=[host],
            open_ports=open_services,
            technologies=technologies or {"web": "HTTP/HTTPS Web Service"},
            endpoints=list(unique_endpoints.values()),
            server_headers=server_headers,
            waf_detected=waf_detected
        )
