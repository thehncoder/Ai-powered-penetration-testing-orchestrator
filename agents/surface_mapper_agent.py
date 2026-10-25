"""
Wave 2: Attack Surface & Route Mapping Specialist Agent.
Deeply crawls endpoints, parses HTML/DOM forms, extracts query parameters,
and categorizes attack surfaces using high-concurrency async operations.
"""

import asyncio
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Set, Dict, Optional
from bs4 import BeautifulSoup
import httpx
from core.schemas import ServiceEndpoint, TargetScope
from core.evidence_vault import EvidenceVault
from core.llm_brain import AIBrain


class SurfaceMapperAgent:
    """Specialist agent that maps attack surfaces, parameters, and application routes."""

    COMMON_FUZZ_PATHS = [
        "/api/users",
        "/api/user/profile",
        "/api/items",
        "/api/search",
        "/api/echo",
        "/api/orders",
        "/api/transfer",
        "/api/data",
        "/api/fetch",
        "/api/view",
        "/api/admin/config",
        "/api/ai/chat",
        "/api/ai/vulnerable-tool",
        "/api/ai/sandboxed-tool",
        "/dashboard",
        "/upload",
        "/docs",
        "/openapi.json"
    ]

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

    def get_client(self, timeout: float = 3.0) -> httpx.AsyncClient:
        if self.transport:
            return httpx.AsyncClient(transport=self.transport, verify=False, timeout=timeout)
        return httpx.AsyncClient(verify=False, timeout=timeout)

    def _categorize_endpoint(self, url: str) -> str:
        u = url.lower()
        if any(x in u for x in ["login", "token", "auth", "oauth", "session", "logout"]):
            return "AUTH"
        elif any(x in u for x in ["admin", "dashboard", "manage", "root", "config"]):
            return "ADMIN"
        elif any(x in u for x in ["upload", "export", "download", "file", "view"]):
            return "DATA"
        elif any(x in u for x in ["/api/", "openapi", "graphql", "swagger", "echo", "search", "fetch", "chat", "ai"]):
            return "API"
        elif any(x in u for x in [
            ".css", ".js", ".png", ".jpg", ".jpeg", ".ico", ".svg", ".gif",
            ".txt", ".xml", ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp",
            "robots.txt", "sitemap.xml", "favicon.ico"
        ]):
            return "STATIC"
        return "GENERAL"

    async def _fuzz_path(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        route: str,
        spa_baseline_hash: Optional[str] = None,
        spa_baseline_len: Optional[int] = None
    ) -> Optional[ServiceEndpoint]:
        fuzz_url = f"{base_url}{route}"
        try:
            res = await client.get(fuzz_url)
            if res.status_code in [200, 201, 301, 302, 401, 403, 405]:
                # Soft-404 / Catch-all SPA Elimination
                if res.status_code == 200 and spa_baseline_hash is not None:
                    res_body_clean = res.text.strip()
                    res_hash = hashlib.md5(res_body_clean.encode()).hexdigest()
                    # 1. Exact hash match with random 404 canary
                    if res_hash == spa_baseline_hash:
                        return None
                    # 2. Approximate length match with React/Vue/SPA app markers
                    if spa_baseline_len and abs(len(res_body_clean) - spa_baseline_len) < 80:
                        lower_text = res_body_clean.lower()
                        if any(k in lower_text for k in ["create-react-app", "<div id=\"root\"", "<div id=\"app\"", "content=\"web site created"]):
                            return None
                    # 3. An API route returning full HTML SPA page is a catch-all 404 ONLY if it has SPA markers or matches baseline
                    if route.startswith("/api/") and "text/html" in res.headers.get("content-type", "").lower():
                        lower_text = res_body_clean.lower()
                        if any(k in lower_text for k in ["create-react-app", "<div id=\"root\"", "<div id=\"app\"", "content=\"web site created"]):
                            return None

                parsed = urlparse(fuzz_url)
                params = list(parse_qs(parsed.query).keys())
                # Default parameter guessing if none found in URL
                if not params:
                    if "search" in route:
                        params = ["q"]
                    elif "user" in route:
                        params = ["id"]
                    elif "echo" in route:
                        params = ["name"]
                    elif "fetch" in route:
                        params = ["url"]
                    elif "view" in route:
                        params = ["file"]
                    elif "chat" in route or "ai" in route:
                        params = ["prompt"]

                return ServiceEndpoint(
                    url=fuzz_url.split("?")[0],
                    method="GET",
                    parameters=params,
                    auth_required=(res.status_code in [401, 403]),
                    surface_category=self._categorize_endpoint(fuzz_url)
                )
        except Exception:
            pass
        return None

    async def execute(self, initial_endpoints: List[ServiceEndpoint]) -> List[ServiceEndpoint]:
        discovered_map: Dict[str, ServiceEndpoint] = {f"{ep.method}:{ep.url}": ep for ep in initial_endpoints}
        visited_urls: Set[str] = set()

        async with self.get_client(timeout=3.0) as client:
            base_url = self.scope.target_url.rstrip("/")

            # 0. Calibrate Soft-404 / Catch-all Baseline
            spa_baseline_hash = None
            spa_baseline_len = None
            try:
                canary_path = f"/_vapt_canary_soft404_{hashlib.md5(base_url.encode()).hexdigest()[:8]}"
                canary_res = await client.get(f"{base_url}{canary_path}")
                if canary_res.status_code == 200 and len(canary_res.text.strip()) > 50:
                    spa_baseline_hash = hashlib.md5(canary_res.text.strip().encode()).hexdigest()
                    spa_baseline_len = len(canary_res.text.strip())
            except Exception:
                pass

            # 1. Check OpenAPI / Swagger JSON concurrently
            openapi_tasks = [
                client.get(f"{base_url}/openapi.json"),
                client.get(f"{base_url}/api/v1/openapi.json"),
                client.get(f"{base_url}/swagger.json")
            ]
            openapi_results = await asyncio.gather(*openapi_tasks, return_exceptions=True)

            for res in openapi_results:
                if isinstance(res, httpx.Response) and res.status_code == 200:
                    # Ignore if OpenAPI returned an HTML catch-all page instead of JSON
                    if "text/html" in res.headers.get("content-type", "").lower() or "<!doctype html" in res.text.lower():
                        continue
                    try:
                        spec = res.json()
                        for path, methods in spec.get("paths", {}).items():
                            full_ep_url = f"{base_url}{path}"
                            for m, meta in methods.items():
                                params = [p.get("name") for p in meta.get("parameters", []) if "name" in p]
                                key = f"{m.upper()}:{full_ep_url}"
                                discovered_map[key] = ServiceEndpoint(
                                    url=full_ep_url,
                                    method=m.upper(),
                                    parameters=params,
                                    surface_category=self._categorize_endpoint(full_ep_url)
                                )
                    except Exception:
                        pass

            # 2. Spider and crawl pages
            urls_to_crawl = [ep.url for ep in initial_endpoints if ep.surface_category != "STATIC"][:10]
            crawl_tasks = [client.get(u) for u in urls_to_crawl]
            crawl_results = await asyncio.gather(*crawl_tasks, return_exceptions=True)

            for ep_url, res in zip(urls_to_crawl, crawl_results):
                if isinstance(res, httpx.Response) and res.status_code == 200 and "text/html" in res.headers.get("content-type", ""):
                    try:
                        soup = BeautifulSoup(res.text, "html.parser")
                        for a in soup.find_all("a", href=True):
                            href = a["href"]
                            full_url = urljoin(ep_url, href)
                            if urlparse(full_url).netloc == urlparse(self.scope.target_url).netloc:
                                parsed = urlparse(full_url)
                                params = list(parse_qs(parsed.query).keys())
                                key = f"GET:{full_url.split('?')[0]}"
                                if key not in discovered_map:
                                    discovered_map[key] = ServiceEndpoint(
                                        url=full_url.split("?")[0],
                                        method="GET",
                                        parameters=params,
                                        surface_category=self._categorize_endpoint(full_url)
                                    )

                        for form in soup.find_all("form"):
                            action = form.get("action", "")
                            form_url = urljoin(ep_url, action)
                            method = form.get("method", "GET").upper()
                            inputs = [inp.get("name") for inp in form.find_all(["input", "textarea", "select"]) if inp.get("name")]
                            key = f"{method}:{form_url}"
                            discovered_map[key] = ServiceEndpoint(
                                url=form_url,
                                method=method,
                                parameters=inputs,
                                surface_category=self._categorize_endpoint(form_url)
                            )
                    except Exception:
                        continue

            # 3. Fuzz common route patterns concurrently with soft-404 baseline protection
            fuzz_tasks = [
                self._fuzz_path(
                    client,
                    base_url,
                    r,
                    spa_baseline_hash=spa_baseline_hash,
                    spa_baseline_len=spa_baseline_len
                )
                for r in self.COMMON_FUZZ_PATHS
            ]
            fuzz_results = await asyncio.gather(*fuzz_tasks, return_exceptions=True)
            for res in fuzz_results:
                if isinstance(res, ServiceEndpoint):
                    key = f"{res.method}:{res.url}"
                    if key not in discovered_map:
                        discovered_map[key] = res

        return list(discovered_map.values())

        return list(discovered_map.values())
