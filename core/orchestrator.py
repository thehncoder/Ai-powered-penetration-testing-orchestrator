"""
Gated Wave Pipeline Orchestrator for Multi-Agent AI Penetration Testing.
Coordinates parallel specialist agents, enforces quality gates, manages re-dispatching
for under-tested attack surfaces, and synthesizes final CVSS-scored deliverables.
"""

import asyncio
import time
from typing import Callable, List, Optional, Dict, Any
from core.schemas import (
    TargetScope,
    ReconData,
    ServiceEndpoint,
    VulnerabilityFinding,
    QualityGateResult,
    AssessmentReport,
    QualityGateStatus
)
from core.evidence_vault import EvidenceVault
from core.llm_brain import AIBrain
from core.quality_gate import QualityGateEngine
from core.threat_model import ThreatModelingEngine
from agents.recon_agent import ReconAgent
from agents.surface_mapper_agent import SurfaceMapperAgent
from agents.web_vuln_agent import WebVulnAgent
from agents.auth_sec_agent import AuthSecAgent
from agents.network_infra_agent import NetworkInfraAgent
from agents.ai_sec_agent import AISecurityAgent
from agents.reporter_agent import ReporterAgent


class VAPTOrchestrator:
    """Master orchestrator executing the 5-Wave autonomous penetration testing pipeline."""

    def __init__(
        self,
        scope: TargetScope,
        event_callback: Optional[Callable[[str, str, Dict[str, Any]], None]] = None,
        transport: Optional[Any] = None
    ):
        self.scope = scope
        self.event_callback = event_callback or (lambda wave, msg, data: None)
        self.transport = transport
        self.vault = EvidenceVault()
        self.brain = AIBrain()
        self.quality_gate_engine = QualityGateEngine(min_coverage_threshold=80.0)
        self.threat_modeling_engine = ThreatModelingEngine()

        # Pipeline state
        self.recon_data: Optional[ReconData] = None
        self.mapped_endpoints: List[ServiceEndpoint] = []
        self.threat_model = None
        self.raw_findings: List[VulnerabilityFinding] = []
        self.verified_findings: List[VulnerabilityFinding] = []
        self.quality_gates: List[QualityGateResult] = []
        self.final_report: Optional[AssessmentReport] = None

    def _emit(self, wave: str, message: str, data: Optional[Dict[str, Any]] = None):
        """Emits real-time telemetry to CLI or UI listeners."""
        self.event_callback(wave, message, data or {})

    async def run(self) -> AssessmentReport:
        start_time = time.time()
        self._emit("SYSTEM", f"Initializing Autonomous VAPT Pipeline for {self.scope.target_url}", {
            "target": self.scope.target_url,
            "safe_mode": self.scope.safe_mode
        })

        # =========================================================================
        # WAVE 1: SURFACE RECONNAISSANCE & DISCOVERY
        # =========================================================================
        self._emit("PROGRESS", "Phase 1/5 (20%) | Est. Total Duration: ~15-45s (Target Discovery)", {"phase": 1, "pct": 20})
        self._emit("WAVE 1", "Starting host, port, and technology reconnaissance...", {})
        recon_agent = ReconAgent(self.scope, self.vault, self.brain, transport=self.transport)
        self.recon_data = await recon_agent.execute()

        # Gate 1 Evaluation
        gate1 = self.quality_gate_engine.evaluate_recon_gate(self.recon_data)
        self.quality_gates.append(gate1)
        self._emit("GATE 1", f"Recon Gate: {gate1.status.value}", {
            "open_ports": len(self.recon_data.open_ports),
            "seed_endpoints": len(self.recon_data.endpoints)
        })

        if gate1.status == QualityGateStatus.FAILED:
            self._emit("ERROR", "Reconnaissance failed quality gate. Terminating run.", {})
            raise RuntimeError("Pipeline halted at Wave 1 Quality Gate: Target unreachable or blocked.")

        # =========================================================================
        # WAVE 2: ATTACK SURFACE & ROUTE MAPPING
        # =========================================================================
        self._emit("WAVE 2", "Mapping attack surfaces, parameter mining, and API endpoints...", {})
        surface_agent = SurfaceMapperAgent(self.scope, self.vault, self.brain, transport=self.transport)
        self.mapped_endpoints = await surface_agent.execute(self.recon_data.endpoints)
        est_sec = 1 if self.transport else max(5, int(len(self.mapped_endpoints) * 1.5 / max(1, self.scope.concurrency_limit)))
        self._emit("PROGRESS", f"Phase 2/5 (40%) | Mapped {len(self.mapped_endpoints)} surfaces | Est. Remaining: ~{est_sec}s", {"phase": 2, "pct": 40, "eta_sec": est_sec})
        self._emit("WAVE 2", f"Attack surface mapped: {len(self.mapped_endpoints)} unique endpoints identified", {
            "total_surfaces": len(self.mapped_endpoints),
            "categories": {
                "AUTH": sum(1 for e in self.mapped_endpoints if e.surface_category == "AUTH"),
                "ADMIN": sum(1 for e in self.mapped_endpoints if e.surface_category == "ADMIN"),
                "DATA": sum(1 for e in self.mapped_endpoints if e.surface_category == "DATA"),
                "API": sum(1 for e in self.mapped_endpoints if e.surface_category == "API"),
                "GENERAL": sum(1 for e in self.mapped_endpoints if e.surface_category == "GENERAL")
            }
        })

        # STRIDE Threat Modeling Analysis
        self._emit("THREAT MODEL", "Executing STRIDE architectural threat modeling...", {})
        self.threat_model = self.threat_modeling_engine.generate_threat_model(self.recon_data, self.mapped_endpoints)
        self._emit("THREAT MODEL", f"STRIDE model completed: {self.threat_model.total_threats} threats identified across attack surfaces", {
            "total_threats": self.threat_model.total_threats,
            "threats_by_category": self.threat_model.threats_by_category
        })

        # =========================================================================
        # WAVE 3: PARALLEL SPECIALIST AGENTS EXECUTION
        # =========================================================================
        rem_sec = 1 if self.transport else max(3, int(est_sec * 0.6))
        self._emit("PROGRESS", f"Phase 3/5 (65%) | Probing attack vectors in parallel | Est. Remaining: ~{rem_sec}s", {"phase": 3, "pct": 65, "eta_sec": rem_sec})
        self._emit("WAVE 3", "Deploying specialist agents concurrently across attack surface...", {})
        web_agent = WebVulnAgent(self.scope, self.vault, self.brain, transport=self.transport)
        auth_agent = AuthSecAgent(self.scope, self.vault, self.brain, transport=self.transport)
        net_agent = NetworkInfraAgent(self.scope, self.vault, self.brain, transport=self.transport)
        ai_agent = AISecurityAgent(self.scope, self.vault, self.brain, transport=self.transport)

        # Concurrently execute specialist agents
        agent_tasks = [
            web_agent.execute(self.mapped_endpoints),
            auth_agent.execute(self.mapped_endpoints),
            net_agent.execute(self.mapped_endpoints),
            ai_agent.execute(self.mapped_endpoints)
        ]

        results = await asyncio.gather(*agent_tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, list):
                self.raw_findings.extend(res)
            elif isinstance(res, Exception):
                self._emit("WARN", f"Agent encountered execution exception: {str(res)}", {})

        self._emit("WAVE 3", f"Specialist testing complete. {len(self.raw_findings)} raw findings harvested.", {
            "raw_findings_count": len(self.raw_findings)
        })

        # =========================================================================
        # WAVE 4: COVERAGE VERIFICATION & QUALITY GATE (WITH SELF-CORRECTION)
        # =========================================================================
        self._emit("PROGRESS", "Phase 4/5 (85%) | Quality gate coverage & evidence audit | Est. Remaining: ~2s", {"phase": 4, "pct": 85})
        self._emit("WAVE 4", "Auditing attack surface coverage and validating cryptographic evidence...", {})
        gate4, verified, under_tested = self.quality_gate_engine.evaluate_testing_gate(
            self.mapped_endpoints, self.raw_findings, self.vault
        )

        # Self-correction check: If critical under-tested surfaces exist, trigger targeted re-dispatch
        if under_tested:
            self._emit("WAVE 4", f"Quality gate flagged {len(under_tested)} under-tested surfaces. Initiating targeted re-dispatch pass...", {
                "under_tested": [ep.url for ep in under_tested]
            })
            targeted_pass = await web_agent.execute(under_tested)
            self.raw_findings.extend(targeted_pass)

            # Re-evaluate Wave 4 gate after targeted pass
            gate4, verified, under_tested = self.quality_gate_engine.evaluate_testing_gate(
                self.mapped_endpoints, self.raw_findings, self.vault
            )

        self.verified_findings = verified
        self.quality_gates.append(gate4)
        self._emit("GATE 4", f"Testing Quality Gate: {gate4.status.value}", {
            "coverage_score": gate4.coverage_score,
            "verified_findings": len(self.verified_findings),
            "rejected_findings": gate4.findings_rejected
        })

        # =========================================================================
        # WAVE 5: CVSS SCORING & EXECUTIVE REPORT GENERATION
        # =========================================================================
        self._emit("WAVE 5", "Generating CVSS v3.1 scores, remediation roadmap, and multi-format reports...", {})
        reporter = ReporterAgent(output_dir="reports")
        self.final_report = reporter.generate_report(
            scope=self.scope,
            recon=self.recon_data,
            quality_gates=self.quality_gates,
            findings=self.verified_findings,
            threat_model=self.threat_model
        )

        elapsed = round(time.time() - start_time, 2)
        self._emit("SUCCESS", f"VAPT Pipeline Complete in {elapsed}s. Report generated: {self.final_report.report_id}", {
            "report_id": self.final_report.report_id,
            "total_findings": len(self.verified_findings),
            "critical": self.final_report.summary.critical_count,
            "high": self.final_report.summary.high_count,
            "medium": self.final_report.summary.medium_count
        })

        return self.final_report
