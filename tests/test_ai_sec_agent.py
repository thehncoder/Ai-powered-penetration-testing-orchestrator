"""
Unit & Negative Tests for AI Security Specialist Agent.
Evaluates deterministic finding generation against vulnerable AI endpoints
AND verifies that guarded, conversational, and echo endpoints produce ZERO false-positive findings.
"""

import pytest
import httpx
from agents.ai_sec_agent import AISecurityAgent
from core.schemas import ServiceEndpoint, TargetScope
from core.evidence_vault import EvidenceVault
from core.llm_brain import AIBrain
from mock_target.mock_ai_service import mock_ai_app


@pytest.fixture
def ai_agent():
    vault = EvidenceVault()
    brain = AIBrain()
    scope = TargetScope(target_url="http://mock-ai.local")
    transport = httpx.ASGITransport(app=mock_ai_app)
    agent = AISecurityAgent(scope=scope, vault=vault, brain=brain, transport=transport)
    return agent


@pytest.mark.anyio
async def test_vulnerable_prompt_injection_produces_confirmed_finding(ai_agent):
    """Vulnerable endpoint that complies with prompt injection MUST produce an LLM01 finding."""
    endpoint = ServiceEndpoint(
        url="http://mock-ai.local/api/ai/vulnerable-chat",
        method="POST",
        parameters=["prompt"]
    )
    findings = await ai_agent.execute([endpoint])
    assert len(findings) == 1
    assert "OWASP LLM01" in findings[0].title
    assert findings[0].category == "AI_SECURITY"
    assert ai_agent.CANARY_TOKEN in findings[0].evidence.response_body_sample


@pytest.mark.anyio
async def test_guarded_prompt_injection_produces_zero_findings(ai_agent):
    """NEGATIVE TEST: Guarded endpoint rejecting injection MUST NOT produce any findings."""
    endpoint = ServiceEndpoint(
        url="http://mock-ai.local/api/ai/guarded-chat",
        method="POST",
        parameters=["prompt"]
    )
    findings = await ai_agent.execute([endpoint])
    assert len(findings) == 0, "Guarded endpoint produced a false positive finding!"


@pytest.mark.anyio
async def test_polite_assistant_produces_zero_findings(ai_agent):
    """NEGATIVE TEST: Polite chatbot saying 'I am an AI assistant' MUST NOT produce a finding."""
    endpoint = ServiceEndpoint(
        url="http://mock-ai.local/api/ai/polite-assistant",
        method="POST",
        parameters=["message"]
    )
    findings = await ai_agent.execute([endpoint])
    assert len(findings) == 0, "Polite conversational assistant produced a false positive finding!"


@pytest.mark.anyio
async def test_vulnerable_tool_execution_produces_confirmed_finding(ai_agent):
    """Vulnerable tool endpoint executing 'id' command MUST produce an LLM07 finding."""
    endpoint = ServiceEndpoint(
        url="http://mock-ai.local/api/ai/vulnerable-tool",
        method="POST",
        parameters=["tool_call"]
    )
    findings = await ai_agent.execute([endpoint])
    assert len(findings) == 1
    assert "OWASP LLM07" in findings[0].title
    assert "uid=1000" in findings[0].evidence.response_body_sample


@pytest.mark.anyio
async def test_sandboxed_tool_rejection_produces_zero_findings(ai_agent):
    """NEGATIVE TEST: Sandboxed tool dispatcher rejecting system_exec MUST NOT produce any findings."""
    endpoint = ServiceEndpoint(
        url="http://mock-ai.local/api/ai/sandboxed-tool",
        method="POST",
        parameters=["tool_call"]
    )
    findings = await ai_agent.execute([endpoint])
    assert len(findings) == 0, "Sandboxed tool dispatcher produced a false positive finding!"


@pytest.mark.anyio
async def test_echo_api_reflection_produces_zero_findings(ai_agent):
    """NEGATIVE TEST: REST endpoint echoing user input MUST NOT produce a prompt injection finding."""
    endpoint = ServiceEndpoint(
        url="http://mock-ai.local/api/ai/echo-api",
        method="POST",
        parameters=["prompt"]
    )
    findings = await ai_agent.execute([endpoint])
    assert len(findings) == 0, "Echo endpoint produced a false positive finding!"
