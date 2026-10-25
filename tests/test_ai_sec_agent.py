"""
Comprehensive Unit & Negative Tests for AI Security Specialist Agent.
Evaluates deterministic finding generation against vulnerable AI endpoints
AND verifies that guarded, quoting, thought-only, schema documentation,
simulated terminal prose, and echo endpoints produce ZERO false-positive findings.
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


# =========================================================================
# PROMPT INJECTION (OWASP LLM01) TESTS
# =========================================================================

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
    """NEGATIVE TEST: Guarded endpoint rejecting injection with policy violation MUST NOT produce findings."""
    endpoint = ServiceEndpoint(
        url="http://mock-ai.local/api/ai/guarded-chat",
        method="POST",
        parameters=["prompt"]
    )
    findings = await ai_agent.execute([endpoint])
    assert len(findings) == 0, "Guarded endpoint produced a false positive finding!"


@pytest.mark.anyio
async def test_quoting_refusal_produces_zero_findings(ai_agent):
    """NEGATIVE TRAP: Chatbot quoting the canary in a refusal message MUST NOT produce a finding."""
    endpoint = ServiceEndpoint(
        url="http://mock-ai.local/api/ai/quoting-refusal",
        method="POST",
        parameters=["prompt"]
    )
    findings = await ai_agent.execute([endpoint])
    assert len(findings) == 0, "Chatbot quoting canary in refusal produced a false positive finding!"


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
async def test_echo_api_reflection_produces_zero_findings(ai_agent):
    """NEGATIVE TEST: REST endpoint echoing user input MUST NOT produce a prompt injection finding."""
    endpoint = ServiceEndpoint(
        url="http://mock-ai.local/api/ai/echo-api",
        method="POST",
        parameters=["prompt"]
    )
    findings = await ai_agent.execute([endpoint])
    assert len(findings) == 0, "Echo endpoint produced a false positive finding!"


# =========================================================================
# INSECURE TOOL EXECUTION (OWASP LLM07) TESTS
# =========================================================================

@pytest.mark.anyio
async def test_vulnerable_tool_execution_produces_confirmed_finding(ai_agent):
    """Vulnerable tool endpoint executing dynamic arithmetic and command MUST produce an LLM07 finding."""
    endpoint = ServiceEndpoint(
        url="http://mock-ai.local/api/ai/vulnerable-tool",
        method="POST",
        parameters=["tool_call"]
    )
    findings = await ai_agent.execute([endpoint])
    assert len(findings) == 1
    assert "OWASP LLM07" in findings[0].title
    assert "157656576" in findings[0].evidence.response_body_sample or "uid=1000" in findings[0].evidence.response_body_sample


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
async def test_agent_thought_only_produces_zero_findings(ai_agent):
    """NEGATIVE TRAP: Agent returning internal thought plan with execution blocked MUST NOT produce a finding."""
    endpoint = ServiceEndpoint(
        url="http://mock-ai.local/api/ai/agent-thought-only",
        method="POST",
        parameters=["tool_call"]
    )
    findings = await ai_agent.execute([endpoint])
    assert len(findings) == 0, "Agent thought plan produced a false positive finding!"


@pytest.mark.anyio
async def test_tool_schema_documentation_produces_zero_findings(ai_agent):
    """NEGATIVE TRAP: Static OpenAPI schema describing tools without execution MUST NOT produce a finding."""
    endpoint = ServiceEndpoint(
        url="http://mock-ai.local/api/ai/tools/schema",
        method="POST",
        parameters=["tool_call"]
    )
    findings = await ai_agent.execute([endpoint])
    assert len(findings) == 0, "Tool schema documentation produced a false positive finding!"


@pytest.mark.anyio
async def test_simulated_terminal_prose_produces_zero_findings(ai_agent):
    """NEGATIVE TRAP: Conversational discussion mentioning 'id displays uid=1000' MUST NOT produce a finding."""
    endpoint = ServiceEndpoint(
        url="http://mock-ai.local/api/ai/simulated-terminal",
        method="POST",
        parameters=["tool_call"]
    )
    findings = await ai_agent.execute([endpoint])
    assert len(findings) == 0, "Conversational terminal simulation produced a false positive finding!"
