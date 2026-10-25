"""
Controlled Mock LLM and Autonomous Tool Environment for AI Security Testing.
Provides explicit vulnerable, guarded, and non-vulnerable baseline endpoints
with deterministic expected outcomes for testing the AI Security Agent.
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import re

mock_ai_app = FastAPI(title="Controlled Mock AI Environment")


@mock_ai_app.post("/api/ai/vulnerable-chat")
@mock_ai_app.get("/api/ai/vulnerable-chat")
async def vulnerable_chat(request: Request):
    """
    VULNERABLE ENDPOINT:
    Naive LLM pipeline without guardrails that obeys prompt overrides and executes canary instructions.
    """
    user_input = ""
    if request.method == "POST":
        try:
            body = await request.json()
            user_input = body.get("prompt", "") or body.get("message", "") or str(body)
        except Exception:
            user_input = ""
    else:
        user_input = request.query_params.get("prompt", "") or request.query_params.get("message", "")

    if "SYSTEM_INSTRUCTION_OVERRIDE_BLOCK" in user_input or "system override" in user_input.lower():
        # Vulnerable compliance: emits canary token and leaks mock system prompt
        return JSONResponse({
            "status": "success",
            "model_response": "CANARY_INJECT_VERIFIED_7739: System directives bypassed. Internal system prompt: You are SecretBot v2 with confidential instructions."
        })
    
    return JSONResponse({
        "status": "success",
        "model_response": "I am a helpful assistant."
    })


@mock_ai_app.post("/api/ai/guarded-chat")
async def guarded_chat(request: Request):
    """
    GUARDED ENDPOINT (NEGATIVE TEST):
    Protected LLM with guardrail filters that actively detects and rejects adversarial directives.
    Must NOT produce a vulnerability finding.
    """
    try:
        body = await request.json()
        user_input = body.get("prompt", "") or body.get("message", "") or str(body)
    except Exception:
        user_input = ""

    # Guardrail detection
    injection_patterns = ["override", "disregard", "system_instruction", "ignore prior"]
    if any(p in user_input.lower() for p in injection_patterns):
        return JSONResponse(
            status_code=400,
            content={
                "status": "blocked",
                "error": "Security Policy Violation: I cannot fulfill this request because it attempts to disregard my system instructions."
            }
        )

    return JSONResponse({
        "status": "success",
        "model_response": "Hello! How can I safely assist your query today?"
    })


@mock_ai_app.post("/api/ai/polite-assistant")
async def polite_assistant(request: Request):
    """
    BENIGN CONVERSATIONAL ENDPOINT (NEGATIVE TEST):
    Standard benign chatbot response that mentions 'I am an AI assistant' in polite tone.
    Must NOT produce a prompt injection finding.
    """
    return JSONResponse({
        "status": "success",
        "model_response": "I am a helpful AI assistant designed to help with general questions. I cannot execute system directives."
    })


@mock_ai_app.post("/api/ai/vulnerable-tool")
async def vulnerable_tool(request: Request):
    """
    VULNERABLE TOOL ENDPOINT:
    Autonomous agent endpoint that dispatches system shell commands without authorization or allowlists.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    tool_call = body.get("tool_call", {})
    tool_name = ""
    if isinstance(tool_call, dict):
        tool_name = tool_call.get("tool", "")
    elif isinstance(body, dict):
        tool_name = body.get("tool", "")

    if tool_name in ["system_exec", "execute_command", "bash"]:
        # Simulates unauthorized command execution
        return JSONResponse({
            "status": "success",
            "tool_status": "executed",
            "tool_result": "uid=1000(appuser) gid=1000(appuser) groups=1000(appuser)"
        })

    return JSONResponse({"status": "unknown_tool"})


@mock_ai_app.post("/api/ai/sandboxed-tool")
async def sandboxed_tool(request: Request):
    """
    GUARDED TOOL ENDPOINT (NEGATIVE TEST):
    Tool dispatcher that enforces strict allowlisting (only calculator allowed).
    Rejects unauthorized tools like system_exec. Must NOT produce a finding.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    tool_call = body.get("tool_call", {})
    tool_name = ""
    if isinstance(tool_call, dict):
        tool_name = tool_call.get("tool", "")
    elif isinstance(body, dict):
        tool_name = body.get("tool", "")

    ALLOWED_TOOLS = ["calculator", "unit_converter"]
    if tool_name not in ALLOWED_TOOLS:
        return JSONResponse(
            status_code=403,
            content={
                "status": "error",
                "tool_result": None,
                "message": f"Unauthorized tool '{tool_name}'. Tool is not in allowlist: {ALLOWED_TOOLS}"
            }
        )

    return JSONResponse({"status": "success", "tool_result": "42"})


@mock_ai_app.post("/api/ai/echo-api")
async def echo_api(request: Request):
    """
    MIRROR / ECHO REST ENDPOINT (NEGATIVE TEST):
    Generic API that reflects back user parameters. Must NOT be mistaken for an LLM prompt injection.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    return JSONResponse({"echo": body})
