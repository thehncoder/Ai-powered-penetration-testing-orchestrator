"""
Command Line Interface for AI-Powered Penetration Testing Orchestrator.
Provides cyber-themed terminal animations, live wave tracking, and telemetry tables.
"""

import os
import sys
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Ensure project root is in sys.path
root_dir = str(Path(__file__).resolve().parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

import json
import asyncio
import argparse
import subprocess
import time
from typing import Dict, Any, Optional
from termcolor import colored
from tabulate import tabulate

from core.schemas import TargetScope, AssessmentReport
from core.orchestrator import VAPTOrchestrator
from core.regression_engine import SecurityRegressionEngine


BANNER = """
\033[1;36m
   █████╗ ██╗    ██╗   ██╗ █████╗ ██████╗ ████████╗
  ██╔══██╗██║    ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝
  ███████║██║    ██║   ██║███████║██████╔╝   ██║   
  ██╔══██║██║    ╚██╗ ██╔╝██╔══██║██╔═══╝    ██║   
  ██║  ██║██║     ╚████╔╝ ██║  ██║██║        ██║   
\033[1;35m  AI-POWERED PENETRATION TESTING ORCHESTRATOR\033[0m
  \033[2mMulti-Agent Autonomous VAPT Pipeline with Quality Gating\033[0m
  \033[38;5;244mby Harshit Nigam\033[0m
"""


def telemetry_handler(wave: str, message: str, data: Dict[str, Any]):
    wave_color_map = {
        "SYSTEM": ("cyan", ["bold"]),
        "PROGRESS": ("yellow", ["bold"]),
        "WAVE 1": ("blue", ["bold"]),
        "GATE 1": ("green", ["bold"]),
        "WAVE 2": ("magenta", ["bold"]),
        "THREAT MODEL": ("cyan", ["bold"]),
        "WAVE 3": ("yellow", ["bold"]),
        "WAVE 4": ("red", ["bold"]),
        "GATE 4": ("green", ["bold"]),
        "WAVE 5": ("cyan", ["bold"]),
        "SUCCESS": ("green", ["bold"]),
        "WARN": ("yellow", ["bold"]),
        "ERROR": ("red", ["bold"])
    }

    color, attrs = wave_color_map.get(wave, ("white", []))
    prefix = colored(f"[{wave:^14}]", color, attrs=attrs if attrs else None)
    print(f" {prefix} {message}", flush=True)


def start_mock_server_process(port: int = 8877):
    """Spins up the built-in mock target app in a background subprocess."""
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "mock_target.app:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=root_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1.5)
    return proc


async def run_pipeline(target_url: str, safe_mode: bool = True, concurrency: int = 5, transport: Optional[Any] = None):
    print(BANNER, flush=True)
    print(colored("=" * 72, "dark_grey"), flush=True)
    print(f" Target: {colored(target_url, 'white', attrs=['bold'])} | Safe Mode: {colored(str(safe_mode), 'green')} | Concurrency: {concurrency}", flush=True)
    print(colored("=" * 72, "dark_grey") + "\n", flush=True)

    scope = TargetScope(
        target_url=target_url,
        safe_mode=safe_mode,
        concurrency_limit=concurrency
    )

    orchestrator = VAPTOrchestrator(scope=scope, event_callback=telemetry_handler, transport=transport)
    report = await orchestrator.run()

    # Display Executive Summary Table
    print("\n" + colored("=" * 72, "dark_grey"), flush=True)
    print(colored("  📌 ASSESSMENT EXECUTIVE SCORECARD", "cyan", attrs=["bold"]), flush=True)
    print(colored("=" * 72, "dark_grey"), flush=True)

    summary_rows = [
        ["Report ID", report.report_id],
        ["Target URL", report.target.target_url],
        ["Surface Coverage Rate", f"{report.summary.coverage_rate}%"],
        ["Average CVSS Base Score", f"{report.summary.mean_cvss} / 10.0"],
        ["Total Verified Findings", report.summary.total_findings],
        ["  - Critical Severity (9.0 - 10.0)", colored(str(report.summary.critical_count), "red", attrs=["bold"])],
        ["  - High Severity (7.0 - 8.9)", colored(str(report.summary.high_count), "yellow", attrs=["bold"])],
        ["  - Medium Severity (4.0 - 6.9)", colored(str(report.summary.medium_count), "blue")],
        ["  - Low Severity (0.1 - 3.9)", str(report.summary.low_count)],
    ]
    print(tabulate(summary_rows, tablefmt="rounded_grid"), flush=True)

    # Display Findings Table
    if report.findings:
        print("\n" + colored("  🔍 VERIFIED VULNERABILITIES (EVIDENCE-BACKED)", "yellow", attrs=["bold"]), flush=True)
        findings_table = []
        for f in report.findings:
            sev_badge = colored(f.severity.value, "red" if f.severity.value == "CRITICAL" else "yellow")
            findings_table.append([
                f.finding_id,
                sev_badge,
                f.cvss.base_score,
                f.title[:38],
                f"{f.http_method} {f.affected_url[:35]}",
                f.evidence.proof_hash
            ])
        print(tabulate(findings_table, headers=["ID", "Severity", "CVSS", "Title", "Affected Endpoint", "Proof Hash"], tablefmt="rounded_outline"), flush=True)

        print("\n" + colored("  💡 QUICK PLAIN-ENGLISH SUMMARY OF DISCOVERED FLAWS:", "cyan", attrs=["bold"]), flush=True)
        for idx, f in enumerate(report.findings, 1):
            sev_color = "red" if f.severity.value == "CRITICAL" else ("yellow" if f.severity.value == "HIGH" else "blue")
            print(colored(f"\n  [{idx}] {f.title} ({f.severity.value})", sev_color, attrs=["bold"]))
            if f.where_is_the_flaw:
                print(colored("      📍 Where is the flaw: ", "white", attrs=["bold"]) + f.where_is_the_flaw)
            if f.plain_english_summary:
                print(colored("      💡 Simple breakdown:  ", "white", attrs=["bold"]) + f.plain_english_summary)
            if f.how_attacker_exploits:
                first_step = f.how_attacker_exploits.split('\n')[0]
                print(colored("      🏴‍☠️ Attacker exploit:  ", "white", attrs=["bold"]) + first_step + ("..." if '\n' in f.how_attacker_exploits else ""))
            if f.real_world_impact:
                print(colored("      💥 Real-world impact: ", "white", attrs=["bold"]) + f.real_world_impact)

    html_file = f"reports/{report.report_id.lower().replace('-', '_')}.html"
    print("\n" + colored("  📄 ARTIFACT DELIVERABLES GENERATED", "green", attrs=["bold"]), flush=True)
    print(f"  - HTML Report:     {html_file}", flush=True)
    print(f"  - Markdown Report: reports/{report.report_id.lower().replace('-', '_')}.md", flush=True)
    print(f"  - JSON Schema:     reports/{report.report_id.lower().replace('-', '_')}.json\n", flush=True)

    # Record exact generated report path for batch launcher
    with open("reports/.latest_html.txt", "w", encoding="utf-8") as lf:
        lf.write(html_file)


async def run_regression(report_path: str, target_override: Optional[str] = None):
    print(BANNER, flush=True)
    print(colored("=" * 72, "dark_grey"), flush=True)
    print(colored(f"  🔄 SECURITY REGRESSION & REMEDIATION VERIFICATION AUDIT", "yellow", attrs=["bold"]), flush=True)
    print(colored("=" * 72, "dark_grey") + "\n", flush=True)

    path = Path(report_path)
    if not path.exists():
        print(colored(f"Error: Report file not found at {report_path}", "red"), flush=True)
        return

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    report_obj = AssessmentReport.model_validate(data)
    engine = SecurityRegressionEngine()
    audit_res = await engine.run_regression_audit(report_obj.findings, target_override=target_override)

    print(colored(f"Target: {audit_res.target_url} | Findings Evaluated: {audit_res.total_tested}", "white"), flush=True)
    print(colored(f"Remediated: {audit_res.remediated_count} | Regressed: {audit_res.regressed_count} | Fix Rate: {audit_res.fix_rate}%\n", "cyan"), flush=True)

    rows = []
    for r in audit_res.results:
        st_color = "green" if r["status"] == "REMEDIATED" else "red"
        rows.append([
            r["finding_id"],
            colored(r["status"], st_color, attrs=["bold"]),
            r["original_severity"],
            r["affected_url"][:35],
            r["verification_notes"][:45]
        ])

    print(tabulate(rows, headers=["ID", "Regression Status", "Severity", "Endpoint", "Verification Notes"], tablefmt="rounded_outline"), flush=True)

    # Save regression report
    out_dir = Path("reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{audit_res.audit_id.lower().replace('-', '_')}.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(audit_res.to_dict(), f, indent=2)
    print(colored(f"\n  📄 Regression audit saved to {out_file}\n", "green"), flush=True)


def print_help_manual():
    print("\n" + colored("=" * 72, "cyan"), flush=True)
    print(colored("  📖 AI-POWERED VAPT ORCHESTRATOR - USER GUIDE & MANUAL", "white", attrs=["bold"]), flush=True)
    print(colored("=" * 72, "cyan") + "\n", flush=True)
    print(colored("1. SAFE MODE VS DEEP / INTENSIVE MODE:", "yellow", attrs=["bold"]), flush=True)
    print("   • Safe Mode (Recommended - Press 1): Non-destructive probes only. Safe for", flush=True)
    print("     production systems, APIs, and personal websites. Avoids database mutation.", flush=True)
    print("   • Deep / Intensive Mode (Press 2): Executes full recursive fuzzing across all", flush=True)
    print("     input parameters with extended payload sets. Use on staging or authorized test environments.\n", flush=True)
    
    print(colored("2. THE 5-WAVE AUTONOMOUS PIPELINE:", "yellow", attrs=["bold"]), flush=True)
    print("   • Wave 1: Host, port, WAF, and stack reconnaissance.", flush=True)
    print("   • Wave 2: Attack surface mapping and STRIDE threat modeling.", flush=True)
    print("   • Wave 3: Parallel specialist agents (Web Vulns, Auth/IDOR, Infra, AI/LLM Security).", flush=True)
    print("   • Wave 4: Quality gate coverage audit & self-healing re-dispatch.", flush=True)
    print("   • Wave 5: FIRST CVSS v3.1 scoring, remediation roadmap, and multi-format reports.\n", flush=True)
    
    print(colored("3. CVSS v3.1 SEVERITY Posture:", "yellow", attrs=["bold"]), flush=True)
    print("   • CRITICAL (9.0 - 10.0): Immediate exploitability (SQLi, RCE, SSRF, Auth bypass).", flush=True)
    print("   • HIGH     (7.0 -  8.9): Significant exposure (IDOR, Path Traversal, Privilege Esc).", flush=True)
    print("   • MEDIUM   (4.0 -  6.9): Moderate risk (Reflected XSS, Permissive CORS).", flush=True)
    print("   • LOW      (0.1 -  3.9): Minor hardening and missing defense headers.\n", flush=True)
    
    print(colored("4. ETHICAL & LEGAL RULES OF ENGAGEMENT:", "yellow", attrs=["bold"]), flush=True)
    print("   • Always obtain explicit written authorization before scanning any target.", flush=True)
    print("   • For practice, use the built-in mock testbed or authorized labs (HTB/DVWA).\n", flush=True)
    input(colored("Press Enter to return to the main menu...", "cyan"))


def interactive_menu():
    while True:
        print(BANNER, flush=True)
        print(colored("=" * 72, "dark_grey"), flush=True)
        print(colored("  🕹️  AI PENETRATION TESTING CONSOLE • BY HARSHIT NIGAM", "cyan", attrs=["bold"]), flush=True)
        print(colored("=" * 72, "dark_grey") + "\n", flush=True)
        print(colored("  [1] 🛡️  Scan Target in Safe Mode (Recommended - Non-destructive)", "green", attrs=["bold"]), flush=True)
        print(colored("  [2] ⚡  Scan Target in Deep / Intensive Mode (Full vector depth)", "yellow", attrs=["bold"]), flush=True)
        print(colored("  [3] 🎯  Run Built-in Safe Testbed Microservice (Instant Trial Demo)", "cyan", attrs=["bold"]), flush=True)
        print(colored("  [4] 🔄  Run Security Regression Audit (Validate bug fixes from report)", "magenta", attrs=["bold"]), flush=True)
        print(colored("  [5] 📖  Help & User Manual (How to use & interpret results)", "white", attrs=["bold"]), flush=True)
        print(colored("  [0] ❌  Exit", "dark_grey"), flush=True)
        print("\n" + colored("=" * 72, "dark_grey"), flush=True)

        choice = input("\nSelect an option [0-5]: ").strip()

        if choice == "1":
            url = input("\nEnter target URL (e.g. https://mrhn.in or http://localhost:3000): ").strip()
            if url:
                asyncio.run(run_pipeline(target_url=url, safe_mode=True))
                input(colored("\nScan complete. Press Enter to return to menu...", "cyan"))
        elif choice == "2":
            url = input("\nEnter target URL for Deep Scan (Authorized targets only!): ").strip()
            if url:
                asyncio.run(run_pipeline(target_url=url, safe_mode=False))
                input(colored("\nScan complete. Press Enter to return to menu...", "cyan"))
        elif choice == "3":
            import httpx
            from mock_target.app import app as mock_app
            transport = httpx.ASGITransport(app=mock_app)
            asyncio.run(run_pipeline(target_url="http://127.0.0.1:8877", safe_mode=True, transport=transport))
            input(colored("\nTrial run complete. Press Enter to return to menu...", "cyan"))
        elif choice == "4":
            rep = input("\nEnter path to previous report JSON (e.g. reports/vapt_report_...json): ").strip()
            if rep:
                asyncio.run(run_regression(rep))
                input(colored("\nRegression complete. Press Enter to return to menu...", "cyan"))
        elif choice == "5":
            print_help_manual()
        elif choice in ["0", "exit", "quit", "q"]:
            print(colored("\nExiting. Stay secure!\n", "green"), flush=True)
            break
        else:
            print(colored("\nInvalid choice. Please select 0, 1, 2, 3, 4, or 5.", "red"), flush=True)


def main():
    if len(sys.argv) == 1:
        interactive_menu()
        return

    parser = argparse.ArgumentParser(description="AI Penetration Testing Orchestrator CLI")
    parser.add_argument("--target", "-t", type=str, default="http://127.0.0.1:8877", help="Target URL or domain to audit")
    parser.add_argument("--mock-target", action="store_true", help="Launch built-in safe vulnerable testbed and audit it")
    parser.add_argument("--unsafe", action="store_true", help="Disable non-destructive safe mode")
    parser.add_argument("--safe-mode", action="store_true", default=True, help="Enforce non-destructive safe mode (default: True)")
    parser.add_argument("--concurrency", "-c", type=int, default=5, help="Number of concurrent agent workers")
    parser.add_argument("--regression", "-r", type=str, default=None, help="Path to prior report JSON for remediation regression verification")

    args = parser.parse_args()

    transport = None
    if args.mock_target:
        import httpx
        from mock_target.app import app as mock_app
        print(colored(" Initializing built-in safe testbed microservice engine...", "cyan"), flush=True)
        transport = httpx.ASGITransport(app=mock_app)
        target = "http://127.0.0.1:8877"
    else:
        target = args.target.strip().strip('"').strip("'")

    if args.regression:
        asyncio.run(run_regression(args.regression, target_override=target if args.target != "http://127.0.0.1:8877" else None))
    else:
        asyncio.run(run_pipeline(
            target_url=target,
            safe_mode=not args.unsafe,
            concurrency=args.concurrency,
            transport=transport
        ))


if __name__ == "__main__":
    main()
