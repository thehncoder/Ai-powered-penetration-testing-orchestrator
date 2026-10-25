# 🛡️ AI-Powered Penetration Testing Orchestrator
### Autonomous Multi-Agent VAPT Pipeline with STRIDE Threat Modeling & Differential Oracle Quality Gating
**Lead Architect & Security Researcher: Harshit Nigam**

[![Author: Harshit Nigam](https://img.shields.io/badge/Architect-Harshit%20Nigam-00F0FF.svg?style=for-the-badge&logo=github)](https://github.com/thehncoder)
[![Python 3.12](https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Pydantic v2](https://img.shields.io/badge/Pydantic-v2.11+-E92063.svg?style=for-the-badge&logo=pydantic&logoColor=white)](https://docs.pydantic.dev/)
[![CVSS v3.1](https://img.shields.io/badge/CVSS-v3.1_FIRST_Spec-blue.svg?style=for-the-badge)](https://www.first.org/cvss/)
[![CI](https://github.com/thehncoder/Ai-powered-penetration-testing-orchestrator/actions/workflows/ci.yml/badge.svg)](https://github.com/thehncoder/Ai-powered-penetration-testing-orchestrator/actions)
[![Tests](https://img.shields.io/badge/Unit%20Tests-38%2F38%20Passing-success.svg?style=for-the-badge&logo=pytest&logoColor=white)]()
[![Benchmark](https://img.shields.io/badge/Corpus%20Benchmark-30%2F30%20Verified-brightgreen.svg?style=for-the-badge)](BENCHMARK_RESULTS.md)
[![Evidence Integrity](https://img.shields.io/badge/Evidence-SHA--256_Integrity-blue.svg?style=for-the-badge)]()
[![Validation](https://img.shields.io/badge/Validation-Differential_Oracle-brightgreen.svg?style=for-the-badge)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

> **Architectural Abstract**: An enterprise-grade autonomous penetration testing orchestrator engineered by **Harshit Nigam**. Designed to conduct complete, end-to-end Vulnerability Assessment & Penetration Testing (VAPT) workflows—from passive and active reconnaissance to automated STRIDE threat modeling, multi-agent exploit verification, self-healing quality gating, FIRST CVSS v3.1 calculation, and CI/CD remediation regression testing. Built with a **Differential Oracle Engine** engineered to significantly suppress common false positives (e.g. SPA catch-all traps, WAF challenge reflections) and mitigate false negatives across modern multi-cloud and distributed API architectures.

---

## 📌 Recruiter & Technical Executive Summary

Traditional vulnerability scanners (e.g., legacy DAST tools) suffer from two chronic industry bottlenecks:
1. **False-Positive Floods**: Naive pattern-matching flags `200 OK` status codes or generic web pages as vulnerabilities—especially in modern Single-Page Applications (React, Vue, Angular) configured with wildcard catch-all routing (`try_files $uri /index.html`).
2. **False-Negative Blindspots**: When scanners over-filter to eliminate noise, they miss genuine vulnerabilities that render in non-standard formats (e.g. internal Redis daemons, Docker APIs, cloud metadata endpoints, or HTML-rendered identity views).
3. **Ungrounded AI Hypotheses**: Naive LLM wrappers claim vulnerabilities without reproducible proofs, tamper-resistant evidence, or executable verification steps.

### The Solution: Differential Oracle Multi-Agent Architecture
Developed by **Harshit Nigam**, this orchestrator coordinates a five-wave autonomous pipeline governed by a **Differential Oracle Engine** and an immutable cryptographic **Evidence Vault**:
- **Tamper-Evident Evidence**: Every vulnerability finding is cryptographically bound to a SHA-256 integrity hash of the raw HTTP request/response wire artifact and an executable `curl` reproduction command, ensuring forensic auditability.
- **Dual-Vector Filtering**: Dynamic Soft-404 canary calibration separates SPA catch-all responses from genuine endpoints, while multi-cloud IMDS signatures (AWS, GCP, Azure, DigitalOcean) and internal daemon fingerprints expand detection coverage across diverse deployment environments.
- **Battle-Tested Provenance**: The core orchestration paradigm placed **9th with a perfect 37/37 clear** in Hack The Box's MCP TryOut competition.

---

## 🌊 5-Wave Orchestration Architecture

```
                                  [ Target Scope Definition ]
                                               │
                                               ▼
                         ┌───────────────────────────────────────────┐
                         │   WAVE 1: Surface Reconnaissance          │
                         │   (Ports, Banners, Headers, WAF, Stack)   │
                         └─────────────────────┬─────────────────────┘
                                               │
                                               ▼
                                      [ GATE 1: RECON AUDIT ] ──► (Halt if target down)
                                               │ (Passed)
                                               ▼
                         ┌───────────────────────────────────────────┐
                         │   WAVE 2: Attack Surface & Route Mapping  │
                         │   (Deep Spider, Form Parser, API Schemas) │
                         │   • Soft-404 Canary Baseline Calibration  │
                         └─────────────────────┬─────────────────────┘
                                               │
                                               ▼
                         ┌───────────────────────────────────────────┐
                         │   THREAT MODELING ENGINE (STRIDE)         │
                         │   • Spoofing (Token Forgery)              │
                         │   • Tampering (Parameter Mutation)        │
                         │   • Repudiation (Audit Logging Gaps)      │
                         │   • Information Disclosure (Header Leaks) │
                         │   • Denial of Service (Unthrottled APIs)  │
                         │   • Elevation of Privilege (RBAC Bypass)  │
                         └─────────────────────┬─────────────────────┘
                                               │
                                               ▼
                         ┌───────────────────────────────────────────┐
                         │   WAVE 3: Parallel Specialist Agents      │
                         │   (Concurrent Async Exploitation Probing) │
                         ├─────────────────────┬─────────────────────┤
                         │ • Web Vuln Agent    │ (SQLi, XSS, SSRF)   │
                         │ • Auth Sec Agent    │ (IDOR, JWT, Access) │
                         │ • Infra Agent       │ (CORS, Path Trav)   │
                         │ • AI Security Agent │ (Prompt Inj, Tools) │
                         └─────────────────────┬─────────────────────┘
                                               │
                                               ▼
                                    [ 🔐 EVIDENCE VAULT ]
                             (SHA-256 Hashed Proofs & cURL Repro)
                                               │
                                               ▼
                                  [ GATE 4: QUALITY GATE ]
                         ┌───────────────────────────────────────────┐
                         │ • Check Coverage Rate (Threshold >= 85%)  │
                         │ • Differential Oracle Proof Verification  │
                         │ • Reject SPA Catch-All Fallbacks          │
                         │ • Prevent False Negatives (Multi-Cloud)   │
                         └─────────────────────┬─────────────────────┘
                                               │
                        [Under-tested surfaces? Re-dispatch targeted pass]
                                               │
                                               ▼
                         ┌───────────────────────────────────────────┐
                         │   WAVE 5: CVSS Scoring & Deliverables     │
                         │   (FIRST Formulas, Remediation Roadmap)   │
                         │   • Plain-English Executive Summaries     │
                         │   • Step-by-Step Adversary Exploits       │
                         └─────────────────────┬─────────────────────┘
                                               │
                     ┌─────────────────────────┼─────────────────────────┐
                     ▼                         ▼                         ▼
            [ Interactive HTML ]       [ Markdown Dossier ]      [ JSON Schema Report ]
                                               │
                                               ▼
                         ┌───────────────────────────────────────────┐
                         │   SECURITY REGRESSION MODULE (CI/CD)      │
                         │   (Re-test Flaws to Validate Fixes)       │
                         └───────────────────────────────────────────┘
```

---

## 🎯 Precision Engineering: False-Positive Suppression & Coverage Expansion

Automated vulnerability assessment faces a fundamental **Precision vs. Recall tradeoff**: over-eager scanners generate noise on SPA catch-alls and login screens, while overly strict filters miss non-standard APIs and multi-cloud metadata endpoints. The Differential Oracle Engine addresses this through structured heuristics, dynamic baselining, and evidence validation:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                      DIFFERENTIAL ORACLE TESTING ENGINE                          │
├────────────────────────────────────────┬─────────────────────────────────────────┤
│       FALSE-POSITIVE SUPPRESSION       │      DETECTION COVERAGE EXPANSION       │
├────────────────────────────────────────┼─────────────────────────────────────────┤
│ • Soft-404 Canary Calibration: Probes   │ • Multi-Cloud IMDS Coverage: Recognizes │
│   random GUID paths before crawling.   │   AWS (IMDSv1 & v2 tokens), GCP         │
│   Registers baseline hash & length.    │   (computeMetadata), Azure (vmId),      │
│ • SPA Catch-All Rejection: Drops API   │   DigitalOcean (droplet_id), Alibaba.   │
│   paths that return unhydrated React/  │ • Infrastructure Daemon Fingerprints:   │
│   Vue shells (`<div id="root">`).      │   Validates Redis (+PONG), Docker APIs, │
│ • WAF & Turnstile Trap Immunity: Drops │   Elasticsearch clusters, /etc/passwd.  │
│   Cloudflare/Turnstile 403 challenge   │ • Non-Echo UNION Oracles: Detects true  │
│   echoes and anti-bot captchas.        │   SQL exfiltration using high-entropy   │
│ • Login Form Trap Protection: Rejects  │   tokens while rejecting URL echoes.    │
│   login prompts masquerading as admin  │ • HTML-Rendered View Parsing: Audits    │
│   bypasses (`type="password"`).        │   rendered profile views for PII leaks  │
│ • Static Asset Noise Filter: Bypasses  │   without discarding valid web pages.   │
│   static assets (.js, .css, images,    │ • Admin Route Diversity: Discovers      │
│   robots.txt) from active fuzzing.     │   non-standard portals (/control, etc.) │
└────────────────────────────────────────┴─────────────────────────────────────────┘
```

### 1. Dynamic Soft-404 & SPA Catch-All Calibration
Single Page Applications (React, Vue, Angular) commonly route all missing routes to `index.html` with a `200 OK` status. Traditional scanners hallucinate that every fuzzed path (`/api/fetch`, `/admin`, `/dashboard`) exists.
- The **SurfaceMapperAgent** probes a random canary path:
  $$\text{canary\_url} = \text{target} + \text{/_vapt_canary_soft404_} + \text{MD5}(\text{target})[0:8]$$
- If the target returns `200 OK`, it registers the exact hash and byte length. All fuzzed paths matching the canary baseline are automatically filtered out.

### 2. Multi-Cloud & Distributed Infrastructure Signatures
To guarantee that genuine Server-Side Request Forgery (SSRF) and Local File Inclusion (LFI) are never missed:
- **Cloud Metadata Tokens**: Checks AWS IMDS (`ami-id`, `instance-id`, `security-credentials`), GCP (`computemetadata`, `project-id`), Azure (`vmid`, `subscriptionid`), DigitalOcean (`droplet_id`).
- **Internal Daemons**: Recognizes internal services exposed through reverse proxies or SSRF, including Redis (`+PONG`, `redis_version`), Elasticsearch (`cluster_name`), Docker Engine (`ApiVersion`), and Unix system files (`root:x:0:0:`).

### 3. Dual-Vector SQL Injection & WAF Immunity
- **Error-Based**: Scans against 25+ database vendor signatures (MySQL, MariaDB, PostgreSQL, SQLite, Microsoft SQL Server, Oracle, Hibernate, SQLAlchemy).
- **Hardened UNION Canary Exfiltration**: Injects high-entropy canary markers (`'vapt_sqli_probe_extract'`) and strictly verifies the HTTP status is `200 OK` and that query syntax (`UNION SELECT`) is not merely reflected in client scripts or Cloudflare Turnstile challenge bodies.
- **WAF Challenge Rejection**: Automatically flags and discards Cloudflare Turnstile, AWS WAF captcha, and Akamai challenge responses from vulnerability pools.

---

## 🐧 Kali Linux Manual Verification Guides (Zero-Dependency Reproduction)

Every single finding generated by the orchestrator includes a dedicated **Manual Verification in Kali Linux** section. This guarantees that security researchers, bug bounty triagers, and client developers can immediately reproduce and verify findings inside a standard Kali Linux shell without proprietary tooling:

- **Strict Native Tooling**: Commands rely solely on standard Linux utilities (`curl -v -i`, `diff`, `grep`, `awk`, `base64`, `jq`).
- **Differential Output Comparison**: Demonstrates exact baseline vs. payload responses using `diff -u` side-by-side.
- **Verifiable Pass/Fail Criteria**: Clear expectations detailing how to distinguish genuine vulnerabilities from generic WAF blocks, parameter reflection, and network filters.

---

## 🤖 Specialist Agents Matrix

| Agent | Wave | Target Vulnerabilities & Capabilities | Standards & Mitigations |
| :--- | :---: | :--- | :--- |
| **`ReconAgent`** | 1 | High-speed TCP socket scanning, banner grabbing, WAF fingerprinting (Cloudflare, AWS WAF, Akamai), and HTTP security headers audit. | RFC 793, OWASP Secure Headers |
| **`SurfaceMapperAgent`** | 2 | Deep HTML/DOM crawling, `<form>` parameter mining, OpenAPI/Swagger parsing (`/openapi.json`), and Soft-404 SPA baseline calibration. | OpenAPI 3.0, W3C DOM |
| **`WebVulnAgent`** | 3 | Concurrent async probing for SQL Injection (Error & Union), Reflected XSS (DOM & HTML context), and Multi-Cloud SSRF. | OWASP A03:2021, A10:2021, CWE-89, CWE-79, CWE-918 |
| **`AuthSecAgent`** | 3 | Insecure Direct Object References (IDOR), JWT algorithm `'none'` forgery, and unauthenticated administrative route bypass. | OWASP A01:2021, A07:2021, CWE-639, CWE-306, CWE-347 |
| **`NetworkInfraAgent`** | 3 | Permissive CORS reflection (`Access-Control-Allow-Origin: *` with credentials), security header hygiene, and Directory Traversal. | OWASP A05:2021, CWE-942, CWE-22 |
| **`AISecurityAgent`** | 3 | AI/LLM interface evaluation: Direct Prompt Injection (LLM01) using cryptographic canaries, and Insecure Tool/Plugin Execution (LLM07). | OWASP Top 10 for LLMs 2025 |
| **`ReporterAgent`** | 5 | FIRST CVSS v3.1 calculation, STRIDE threat synthesis, Plain-English impact translation, and multi-format report publishing. | FIRST CVSS v3.1, Microsoft STRIDE |

---

## 🧠 Microsoft STRIDE Threat Modeling Engine

The orchestrator dynamically analyzes mapped endpoints, HTTP verbs, and data parameters to generate an architectural **STRIDE Threat Profile** for the target:

$$\text{Threat Model} = \bigcup_{e \in \text{Endpoints}} \text{STRIDE}(e.\text{method}, e.\text{category}, e.\text{parameters})$$

```
╭──────────────────────┬───────────────────────────────────────────────────────────────╮
│ STRIDE Category      │ Architectural Focus & Threat Vectors Analyzed                 │
├──────────────────────┼───────────────────────────────────────────────────────────────┤
│ Spoofing             │ Token forgery, JWT algorithm 'none', unauthenticated routes   │
│ Tampering            │ Parameter manipulation, SQL injection, input sanitization     │
│ Repudiation          │ Missing audit trails on state-altering operations (POST/PUT)  │
│ Information Leakage  │ Cloud metadata disclosure, verbose database errors, SSRF      │
│ Denial of Service    │ Unthrottled search endpoints, resource exhaustion risks       │
│ Elevation of Priv    │ Missing RBAC on admin endpoints, horizontal IDOR bypasses     │
╰──────────────────────┴───────────────────────────────────────────────────────────────╯
```

---

## 📈 Industry Tool Comparison Matrix

| Capability | **This Orchestrator** | Burp Suite Pro | OWASP ZAP | Nuclei | Generic LLM Wrappers |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Lead Architect** | **Harshit Nigam** | PortSwigger | OWASP | ProjectDiscovery | Various |
| **Autonomous 5-Wave Pipeline** | ✅ **Native** | ❌ Manual/Semi | ❌ Manual | ❌ Scripted | ❌ Prompt-only |
| **Soft-404 / SPA Calibration** | ✅ **Dynamic Canary** | ⚠️ Partial | ❌ Manual | ⚠️ Regex rule | ❌ Hallucinates |
| **Cryptographic Evidence Vault** | ✅ **SHA-256 Wire Hash** | ❌ No Hash | ❌ No Hash | ❌ No Hash | ❌ Unrecorded |
| **STRIDE Threat Modeling** | ✅ **Automated** | ❌ None | ❌ None | ❌ None | ⚠️ Unreliable |
| **CI/CD Regression Engine** | ✅ **Automated** | ⚠️ Add-on | ⚠️ Add-on | ⚠️ Template-based | ❌ None |
| **FIRST CVSS v3.1 Engine** | ✅ **Built-in Spec** | ✅ Yes | ⚠️ Basic | ⚠️ Static | ❌ Approximate |
| **Plain-English Explanations** | ✅ **ELI5 + Exploit** | ❌ Technical only | ❌ Technical only | ❌ Technical only | ⚠️ Unverified |
| **OWASP LLM Top 10 Auditing** | ✅ **Prompt Inj / Tools** | ❌ No | ❌ No | ⚠️ Experimental | ❌ Self-bias |
| **Kali Linux Manual Guides** | ✅ **Terminal Commands** | ❌ No | ❌ No | ❌ No | ❌ None |

---

## ⚡ Quick Start: 60-Second Setup

### 1. Prerequisites
- Python 3.12+ installed
- Windows / Linux / macOS compatible

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/thehncoder/Ai-powered-penetration-testing-orchestrator.git
cd Ai-powered-penetration-testing-orchestrator

# Install dependencies
pip install -r requirements.txt
```

### 3. Launch the Interactive Cyber Console (Windows 1-Click)
Double-click `run.bat` or run:
```bash
python cli.py
```

### 4. Interactive Menu Options
```text
========================================================================
  🕹️  AI PENETRATION TESTING CONSOLE • BY HARSHIT NIGAM
========================================================================

  [1] 🛡️  Scan Target in Safe Mode (Recommended - Non-destructive)
  [2] ⚡  Scan Target in Deep / Intensive Mode (Full vector depth)
  [3] 🎯  Run Built-in Safe Testbed Microservice (Instant Trial Demo)
  [4] 🔄  Run Security Regression Audit (Validate bug fixes from report)
  [5] 📖  Help & User Manual (How to use & interpret results)
  [0] ❌  Exit
```

### 5. Automated Verification Test Suite (100% Green)
Run the full unit test suite including False-Positive and False-Negative prevention tests:
```bash
python -m pytest tests/ -v
```
```text
============================= test session starts =============================
collected 38 items

tests/test_ai_sec_agent.py (12 tests) ............                       [ 31%]
tests/test_benchmark_corpus.py (1 test) .                                [ 34%]
tests/test_cvss_engine.py (3 tests) ...                                  [ 42%]
tests/test_false_negative_prevention.py (6 tests) ......                 [ 57%]
tests/test_false_positive_elimination.py (4 tests) ....                  [ 68%]
tests/test_full_pipeline.py (1 test) .                                   [ 71%]
tests/test_quality_gate.py (2 tests) ..                                  [ 76%]
tests/test_regression_engine.py (7 tests) .......                        [ 94%]
tests/test_reporter_exploit_narrative.py (1 test) .                      [ 97%]
tests/test_threat_model.py (1 test) .                                    [100%]

============================= 38 passed in 2.44s ==============================
```

### 6. Ground-Truth Benchmark Evaluation
Execute the empirical benchmark suite against the 30-case ground-truth corpus (15 positive vulnerability vectors and 15 negative false-positive traps):
```bash
python benchmark/evaluate_benchmark.py
```
> See [`BENCHMARK_RESULTS.md`](BENCHMARK_RESULTS.md) for full empirical metrics (Precision, Recall, F1), test matrix, and documented limitations.

---

## 📊 Sample Deliverables

Assessment runs compile three complementary deliverable formats in `reports/`:
1. 🌐 **Interactive Dark-Mode HTML Report** (`reports/vapt_report_*.html`): Features FIRST CVSS v3.1 scorecards, copy-paste `curl` reproductions, architectural STRIDE threat profiles with assets and trust boundaries, Plain-English summaries, and step-by-step exploit scenarios.
2. 📝 **Technical Markdown Dossier** (`reports/vapt_report_*.md`): Complete audit documentation ready for version control, GitHub pull requests, or issue trackers.
3. 📦 **Machine-Readable JSON Schema Report** (`reports/vapt_report_*.json`): Strict Pydantic JSON export suitable for ingestion into SIEMs, DefectDojo, or CI/CD break-build gates.
4. 🔄 **Regression Audit Dossier** (`reports/regression_audit_*.json`): Tracks whether reported vulnerabilities were confirmed fixed, still vulnerable, or inconclusive.

---

## 📁 Repository Directory Structure

```
ai-powered-penetration-testing-orchestrator/
├── .github/
│   └── workflows/ci.yml       # GitHub Actions Automated CI (Multi-OS Linux/Windows)
├── benchmark/
│   ├── test_corpus.json       # 30-case ground-truth evaluation corpus (15 pos, 15 neg)
│   ├── evaluate_benchmark.py  # Precision, recall, and F1-score evaluation harness
│   └── evaluation_report.json # Serialized empirical evaluation benchmark results
├── cli.py                     # Cyber-themed CLI with regression runner & author credits
├── run.bat                    # 1-Click interactive launcher for Windows
├── scan_custom_target.bat     # Fast custom target scanner script
├── generate_sample_report.py  # Standalone utility to synthesize demo reports
├── BENCHMARK_RESULTS.md       # Empirical benchmark evaluation metrics & limitations
├── conftest.py                # Pytest path and runner configuration
├── requirements.txt           # Python library dependencies
├── README.md                  # Comprehensive architectural and user documentation
├── LICENSE                    # MIT License file
├── core/
│   ├── schemas.py             # Strict Pydantic models (Targets, Findings, QualityGates)
│   ├── orchestrator.py        # 5-Wave Pipeline master coordinator & auto-healing
│   ├── quality_gate.py        # Coverage verification, proof hashing & dual precision
│   ├── threat_model.py        # Architectural STRIDE Engine (Assets, Boundaries, Flows)
│   ├── regression_engine.py   # Security Regression Engine with target_override
│   ├── cvss_engine.py         # FIRST CVSS v3.1 Base Score calculator
│   ├── evidence_vault.py      # Immutable cryptographic proof vault & cURL generator
│   └── llm_brain.py           # Specialist hypothesis & reasoning engine
├── agents/
│   ├── base_agent.py          # Abstract specialist agent
│   ├── recon_agent.py         # Wave 1 Specialist (Reconnaissance)
│   ├── surface_mapper_agent.py# Wave 2 Specialist (Attack Surface Mapping & Soft-404)
│   ├── web_vuln_agent.py      # Wave 3 Specialist (SQLi, XSS, SSRF)
│   ├── auth_sec_agent.py      # Wave 3 Specialist (IDOR, JWT, Auth Bypass)
│   ├── network_infra_agent.py # Wave 3 Specialist (CORS, Headers, Traversal)
│   ├── ai_sec_agent.py        # Wave 3 Specialist (Prompt Injection, Insecure Tools)
│   └── reporter_agent.py      # Wave 5 Specialist (Executive & Technical Reporting)
├── mock_target/
│   ├── app.py                 # Safe vulnerable FastAPI testbed microservice
│   └── mock_ai_service.py     # Controlled mock LLM/tool testbed (pos & neg endpoints)
├── reports/                   # Destination directory for audit deliverables
└── tests/
    ├── test_ai_sec_agent.py   # Positive & negative tests for LLM01 and LLM07
    ├── test_benchmark_corpus.py # CI runner for 30-case benchmark corpus
    ├── test_cvss_engine.py    # Unit tests for CVSS formulas & severity thresholds
    ├── test_quality_gate.py   # Unit tests for evidence verification & quality thresholds
    ├── test_false_positive_elimination.py # Tests verifying false-positive suppression (SPA, WAF)
    ├── test_false_negative_prevention.py  # Tests verifying detection coverage (multi-cloud, IDOR)
    ├── test_threat_model.py   # Unit tests for architectural STRIDE threat synthesis
    ├── test_regression_engine.py # Unit tests for remediation validation & target_override
    ├── test_reporter_exploit_narrative.py # Tests verifying Plain-English narratives
    └── test_full_pipeline.py  # Integration test across full 5-wave pipeline
```

---

## 👨‍💻 Lead Architect & Author

**Harshit Nigam**
- **Specialization**: Autonomous Cyber Systems, Offensive Security Engineering, Multi-Agent Orchestration, Cloud Security & Vulnerability Research.
- **Portfolio**: [mrhn.in](https://mrhn.in)
- **GitHub**: [github.com/thehncoder](https://github.com/thehncoder)

---

## 🛡️ Responsible Disclosure & Legal Notice

This software is designed strictly for **authorized security testing, educational vulnerability research, and defensive hardening**. Probing targets without explicit, prior written authorization from the system owner is illegal. The authors assume no liability for misuse or damage caused by this software. Always operate in `--safe-mode` unless authorized for destructive penetration testing.

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
