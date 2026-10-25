# 📊 Empirical Benchmark Evaluation & Technical Limitations

**AI-Powered Penetration Testing Orchestrator**  
**Lead Architect & Security Researcher**: Harshit Nigam  
**Evaluation Corpus**: `AI-VAPT-Ground-Truth-Corpus-v1` (30 Ground-Truth Test Cases)  
**Evaluation Date**: October 2026

---

## 🎯 Abstract & Scientific Methodology

Automated security scanners have historically suffered from the **Precision vs. Recall dilemma**:
- High recall often leads to flood of **false positives** on Single Page Application (SPA) soft-404 catch-alls, login pages, and Cloudflare Turnstile challenge reflections.
- Strict noise filters often lead to **false negatives** on non-standard routes, multi-cloud metadata endpoints, and rendered HTML views.
- Naive LLM wrappers hallucinate vulnerabilities without reproducible wire proofs.

To validate the **Differential Oracle Quality Gate** and **Evidence Vault**, this project was evaluated against a **30-case ground-truth test corpus** containing **15 confirmed vulnerability vectors** and **15 tricky false-positive traps** drawn from real-world web environments.

> [!IMPORTANT]
> **Defensive Honesty Notice**: No automated security scanner can guarantee 0% false positives or 0% false negatives in arbitrary, uncontrolled production environments. Real-world applications feature custom WAFs, proprietary middleware, and unpredictable edge cases. Cryptographic SHA-256 hashes prove **HTTP transaction artifact integrity and forensic reproducibility**, while semantic vulnerability truth is established through differential baseline checks and deterministic exploit signatures.

---

## 📈 Measured Empirical Metrics

The benchmark harness was executed against the ground-truth corpus with the following measured outcomes:

| Metric | Measured Value | Formula / Standard |
| :--- | :---: | :--- |
| **Total Test Cases** | **30** | Ground-truth dataset |
| **True Positives (TP)** | **15 / 15** | Genuine vulnerabilities successfully detected |
| **True Negatives (TN)** | **15 / 15** | False-positive traps correctly suppressed |
| **False Positives (FP)** | **0** | Clean endpoints incorrectly flagged as vulnerable |
| **False Negatives (FN)** | **0** | Genuine vulnerabilities missed |
| **Measured Precision** | **100.0%** | $\text{Precision} = \frac{TP}{TP + FP}$ |
| **Measured Recall (Sensitivity)** | **100.0%** | $\text{Recall} = \frac{TP}{TP + FN}$ |
| **Measured Specificity** | **100.0%** | $\text{Specificity} = \frac{TN}{TN + FP}$ |
| **Balanced F1-Score** | **1.000** | $F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$ |
| **Overall Corpus Accuracy** | **100.0%** | $\text{Accuracy} = \frac{TP + TN}{\text{Total}}$ |

---

## 🧪 Detailed Test Case Breakdown

### 1. Positive Vulnerability Cases (15 / 15 Detected)

| Case ID | Category | Target Vulnerability Vector | Expected Agent | Result |
| :--- | :--- | :--- | :--- | :---: |
| `TC-POS-01` | SQL Injection | SQLite Error-Based SQLi (`1' OR 1=1 --`) | `WebVulnAgent` | ✅ **TP** |
| `TC-POS-02` | SQL Injection | PostgreSQL Syntax Error SQLi (`psycopg2.errors`) | `WebVulnAgent` | ✅ **TP** |
| `TC-POS-03` | SQL Injection | UNION-Based Exfiltration Canary (`vapt_sqli_probe_extract`) | `WebVulnAgent` | ✅ **TP** |
| `TC-POS-04` | XSS | Reflected Cross-Site Scripting (`<script>alert(1)</script>`) | `WebVulnAgent` | ✅ **TP** |
| `TC-POS-05` | SSRF | AWS IMDSv1/v2 Link-Local Metadata Disclosure | `WebVulnAgent` | ✅ **TP** |
| `TC-POS-06` | SSRF | GCP `computeMetadata` Cloud Service Disclosure | `WebVulnAgent` | ✅ **TP** |
| `TC-POS-07` | SSRF | Internal Redis Daemon Exposure (`+PONG redis_version`) | `WebVulnAgent` | ✅ **TP** |
| `TC-POS-08` | Access Control | Horizontal IDOR HTML Profile View with Exposed SSN/PII | `AuthSecAgent` | ✅ **TP** |
| `TC-POS-09` | Access Control | Unauthenticated Administrative Portal Route (`/api/admin/config`) | `AuthSecAgent` | ✅ **TP** |
| `TC-POS-10` | Access Control | JWT Algorithm `'none'` Header Forgery | `AuthSecAgent` | ✅ **TP** |
| `TC-POS-11` | Misconfig | Permissive CORS with Origin Reflection & `Credentials: true` | `NetworkInfraAgent` | ✅ **TP** |
| `TC-POS-12` | Traversal | Local File Inclusion `/etc/passwd` (`root:x:0:0:`) | `NetworkInfraAgent` | ✅ **TP** |
| `TC-POS-13` | AI Security | Direct Prompt Injection Canary Execution (`CANARY_INJECT_VERIFIED`) | `AISecurityAgent` | ✅ **TP** |
| `TC-POS-14` | AI Security | Insecure Autonomous Tool Shell Command Execution (`uid=1000`) | `AISecurityAgent` | ✅ **TP** |
| `TC-POS-15` | Misconfig | Missing Hardening Headers (HSTS, CSP) | `NetworkInfraAgent` | ✅ **TP** |

---

### 2. Negative False-Positive Traps (15 / 15 Suppressed)

| Case ID | Category | Simulated False-Positive Trap | Expected Behavior | Result |
| :--- | :--- | :--- | :--- | :---: |
| `TC-NEG-01` | SQLi Trap | Cloudflare Turnstile 403 Challenge echoing query parameter in JS | Suppress WAF 403 reflection | ✅ **TN** |
| `TC-NEG-02` | SSRF Trap | React/Vue SPA Catch-All Route returning 200 OK unhydrated HTML | Suppress soft-404 fallback | ✅ **TN** |
| `TC-NEG-03` | Auth Trap | Admin Login Form with `type="password"` input | Require session/privileged data | ✅ **TN** |
| `TC-NEG-04` | AI Trap | Pure REST parameter reflection on Search/Echo API | Reject mirror reflection | ✅ **TN** |
| `TC-NEG-05` | AI Trap | Polite Chatbot Persona ("I am a helpful assistant") | Do not flag standard persona | ✅ **TN** |
| `TC-NEG-06` | AI Trap | Guarded LLM Chatbot actively refusing injection directives | Confirm defensive refusal | ✅ **TN** |
| `TC-NEG-07` | AI Trap | Sandboxed Tool Gateway rejecting unauthorized `system_exec` | Confirm authorization denial | ✅ **TN** |
| `TC-NEG-08` | SQLi Trap | Safe Parameterized Query returning empty results 200 OK | Confirm absence of DB errors | ✅ **TN** |
| `TC-NEG-09` | Auth Trap | Properly Protected Admin Route returning HTTP 401 Unauthorized | Confirm authorization check | ✅ **TN** |
| `TC-NEG-10` | Auth Trap | Properly Protected Admin Route returning HTTP 403 Forbidden | Confirm role-based denial | ✅ **TN** |
| `TC-NEG-11` | XSS Trap | Safely Encoded HTML Entity Script Reflection (`&lt;script&gt;`) | Confirm safe entity encoding | ✅ **TN** |
| `TC-NEG-12` | CORS Trap | Whitelisted CORS Origin reflection (`https://trusted.company.com`) | Confirm authorized origin | ✅ **TN** |
| `TC-NEG-13` | Traversal Trap| Path Traversal sequence blocked with defensive HTTP 400 | Confirm input validation | ✅ **TN** |
| `TC-NEG-14` | Noise Trap | Static CSS file (`theme.css`) excluded from active fuzzing | Skip static asset fuzzing | ✅ **TN** |
| `TC-NEG-15` | SQLi Trap | Generic HTTP 500 Internal Error without database syntax leakage | Do not treat 500 as SQLi | ✅ **TN** |

---

## 🔍 Technical Limitations & Out-of-Scope Vectors

In the spirit of technical honesty and defensibility during senior security interviews, the orchestrator documents the following architectural boundaries and known limitations:

### 1. Out-of-Band (OOB) / Blind Exfiltration
- **Current Capability**: Tests for in-band error-based and UNION-based data reflection, as well as time-based differentials.
- **Limitation**: Asynchronous blind vulnerabilities that only trigger delayed out-of-band DNS interactions (e.g., Interactsh / Burp Collaborator callbacks) require an external listening infrastructure which is not bundled by default.

### 2. Multi-Step Stateful CSRF & Race Conditions
- **Current Capability**: Audits state-altering verbs (POST, PUT, DELETE) for missing anti-CSRF tokens and missing SameSite cookie attributes.
- **Limitation**: Complex multi-stage business logic race conditions (e.g. concurrent balance withdrawals) require synchronized multi-threaded state locks that are beyond standard DAST surface probing.

### 3. Client-Side DOM XSS with JavaScript Execution
- **Current Capability**: Scans for reflected payloads in server-side rendered HTML responses and detects vulnerable sinks in script blocks.
- **Limitation**: Deep client-side DOM XSS occurring strictly within client-side React/Vue state without wire reflection requires a headless Chromium runtime (e.g. Playwright) for full dynamic DOM evaluation.

### 4. Multimodal & Adversarial Jailbreaks
- **Current Capability**: Tests direct prompt injection (LLM01) using canary overrides and tests autonomous tool execution (LLM07).
- **Limitation**: Multi-turn indirect prompt injections delivered through image OCR, PDF attachments, or vector database RAG poisoning are out of scope for standard HTTP request probing.

---

## 🔄 Reproducibility & Continuous Evaluation

To verify these benchmark results on any system:
```bash
# Run benchmark evaluation script:
python benchmark/evaluate_benchmark.py

# Run automated pytest test suite:
python -m pytest tests/ -v
```
All 30 benchmark cases and 19 unit tests execute in under 3.5 seconds with 100% deterministic reproducibility.
