#!/usr/bin/env node
'use strict';

/**
 * WAF XML Vulnerability Scanner
 *
 * Scans an XML file for patterns that would be blocked by Azure Front Door's
 * WAF (using OWASP Core Rule Set). Reports each finding with the exact line
 * number, a WAF rule ID, severity, and human-readable explanation so you can
 * understand what needs to change (or what custom rule to write).
 *
 * Usage:  node scanner.js <file.xml>
 *         node scanner.js --help
 */

const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// WAF Rules
// Rule IDs follow OWASP CRS numbering where applicable.
// ---------------------------------------------------------------------------

const WAF_RULES = [
  // ── XXE / XML External Entity ─────────────────────────────────────────────
  {
    id: '921160',
    name: 'XXE – DOCTYPE with SYSTEM identifier',
    severity: 'CRITICAL',
    pattern: /<!DOCTYPE[^>]*\bSYSTEM\b/i,
    description:
      'DOCTYPE declaration containing a SYSTEM identifier. ' +
      'This allows the XML parser to fetch an external resource and can be used ' +
      'to read local files, perform SSRF, or cause a DoS.',
    remediation:
      'Remove the DOCTYPE declaration or replace SYSTEM with a static, ' +
      'pre-approved DTD reference. In your WAF custom rule you can exclude ' +
      'this request path from rule 921160 if the DOCTYPE is intentional.',
  },
  {
    id: '921161',
    name: 'XXE – DOCTYPE with PUBLIC identifier',
    severity: 'CRITICAL',
    pattern: /<!DOCTYPE[^>]*\bPUBLIC\b/i,
    description:
      'DOCTYPE declaration containing a PUBLIC identifier. ' +
      'Even public DTDs can be used as an XXE vector when followed by a ' +
      'SYSTEM URL.',
    remediation:
      'Remove the DOCTYPE declaration. If you require DTD validation, use an ' +
      'internal subset only, or pre-load the DTD server-side.',
  },
  {
    id: '921162',
    name: 'XXE – External entity declaration (SYSTEM)',
    severity: 'CRITICAL',
    pattern: /<!ENTITY\s+\S+\s+SYSTEM\s+["'][^"']*["']/i,
    description:
      'An XML entity is declared with a SYSTEM URI. This is the classic XXE ' +
      'payload form that instructs the parser to substitute the entity with ' +
      'the contents of a URL (e.g. file:///etc/passwd).',
    remediation:
      'Remove the external entity declaration. Disable external entity ' +
      'processing in your XML parser configuration.',
  },
  {
    id: '921163',
    name: 'XXE – External entity declaration (PUBLIC)',
    severity: 'CRITICAL',
    pattern: /<!ENTITY\s+\S+\s+PUBLIC\s+["'][^"']*["']/i,
    description:
      'An XML entity is declared with a PUBLIC identifier, which can still ' +
      'resolve to an external resource.',
    remediation:
      'Remove or rewrite the entity declaration to use an internal (inline) ' +
      'value instead of a PUBLIC URI.',
  },
  {
    id: '921164',
    name: 'XXE – file:// or expect:// protocol in entity or attribute',
    severity: 'CRITICAL',
    pattern: /(?:file|expect|glob|php|data|dict|ftp|jar|netdoc):\/\//i,
    description:
      'A URI using a protocol commonly exploited in XXE or SSRF attacks was ' +
      'detected (file://, expect://, php://, etc.). Azure Front Door blocks ' +
      'these at the WAF layer.',
    remediation:
      'Remove the URI from the XML payload. If you need to reference local ' +
      'resources, resolve them server-side before embedding in XML.',
  },

  // ── XML Bomb / Denial of Service ──────────────────────────────────────────
  {
    id: '921170',
    name: 'XML Bomb – deeply nested entity references',
    severity: 'HIGH',
    pattern: /(&[a-zA-Z_][\w.-]*;){4,}/,
    description:
      'Four or more consecutive XML entity references found on one line. ' +
      'This is a characteristic of "Billion Laughs" XML bomb payloads that ' +
      'cause exponential memory expansion during parsing.',
    remediation:
      'Reduce entity nesting. Flatten repeated entities into literal values, ' +
      'or disable entity expansion in your XML parser.',
  },
  {
    id: '921171',
    name: 'XML Bomb – large number of entity declarations',
    severity: 'HIGH',
    isDocumentLevel: true,
    check: checkEntityBomb,
    description:
      'More than 10 entity definitions were found in the document. A high ' +
      'count of entities — especially when they reference each other — is a ' +
      'hallmark of XML bomb attacks.',
    remediation:
      'Reduce the number of entity declarations, or disable DTD/entity ' +
      'processing entirely in your XML parser.',
  },
  {
    id: '921172',
    name: 'XML Bomb – excessive element nesting depth',
    severity: 'MEDIUM',
    isDocumentLevel: true,
    check: checkNestingDepth,
    description:
      'Element nesting exceeds 20 levels deep. Deeply nested XML can ' +
      'cause stack overflows in some parsers and is considered abnormal.',
    remediation:
      'Flatten your XML structure. Azure Front Door WAF blocks requests ' +
      'where the nesting depth triggers parser limits.',
  },

  // ── Cross-Site Scripting (XSS) ────────────────────────────────────────────
  {
    id: '941100',
    name: 'XSS – <script> tag',
    severity: 'HIGH',
    pattern: /<\s*script[\s>\/]/i,
    description:
      'A <script> tag was detected in the XML payload. Azure Front Door ' +
      "WAF rule 941100 blocks this as it's a direct XSS vector.",
    remediation:
      'Encode the content using XML character entities (&lt;script&gt;) or ' +
      'move script logic out of the data payload.',
  },
  {
    id: '941110',
    name: 'XSS – inline event handler attribute',
    severity: 'HIGH',
    pattern: /\bon\w+\s*=\s*["']?(?:javascript|[^"'>\s])/i,
    description:
      "An HTML event handler attribute (e.g. onclick=, onload=) was found. " +
      'These allow JavaScript execution if the XML is rendered in a browser ' +
      'and are blocked by WAF rule 941110.',
    remediation:
      'Remove event handler attributes from the XML, or escape their content ' +
      'using XML entities.',
  },
  {
    id: '941120',
    name: 'XSS – javascript: URI scheme',
    severity: 'HIGH',
    pattern: /javascript\s*:/i,
    description:
      'The javascript: URI scheme was detected. When processed by a browser ' +
      'this executes arbitrary JavaScript and is blocked by WAF rule 941120.',
    remediation:
      'Remove javascript: URIs from href, src, or any other attributes in the XML.',
  },
  {
    id: '941130',
    name: 'XSS – embedded iframe / object / embed element',
    severity: 'HIGH',
    pattern: /<\s*(?:iframe|object|embed|applet|frame|frameset)[\s>\/]/i,
    description:
      'An HTML element capable of loading external content (<iframe>, ' +
      '<object>, <embed>, etc.) was detected inside the XML, which is a ' +
      'common XSS/content-injection vector.',
    remediation:
      'Remove or encode these tags. If the XML is rendered in a browser, ' +
      'use a strict Content Security Policy and output encoding.',
  },
  {
    id: '941150',
    name: 'XSS – HTML injection via common tags',
    severity: 'MEDIUM',
    pattern: /<\s*(?:img|svg|link|meta|base|form|input|button|select|textarea|style)\b[^>]*(?:src|href|action|xlink:href)\s*=/i,
    description:
      'An HTML/SVG element with a URL-loading attribute (src=, href=, ' +
      'action=) was found. These can be used to load external resources or ' +
      'trigger script execution.',
    remediation:
      'Encode these tags or validate that their URL attributes point to ' +
      'approved destinations only.',
  },

  // ── SQL Injection ─────────────────────────────────────────────────────────
  {
    id: '942100',
    name: 'SQLi – UNION SELECT statement',
    severity: 'HIGH',
    pattern: /\bUNION\s+(?:ALL\s+)?SELECT\b/i,
    description:
      'A UNION SELECT construct was detected. This is a classic SQL injection ' +
      'pattern used to append additional queries and is blocked by WAF rule 942100.',
    remediation:
      'Parameterise database queries server-side. Do not embed raw SQL ' +
      'keywords in XML payloads.',
  },
  {
    id: '942200',
    name: 'SQLi – SQL comment operators',
    severity: 'HIGH',
    pattern: /(?:--|#|\/\*[\s\S]*?\*\/)(?:\s*(?:OR|AND|SELECT|DROP|INSERT|UPDATE|DELETE)\b)/i,
    description:
      'SQL comment syntax combined with SQL keywords was found. This ' +
      'pattern is used to terminate SQL statements and inject new ones.',
    remediation:
      'Sanitise all user-supplied XML field values before they reach a ' +
      'database layer.',
  },
  {
    id: '942260',
    name: 'SQLi – authentication bypass via tautology',
    severity: 'HIGH',
    pattern: /'\s*(?:OR|AND)\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?/i,
    description:
      "Classic SQL authentication bypass: '  OR '1'='1 style tautology " +
      'that is always true, used to bypass login checks.',
    remediation:
      'Use parameterised statements. Reject XML payloads that contain SQL ' +
      'comparison operators immediately adjacent to quote characters.',
  },
  {
    id: '942340',
    name: 'SQLi – stacked/batched queries',
    severity: 'HIGH',
    pattern: /;\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b/i,
    description:
      'A semicolon followed by a SQL keyword was detected. This is a ' +
      'stacked-query injection pattern used to run multiple statements.',
    remediation:
      'Disallow semicolons in XML field values that feed into SQL queries, ' +
      'or use parameterised queries exclusively.',
  },
  {
    id: '942410',
    name: 'SQLi – dangerous SQL functions / keywords',
    severity: 'MEDIUM',
    pattern: /\b(?:SLEEP|BENCHMARK|WAITFOR\s+DELAY|LOAD_FILE|INTO\s+(?:OUT|DUMP)FILE|INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)\b/i,
    description:
      'SQL functions or system table names associated with blind SQLi, data ' +
      'exfiltration, or reconnaissance were found.',
    remediation:
      'Strip or encode these keywords before placing user-supplied values ' +
      'into XML that is subsequently processed by a SQL layer.',
  },

  // ── Path Traversal ────────────────────────────────────────────────────────
  {
    id: '930100',
    name: 'Path traversal – ../ sequences',
    severity: 'MEDIUM',
    pattern: /(?:\.\.\/|\.\.\\){2,}/,
    description:
      'Multiple path traversal sequences (../../) were found. These can ' +
      'be used to escape the intended directory when an XML value is used ' +
      'as a file path.',
    remediation:
      'Canonicalise file paths server-side and validate them against an ' +
      'allow-list. Do not pass raw XML values directly to file system APIs.',
  },
  {
    id: '930110',
    name: 'Path traversal – URL-encoded traversal',
    severity: 'MEDIUM',
    pattern: /(?:%2e%2e%2f|%2e%2e\/|\.\.%2f){1,}/i,
    description:
      'URL-encoded path traversal sequences were detected. WAF rule 930110 ' +
      'catches percent-encoded variants of ../ that bypass naive string checks.',
    remediation:
      'Decode and normalise all URL-encoded values before validating file paths.',
  },

  // ── SSRF / Open Redirect in XML ───────────────────────────────────────────
  {
    id: '934100',
    name: 'SSRF – internal network address in URL value',
    severity: 'HIGH',
    pattern:
      /(?:https?|ftp):\/\/(?:localhost|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|0\.0\.0\.0|::1|169\.254\.\d+\.\d+)/i,
    description:
      'A URL referencing a private/internal IP address (localhost, 127.x, ' +
      '10.x, 172.16-31.x, 192.168.x, 169.254.x) was detected. This is a ' +
      'Server-Side Request Forgery (SSRF) vector.',
    remediation:
      'Validate all URL values against an allow-list of approved external ' +
      'hostnames. Block requests to RFC-1918 and loopback addresses.',
  },

  // ── Server-Side Template / Code Injection ─────────────────────────────────
  {
    id: '932100',
    name: 'RCE – Unix/Windows shell command injection patterns',
    severity: 'HIGH',
    pattern: /(?:\$\(|\`)[^`)\n]{1,80}(?:\)|\`)|(?:;\s*(?:ls|cat|rm|wget|curl|bash|sh|cmd|powershell)\b)/i,
    description:
      'Shell command injection patterns (backtick/$(…) substitution or ; ' +
      'followed by common Unix/Windows commands) were found inside XML. ' +
      'If the XML value is passed to a shell this results in RCE.',
    remediation:
      'Never pass XML field values directly to a shell. Use safe APIs with ' +
      'argument arrays instead of string interpolation.',
  },
  {
    id: '932110',
    name: 'RCE – server-side template injection markers',
    severity: 'HIGH',
    pattern: /(?:\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}|#\{.*?\}|<%.*?%>)/,
    description:
      'Template expression delimiters ({{ }}, {% %}, ${ }, #{ }, <% %>) ' +
      'were found. If the XML is passed to a template engine this can lead ' +
      'to server-side template injection (SSTI).',
    remediation:
      'Escape or reject template metacharacters before passing XML values ' +
      'into any template rendering engine.',
  },

  // ── Processing Instruction Abuse ─────────────────────────────────────────
  {
    id: '921180',
    name: 'Dangerous XML processing instruction',
    severity: 'HIGH',
    pattern: /<\?(?!xml\s)[\w-]+/i,
    description:
      'A non-standard XML processing instruction (<? … ?>) was found. ' +
      'Processors like PHP, ASP, and others parse these as executable code ' +
      'when embedded in server-processed XML.',
    remediation:
      'Remove processing instructions from user-supplied XML. Only the ' +
      'standard <?xml …?> declaration is typically safe.',
  },

  // ── CDATA with potentially dangerous content ──────────────────────────────
  {
    id: '921190',
    name: 'CDATA section containing script or entity bypass attempt',
    severity: 'MEDIUM',
    pattern: /<!\[CDATA\[[\s\S]*?(?:<script|javascript:|on\w+=|<!ENTITY|<!DOCTYPE)[\s\S]*?\]\]>/i,
    description:
      'A CDATA section was found containing patterns associated with XSS, ' +
      'XXE, or injection attacks. CDATA sections are sometimes used to ' +
      'bypass WAF string matching that does not process CDATA boundaries.',
    remediation:
      'Validate CDATA content with the same rules applied to element text. ' +
      'Encode dangerous characters before wrapping in CDATA.',
  },
];

// ---------------------------------------------------------------------------
// Document-level checks (operate on the full content, return findings[])
// ---------------------------------------------------------------------------

function checkEntityBomb(lines) {
  const findings = [];
  const entityPattern = /<!ENTITY\s+/gi;
  let count = 0;
  lines.forEach((line, idx) => {
    const matches = line.match(entityPattern);
    if (matches) count += matches.length;
  });
  if (count > 10) {
    let reportLine = 1;
    for (let i = 0; i < lines.length; i++) {
      if (/<!ENTITY\s+/i.test(lines[i])) { reportLine = i + 1; break; }
    }
    findings.push({
      rule: WAF_RULES.find((r) => r.id === '921171'),
      line: reportLine,
      match: `(${count} entity declarations found in document)`,
    });
  }
  return findings;
}

function checkNestingDepth(lines) {
  const findings = [];
  const OPEN_TAG = /<([a-zA-Z_][\w.-]*)(?:\s[^>]*)?\s*(?<!\/)\s*>/g;
  const CLOSE_TAG = /<\/([a-zA-Z_][\w.-]*)\s*>/g;
  const MAX_DEPTH = 20;
  let depth = 0;
  let reported = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Count open tags (excluding self-closing)
    let m;
    OPEN_TAG.lastIndex = 0;
    while ((m = OPEN_TAG.exec(line)) !== null) { depth++; }
    CLOSE_TAG.lastIndex = 0;
    while ((m = CLOSE_TAG.exec(line)) !== null) { depth = Math.max(0, depth - 1); }
    // Self-closing tags do not change depth
    if (!reported && depth > MAX_DEPTH) {
      findings.push({
        rule: WAF_RULES.find((r) => r.id === '921172'),
        line: i + 1,
        match: `(nesting depth reached ${depth} at this line)`,
      });
      reported = true;
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Core scan logic
// ---------------------------------------------------------------------------

function scanLines(lines) {
  const findings = [];

  // Line-level pattern checks
  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    const lineText = lines[i];

    for (const rule of WAF_RULES) {
      if (rule.isDocumentLevel) continue; // handled separately
      if (!rule.pattern) continue;

      const match = rule.pattern.exec(lineText);
      if (match) {
        findings.push({
          rule,
          line: lineNumber,
          match: match[0].trim().slice(0, 80),
        });
        break; // one finding per rule per line to avoid duplicates
      }
    }
  }

  // Document-level checks
  for (const rule of WAF_RULES) {
    if (!rule.isDocumentLevel || !rule.check) continue;
    const docFindings = rule.check(lines);
    findings.push(...docFindings);
  }

  // Sort by line number
  findings.sort((a, b) => a.line - b.line);
  return findings;
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

const SEVERITY_COLOR = {
  CRITICAL: '\x1b[1;31m', // bold red
  HIGH: '\x1b[31m',       // red
  MEDIUM: '\x1b[33m',     // yellow
  LOW: '\x1b[36m',        // cyan
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

function supportsColor() {
  return process.stdout.isTTY && process.env.NO_COLOR === undefined;
}

function colorize(text, code) {
  return supportsColor() ? `${code}${text}${RESET}` : text;
}

function printFindings(filePath, findings, lines) {
  const total = findings.length;
  const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach((f) => { severityCounts[f.rule.severity] = (severityCounts[f.rule.severity] || 0) + 1; });

  console.log('');
  console.log(colorize('━'.repeat(72), BOLD));
  console.log(colorize(` WAF XML Vulnerability Scanner`, BOLD));
  console.log(colorize('━'.repeat(72), BOLD));
  console.log(` File    : ${path.resolve(filePath)}`);
  console.log(` Lines   : ${lines.length}`);
  console.log(` Findings: ${total === 0 ? colorize('0 (clean)', '\x1b[32m') : colorize(String(total), '\x1b[31m')}`);
  if (total > 0) {
    const parts = Object.entries(severityCounts)
      .filter(([, n]) => n > 0)
      .map(([sev, n]) => colorize(`${n} ${sev}`, SEVERITY_COLOR[sev] || ''));
    console.log(` Summary : ${parts.join('  ')}`);
  }
  console.log(colorize('━'.repeat(72), BOLD));

  if (total === 0) {
    console.log(colorize('\n ✔  No WAF rule violations detected.\n', '\x1b[32m'));
    return;
  }

  for (let i = 0; i < findings.length; i++) {
    const { rule, line, match } = findings[i];
    const sevColor = SEVERITY_COLOR[rule.severity] || '';
    console.log('');
    console.log(
      colorize(`[${i + 1}/${total}]`, DIM) +
      ' ' +
      colorize(`[${rule.severity}]`, sevColor) +
      ' ' +
      colorize(`Rule ${rule.id}`, BOLD) +
      ' – ' +
      rule.name,
    );
    console.log(colorize(`  Line ${line}: `, BOLD) + colorize(match, '\x1b[35m'));

    // Show surrounding context (±2 lines)
    const startCtx = Math.max(0, line - 3);
    const endCtx = Math.min(lines.length - 1, line + 1);
    console.log(colorize('  ┌─ Context ──────────────────────────────────────────', DIM));
    for (let l = startCtx; l <= endCtx; l++) {
      const marker = l === line - 1 ? colorize('▶ ', sevColor) : '  ';
      const lineNum = colorize(String(l + 1).padStart(4) + ' │ ', DIM);
      console.log('  │' + marker + lineNum + lines[l]);
    }
    console.log(colorize('  └───────────────────────────────────────────────────', DIM));
    console.log(colorize('  Why: ', BOLD) + rule.description);
    console.log(colorize('  Fix: ', BOLD) + rule.remediation);
  }

  console.log('');
  console.log(colorize('━'.repeat(72), BOLD));
  console.log(colorize(` Total: ${total} violation(s) found.`, '\x1b[31m'));
  console.log(colorize('━'.repeat(72), BOLD));
  console.log('');
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function printHelp() {
  console.log(`
Usage:  node scanner.js <file.xml> [options]

Options:
  --json      Output results as JSON (machine-readable)
  --no-color  Disable ANSI colour output
  --help      Show this help message

Examples:
  node scanner.js payload.xml
  node scanner.js payload.xml --json
  node scanner.js examples/malicious.xml

Description:
  Scans an XML file for patterns that would be blocked by Azure Front
  Door's WAF (OWASP CRS-based rules). Each finding includes:
    • The exact line number
    • The WAF rule ID and name
    • Severity (CRITICAL / HIGH / MEDIUM / LOW)
    • The matching text excerpt
    • An explanation of why the rule fires
    • A remediation suggestion

  Use this tool to identify which part of your XML payload triggers a WAF
  block, so you can either fix the payload or craft a targeted WAF
  exclusion/custom rule.
`);
}

function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h') || args.length === 0) {
    printHelp();
    process.exit(0);
  }

  if (args.includes('--no-color')) {
    process.env.NO_COLOR = '1';
  }

  const jsonMode = args.includes('--json');
  const filePath = args.find((a) => !a.startsWith('--'));

  if (!filePath) {
    console.error('Error: No XML file path provided. Run with --help for usage.');
    process.exit(1);
  }

  if (!fs.existsSync(filePath)) {
    console.error(`Error: File not found: ${filePath}`);
    process.exit(1);
  }

  const ext = path.extname(filePath).toLowerCase();
  if (ext && ext !== '.xml' && ext !== '.xsd' && ext !== '.xsl' && ext !== '.xslt' && ext !== '.svg' && ext !== '.rss' && ext !== '.atom') {
    console.warn(`Warning: File extension "${ext}" is not a recognised XML extension. Scanning anyway.`);
  }

  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    console.error(`Error reading file: ${err.message}`);
    process.exit(1);
  }

  const lines = content.split('\n');
  const findings = scanLines(lines);

  if (jsonMode) {
    const output = {
      file: path.resolve(filePath),
      lines: lines.length,
      total: findings.length,
      findings: findings.map(({ rule, line, match }) => ({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        line,
        match,
        description: rule.description,
        remediation: rule.remediation,
      })),
    };
    console.log(JSON.stringify(output, null, 2));
  } else {
    printFindings(filePath, findings, lines);
  }

  // Exit code: 0 = clean, 1 = findings present
  process.exit(findings.length > 0 ? 1 : 0);
}

main();
