'use strict';

/**
 * test/scanner.test.js
 *
 * Basic unit tests for the WAF XML scanner. Uses only Node.js built-ins
 * (no test framework dependency).
 */

const assert = require('assert');
const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const SCANNER = path.resolve(__dirname, '..', 'scanner.js');
const EXAMPLES = path.resolve(__dirname, '..', 'examples');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✔  ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✘  ${name}`);
    console.error(`     ${err.message}`);
    failed++;
  }
}

function runScanner(args, opts = {}) {
  try {
    const stdout = execSync(`node "${SCANNER}" ${args}`, {
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
      ...opts,
    });
    return { stdout, exitCode: 0 };
  } catch (err) {
    return { stdout: err.stdout || '', stderr: err.stderr || '', exitCode: err.status };
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

console.log('\nWAF XML Scanner – Test Suite\n');

// ── Help ──────────────────────────────────────────────────────────────────
test('--help prints usage information', () => {
  const { stdout, exitCode } = runScanner('--help');
  assert.strictEqual(exitCode, 0, 'exit code should be 0 for --help');
  assert.ok(stdout.includes('Usage:'), 'should include Usage: header');
  assert.ok(stdout.includes('--json'), 'should mention --json option');
});

test('no arguments prints help and exits 0', () => {
  const { stdout, exitCode } = runScanner('');
  assert.strictEqual(exitCode, 0, 'exit code should be 0 when no args');
  assert.ok(stdout.includes('Usage:'), 'should include Usage: header');
});

// ── Clean file ─────────────────────────────────────────────────────────────
test('clean.xml produces zero findings and exits 0', () => {
  const { stdout, exitCode } = runScanner(`"${path.join(EXAMPLES, 'clean.xml')}"`);
  assert.strictEqual(exitCode, 0, 'clean file should exit with code 0');
  assert.ok(stdout.includes('0 (clean)') || stdout.includes('Findings: 0'), 'should report 0 findings');
});

test('clean.xml --json produces valid JSON with zero findings', () => {
  const { stdout, exitCode } = runScanner(`"${path.join(EXAMPLES, 'clean.xml')}" --json`);
  assert.strictEqual(exitCode, 0, 'clean file JSON mode should exit 0');
  const result = JSON.parse(stdout);
  assert.strictEqual(result.total, 0, 'total should be 0');
  assert.ok(Array.isArray(result.findings), 'findings should be an array');
  assert.strictEqual(result.findings.length, 0, 'findings array should be empty');
});

// ── Malicious file ─────────────────────────────────────────────────────────
test('malicious.xml produces findings and exits 1', () => {
  const { exitCode } = runScanner(`"${path.join(EXAMPLES, 'malicious.xml')}"`);
  assert.strictEqual(exitCode, 1, 'malicious file should exit with code 1');
});

test('malicious.xml --json contains expected rule IDs', () => {
  const { stdout } = runScanner(`"${path.join(EXAMPLES, 'malicious.xml')}" --json`);
  const result = JSON.parse(stdout);
  const ruleIds = result.findings.map((f) => f.ruleId);

  const expectedRules = [
    '921160', // DOCTYPE SYSTEM
    '921162', // External entity SYSTEM
    '921164', // file:// protocol
    '941100', // script tag
    '941120', // javascript: URI
    '942100', // UNION SELECT
    '942340', // stacked query
    '942260', // tautology
    '942410', // SLEEP function
    '930100', // path traversal
    '934100', // SSRF
    '932100', // shell injection
    '932110', // template injection
    '921180', // dangerous PI
    '921171', // entity bomb (document-level)
  ];

  for (const id of expectedRules) {
    assert.ok(ruleIds.includes(id), `Expected rule ${id} to fire on malicious.xml`);
  }
});

test('malicious.xml findings include line numbers > 0', () => {
  const { stdout } = runScanner(`"${path.join(EXAMPLES, 'malicious.xml')}" --json`);
  const result = JSON.parse(stdout);
  for (const finding of result.findings) {
    assert.ok(finding.line >= 1, `Finding for rule ${finding.ruleId} should have line >= 1`);
  }
});

test('malicious.xml JSON findings have required fields', () => {
  const { stdout } = runScanner(`"${path.join(EXAMPLES, 'malicious.xml')}" --json`);
  const result = JSON.parse(stdout);
  for (const finding of result.findings) {
    assert.ok(finding.ruleId, 'ruleId should be present');
    assert.ok(finding.ruleName, 'ruleName should be present');
    assert.ok(finding.severity, 'severity should be present');
    assert.ok(finding.line >= 1, 'line should be >= 1');
    assert.ok(finding.description, 'description should be present');
    assert.ok(finding.remediation, 'remediation should be present');
  }
});

// ── Individual rule checks ─────────────────────────────────────────────────

function makeXML(content) {
  const tmpFile = path.join(require('os').tmpdir(), `waf_test_${Date.now()}.xml`);
  fs.writeFileSync(tmpFile, `<?xml version="1.0"?>\n<root>${content}</root>`);
  return { tmpFile, cleanup: () => fs.unlinkSync(tmpFile) };
}

test('XXE DOCTYPE SYSTEM fires rule 921160', () => {
  const tmpFile = path.join(require('os').tmpdir(), `waf_xxe_${Date.now()}.xml`);
  fs.writeFileSync(tmpFile, '<!DOCTYPE foo SYSTEM "file:///etc/passwd"><root/>');
  try {
    const { stdout } = runScanner(`"${tmpFile}" --json`);
    const result = JSON.parse(stdout);
    assert.ok(result.findings.some((f) => f.ruleId === '921160'), '921160 should fire');
  } finally {
    fs.unlinkSync(tmpFile);
  }
});

test('XSS script tag fires rule 941100', () => {
  const { tmpFile, cleanup } = makeXML('<data><script>alert(1)</script></data>');
  try {
    const { stdout } = runScanner(`"${tmpFile}" --json`);
    const result = JSON.parse(stdout);
    assert.ok(result.findings.some((f) => f.ruleId === '941100'), '941100 should fire');
  } finally {
    cleanup();
  }
});

test('SQL UNION SELECT fires rule 942100', () => {
  const { tmpFile, cleanup } = makeXML('<q>\' UNION SELECT 1,2,3 --</q>');
  try {
    const { stdout } = runScanner(`"${tmpFile}" --json`);
    const result = JSON.parse(stdout);
    assert.ok(result.findings.some((f) => f.ruleId === '942100'), '942100 should fire');
  } finally {
    cleanup();
  }
});

test('SSRF internal IP fires rule 934100', () => {
  const { tmpFile, cleanup } = makeXML('<url>http://192.168.0.1/api</url>');
  try {
    const { stdout } = runScanner(`"${tmpFile}" --json`);
    const result = JSON.parse(stdout);
    assert.ok(result.findings.some((f) => f.ruleId === '934100'), '934100 should fire');
  } finally {
    cleanup();
  }
});

test('missing file exits with code 1 and prints error', () => {
  const { stderr, exitCode } = runScanner('"nonexistent_file.xml"');
  assert.strictEqual(exitCode, 1, 'missing file should exit with code 1');
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log('');
console.log(`Results: ${passed} passed, ${failed} failed`);
console.log('');

if (failed > 0) {
  process.exit(1);
}
