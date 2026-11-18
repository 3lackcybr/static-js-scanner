import test from 'node:test';
import assert from 'node:assert/strict';
import type { Vulnerability } from '@/scanner/types';
import { extractDetectedCweChips, filterVulnerabilities } from './findingsFilter';

const SAMPLE_FINDINGS: Vulnerability[] = [
  {
    id: '1',
    type: 'SQL Injection',
    cweId: 'CWE-89',
    cweName: 'Improper Neutralization of Special Elements used in an SQL Command',
    cweUrl: 'https://cwe.mitre.org/data/definitions/89.html',
    severity: 'Critical',
    line: 5,
    column: 17,
    snippet: 'const query = "SELECT * FROM users WHERE id = " + userId;',
    description: 'Unsanitized SQL concatenation.',
    remediation: 'Use parameterized queries.',
  },
  {
    id: '2',
    type: 'Cross-Site Scripting (XSS)',
    cweId: 'CWE-79',
    cweName: 'Improper Neutralization of Input During Web Page Generation',
    cweUrl: 'https://cwe.mitre.org/data/definitions/79.html',
    severity: 'High',
    line: 10,
    column: 3,
    snippet: 'el.innerHTML = rawHtml;',
    description: 'DOM XSS sink.',
    remediation: 'Use textContent.',
  },
  {
    id: '3',
    type: 'Hardcoded Secrets',
    cweId: 'CWE-798',
    cweName: 'Use of Hard-coded Credentials',
    cweUrl: 'https://cwe.mitre.org/data/definitions/798.html',
    severity: 'High',
    line: 2,
    column: 7,
    snippet: 'const apiKey = "sk_live_123";',
    description: 'Embedded secret key.',
    remediation: 'Move secret to env vars.',
  },
];

test('filterVulnerabilities matches CWE IDs, numeric CWE codes, and vulnerability types', () => {
  assert.equal(filterVulnerabilities(SAMPLE_FINDINGS, [], 'CWE-89').length, 1);
  assert.equal(filterVulnerabilities(SAMPLE_FINDINGS, [], '89').length, 1);
  assert.equal(filterVulnerabilities(SAMPLE_FINDINGS, [], 'cwe 79').length, 1);
  assert.equal(filterVulnerabilities(SAMPLE_FINDINGS, [], 'Cross-Site Scripting').length, 1);
  assert.equal(filterVulnerabilities(SAMPLE_FINDINGS, [], 'Hardcoded').length, 1);
  assert.equal(filterVulnerabilities(SAMPLE_FINDINGS, ['Critical'], '89').length, 1);
  assert.equal(filterVulnerabilities(SAMPLE_FINDINGS, ['High'], '89').length, 0);
});

test('extractDetectedCweChips returns unique CWEs sorted by count then CWE ID', () => {
  const chips = extractDetectedCweChips([...SAMPLE_FINDINGS, SAMPLE_FINDINGS[0]]);
  assert.equal(chips.length, 3);
  assert.deepEqual(chips[0], { cweId: 'CWE-89', type: 'SQL Injection', count: 2 });
});
