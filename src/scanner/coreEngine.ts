import { detectFileKind, extractScripts } from './codeExtractor';
import { getCweInfo } from './cweMapper';
import { parseJavaScript } from './parser';
import { runCommandInjectionRule } from './rules/commandInjection';
import { runHardcodedSecretsRule } from './rules/hardcodedSecrets';
import { runInsecureEvalRule } from './rules/insecureEval';
import type { RuleContext, RuleFinding } from './rules/shared';
import { runSqlInjectionRule } from './rules/sqlInjection';
import { runXssRule } from './rules/xss';
import type { ScanProgressEvent, ScanResult, ScanSummary, Vulnerability } from './types';

export interface ScanInput {
  content: string;
  target: string;
  sourceType: 'file' | 'url';
}

const RULE_STEPS: Array<{
  label: string;
  run: (ctx: RuleContext) => RuleFinding[];
}> = [
  { label: 'Checking SQL Injection patterns (CWE-89)...', run: runSqlInjectionRule },
  { label: 'Checking Cross-Site Scripting sinks (CWE-79)...', run: runXssRule },
  { label: 'Checking Command Injection calls (CWE-78)...', run: runCommandInjectionRule },
  { label: 'Scanning for hardcoded credentials (CWE-798)...', run: runHardcodedSecretsRule },
  { label: 'Inspecting dynamic eval() invocations (CWE-95)...', run: runInsecureEvalRule },
];

export function scanSource(
  input: ScanInput,
  onProgress?: (event: ScanProgressEvent) => void
): ScanResult {
  onProgress?.({
    stage: 'extracting',
    label: 'Extracting and normalizing script blocks...',
    percent: 45,
  });

  const fileKind = detectFileKind(input.target, input.content);
  const extracted = extractScripts(input.content, fileKind);

  const parseWarnings: string[] = [];
  const rawFindings: Array<RuleFinding & { sourceBlock: string }> = [];
  let totalLinesAnalyzed = 0;
  let anyBeautified = false;

  const totalBlocks = Math.max(1, extracted.length);

  extracted.forEach((script, blockIdx) => {
    if (script.wasBeautified) {
      anyBeautified = true;
    }

    const lines = script.code.split(/\r?\n/);
    totalLinesAnalyzed += lines.length;

    const parsePercent = 50 + Math.round(((blockIdx + 0.5) / totalBlocks) * 12);
    onProgress?.({
      stage: 'parsing',
      label: `Parsing AST for ${script.label}...`,
      percent: parsePercent,
    });

    const { ast, parseWarning } = parseJavaScript(script.code);
    if (parseWarning) {
      parseWarnings.push(`${script.label}: ${parseWarning}`);
    }

    const ctx: RuleContext = {
      code: script.code,
      lines,
      ast,
      startLine: script.startLine,
      sourceBlock: script.label,
    };

    RULE_STEPS.forEach((step, ruleIdx) => {
      const base = 64 + Math.round((blockIdx / totalBlocks) * 28);
      const stepSpan = Math.round(28 / totalBlocks);
      const rulePercent = Math.min(
        94,
        base + Math.round(((ruleIdx + 1) / RULE_STEPS.length) * stepSpan)
      );
      onProgress?.({
        stage: 'analyzing',
        label: step.label,
        percent: rulePercent,
      });

      const found = step.run(ctx);
      for (const f of found) {
        rawFindings.push({ ...f, sourceBlock: script.label });
      }
    });
  });

  onProgress?.({
    stage: 'finalizing',
    label: 'Mapping CWE definitions and compiling audit report...',
    percent: 97,
  });

  // Deduplicate by (cweId, line, snippet) and sort by severity then line number
  const dedupMap = new Map<string, Vulnerability>();
  let idx = 0;
  for (const item of rawFindings) {
    const key = `${item.cweId}:${item.line}:${item.snippet}`;
    if (dedupMap.has(key)) continue;

    const cwe = getCweInfo(item.cweId);
    idx += 1;
    dedupMap.set(key, {
      id: `vuln-${idx}`,
      type: item.type,
      cweId: cwe.id,
      cweName: cwe.officialName,
      cweUrl: cwe.url,
      severity: cwe.severity,
      line: item.line,
      column: item.column,
      snippet: item.snippet,
      description: item.detail ? `${item.detail} ${cwe.description}` : cwe.description,
      remediation: cwe.remediation,
      sourceBlock: item.sourceBlock,
    });
  }

  const severityRank: Record<string, number> = {
    Critical: 0,
    High: 1,
    Medium: 2,
    Low: 3,
  };

  const vulnerabilities = Array.from(dedupMap.values()).sort((a, b) => {
    const sevDiff = (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9);
    return sevDiff !== 0 ? sevDiff : a.line - b.line;
  });

  const summary: ScanSummary = {
    total: vulnerabilities.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    byCwe: {},
  };

  for (const v of vulnerabilities) {
    if (v.severity === 'Critical') summary.critical += 1;
    else if (v.severity === 'High') summary.high += 1;
    else if (v.severity === 'Medium') summary.medium += 1;
    else summary.low += 1;

    summary.byCwe[v.cweId] = (summary.byCwe[v.cweId] ?? 0) + 1;
  }

  return {
    target: input.target,
    sourceType: input.sourceType,
    fileKind,
    scannedAt: new Date().toISOString(),
    linesAnalyzed: totalLinesAnalyzed,
    scriptsExtracted: extracted.length,
    beautified: anyBeautified,
    parseWarnings,
    summary,
    vulnerabilities,
  };
}
