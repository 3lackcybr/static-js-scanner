import type { Severity, Vulnerability } from '@/scanner/types';

export interface CweQuickChip {
  cweId: string;
  type: string;
  count: number;
}

function normalizeQuery(raw: string): string {
  return raw.trim().toLowerCase();
}

export function matchesVulnerabilityQuery(vuln: Vulnerability, rawQuery: string): boolean {
  const q = normalizeQuery(rawQuery);
  if (!q) return true;

  const compactCweQuery = q.replace(/^cwe[-\s]?/i, '');
  const numericCwe = vuln.cweId.replace(/^cwe-/i, '').toLowerCase();

  return (
    vuln.cweId.toLowerCase().includes(q) ||
    (compactCweQuery.length > 0 && /^\d+$/.test(compactCweQuery) && numericCwe === compactCweQuery) ||
    vuln.cweName.toLowerCase().includes(q) ||
    vuln.type.toLowerCase().includes(q) ||
    vuln.severity.toLowerCase().includes(q) ||
    vuln.snippet.toLowerCase().includes(q) ||
    vuln.description.toLowerCase().includes(q) ||
    String(vuln.line).includes(q)
  );
}

export function filterVulnerabilities(
  vulnerabilities: Vulnerability[],
  selectedSeverities: Severity[],
  searchQuery: string
): Vulnerability[] {
  return vulnerabilities.filter((vuln) => {
    if (selectedSeverities.length > 0 && !selectedSeverities.includes(vuln.severity)) {
      return false;
    }
    return matchesVulnerabilityQuery(vuln, searchQuery);
  });
}

export function extractDetectedCweChips(vulnerabilities: Vulnerability[]): CweQuickChip[] {
  const map = new Map<string, CweQuickChip>();
  for (const vuln of vulnerabilities) {
    const existing = map.get(vuln.cweId);
    if (existing) {
      existing.count += 1;
    } else {
      map.set(vuln.cweId, {
        cweId: vuln.cweId,
        type: vuln.type,
        count: 1,
      });
    }
  }
  return Array.from(map.values()).sort((a, b) => {
    if (b.count !== a.count) return b.count - a.count;
    return a.cweId.localeCompare(b.cweId);
  });
}
