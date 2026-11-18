import cweDatabase from '@/data/cwe.json';
import type { CweInfo } from './types';

const db = cweDatabase as Record<string, CweInfo>;

export function getCweInfo(cweId: string): CweInfo {
  const entry = db[cweId];
  if (entry) {
    return entry;
  }
  return {
    id: cweId,
    name: 'Security Vulnerability',
    officialName: 'Security Vulnerability',
    severity: 'Medium',
    description: 'Potential security weakness detected in JavaScript source code.',
    remediation: 'Review the flagged statement and ensure untrusted input is properly validated and encoded.',
    url: `https://cwe.mitre.org/data/definitions/${cweId.replace(/[^0-9]/g, '') || '0'}.html`,
  };
}

export function getAllCweEntries(): CweInfo[] {
  return Object.values(db);
}
