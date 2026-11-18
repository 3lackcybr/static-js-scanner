export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';

export interface CweInfo {
  id: string;
  name: string;
  officialName: string;
  severity: Severity;
  description: string;
  remediation: string;
  url: string;
}

export interface Vulnerability {
  id: string;
  type: string;
  cweId: string;
  cweName: string;
  cweUrl: string;
  severity: Severity;
  line: number;
  column: number;
  snippet: string;
  description: string;
  remediation: string;
  sourceBlock?: string;
}

export interface ExtractedScript {
  code: string;
  startLine: number;
  label: string;
  wasBeautified: boolean;
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  byCwe: Record<string, number>;
}

export interface ScanResult {
  target: string;
  sourceType: 'file' | 'url';
  fileKind: 'js' | 'html' | 'php';
  scannedAt: string;
  linesAnalyzed: number;
  scriptsExtracted: number;
  beautified: boolean;
  parseWarnings: string[];
  summary: ScanSummary;
  vulnerabilities: Vulnerability[];
}

export type ScanProgressStage =
  | 'uploading'
  | 'fetching'
  | 'extracting'
  | 'parsing'
  | 'analyzing'
  | 'finalizing';

export interface ScanProgressEvent {
  stage: ScanProgressStage;
  label: string;
  percent: number;
}

