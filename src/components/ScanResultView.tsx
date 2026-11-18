'use client';

import { useState } from 'react';
import { motion } from 'motion/react';
import {
  AlertOctagon,
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  Download,
  ExternalLink,
  FileDown,
  Info,
  RotateCcw,
  ShieldAlert,
} from 'lucide-react';
import { exportReportAsJson, exportReportAsPdf } from '@/lib/reportExporter';
import { getSeverityStyle } from '@/lib/severityStyles';
import type { ScanResult, Severity, Vulnerability } from '@/scanner/types';
import SeverityFilter from './SeverityFilter';
import SeverityPieChart from './SeverityPieChart';

interface ScanResultViewProps {
  result: ScanResult;
  filteredVulnerabilities: Vulnerability[];
  selectedSeverities: Severity[];
  searchQuery: string;
  onToggleSeverity: (severity: Severity) => void;
  onSelectAllSeverities: () => void;
  onResetFilters: () => void;
  onReset: () => void;
}

function SeverityIcon({ severity, className }: { severity: Severity; className: string }) {
  if (severity === 'Critical') return <AlertOctagon className={className} aria-hidden="true" />;
  if (severity === 'High') return <AlertTriangle className={className} aria-hidden="true" />;
  if (severity === 'Medium') return <ShieldAlert className={className} aria-hidden="true" />;
  return <Info className={className} aria-hidden="true" />;
}

function SeverityBadge({ severity }: { severity: Severity }) {
  const style = getSeverityStyle(severity);
  return (
    <span
      data-testid={`severity-badge-${severity.toLowerCase()}`}
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded border text-[11px] font-semibold uppercase tracking-wider whitespace-nowrap shrink-0 ${style.badgeClass}`}
    >
      <SeverityIcon severity={severity} className="w-3.5 h-3.5 shrink-0" />
      <span>{style.label}</span>
    </span>
  );
}

export default function ScanResultView({
  result,
  filteredVulnerabilities,
  selectedSeverities,
  searchQuery,
  onToggleSeverity,
  onSelectAllSeverities,
  onResetFilters,
  onReset,
}: ScanResultViewProps) {
  const [exportingPdf, setExportingPdf] = useState(false);
  const hasActiveFilter = selectedSeverities.length > 0 || searchQuery.trim().length > 0;

  const handleDownloadJson = () => {
    exportReportAsJson(result);
  };

  const handleDownloadPdf = () => {
    setExportingPdf(true);
    try {
      exportReportAsPdf(result);
    } finally {
      setExportingPdf(false);
    }
  };

  return (
    <motion.section
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
      className="space-y-6"
    >
      {/* Report Header */}
      <div className="bg-[#111622] border border-slate-800 rounded-lg p-6">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-6 border-b border-slate-800/80">
          <div className="space-y-1.5 min-w-0">
            <h1 className="font-[family-name:var(--font-display)] text-2xl sm:text-3xl font-semibold text-slate-100 tracking-wide">
              Security Audit Report
            </h1>
            <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-slate-400">
              <span className="text-slate-200 font-medium break-all">{result.target}</span>
              <span aria-hidden="true">&middot;</span>
              <span className="font-mono uppercase">{result.sourceType}</span>
              <span aria-hidden="true">&middot;</span>
              <span className="font-mono">.{result.fileKind}</span>
              <span aria-hidden="true">&middot;</span>
              <span className="font-mono tabular-nums">
                {new Date(result.scannedAt).toLocaleString()}
              </span>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={handleDownloadPdf}
              disabled={exportingPdf}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-200 bg-[#171E2E] border border-slate-700 rounded-md hover:border-[#C8A253]/60 hover:text-white transition-colors disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <FileDown className="w-3.5 h-3.5 text-[#C8A253]" aria-hidden="true" />
              <span>{exportingPdf ? 'Preparing PDF...' : 'Export PDF'}</span>
            </button>
            <button
              type="button"
              onClick={handleDownloadJson}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-200 bg-[#171E2E] border border-slate-700 rounded-md hover:border-[#C8A253]/60 hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" aria-hidden="true" />
              <span>Export JSON</span>
            </button>
            <button
              type="button"
              onClick={onReset}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-[#090C12] bg-[#C8A253] rounded-md hover:bg-[#D6B466] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" aria-hidden="true" />
              <span>New Scan</span>
            </button>
          </div>
        </div>

        {/* Unified 4-Column Tabular KPI Strip */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 md:gap-0 md:divide-x divide-slate-800/80 pt-5">
          <div className="py-1 md:py-2 md:pr-6">
            <div className="text-xs text-slate-400">Total Findings</div>
            <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-slate-100">
              {result.summary.total}
            </div>
          </div>
          <div className="py-1 md:py-2 md:px-6">
            <div className="text-xs text-slate-400">Critical Severity</div>
            <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-purple-400">
              {result.summary.critical}
            </div>
          </div>
          <div className="py-1 md:py-2 md:px-6">
            <div className="text-xs text-slate-400">High Severity</div>
            <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-red-400">
              {result.summary.high}
            </div>
          </div>
          <div className="py-1 md:py-2 md:pl-6">
            <div className="text-xs text-slate-400">Lines Analyzed</div>
            <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-slate-100">
              {result.linesAnalyzed}
              <span className="ml-2 text-xs font-sans font-normal text-slate-400">
                ({result.scriptsExtracted} block{result.scriptsExtracted === 1 ? '' : 's'})
              </span>
            </div>
          </div>
        </div>

        {(result.beautified || result.parseWarnings.length > 0) && (
          <div className="mt-5 pt-4 border-t border-slate-800/80 space-y-2 text-xs">
            {result.beautified && (
              <p className="text-sky-300 flex items-center gap-2">
                <Info className="w-4 h-4 shrink-0" aria-hidden="true" />
                <span>
                  Minified source code was formatted prior to inspection for accurate line attribution.
                </span>
              </p>
            )}
            {result.parseWarnings.length > 0 && (
              <p className="text-amber-300 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" aria-hidden="true" />
                <span>Parser notice: {result.parseWarnings.join(' · ')}</span>
              </p>
            )}
          </div>
        )}
      </div>

      {/* Empty / Clean Result State */}
      {result.vulnerabilities.length === 0 ? (
        <div className="bg-[#111622] border border-emerald-500/30 rounded-lg p-8 text-center space-y-3">
          <div className="inline-flex items-center justify-center w-11 h-11 rounded-full bg-emerald-500/10 text-emerald-400 mx-auto">
            <CheckCircle2 className="w-6 h-6" aria-hidden="true" />
          </div>
          <h2 className="font-[family-name:var(--font-display)] text-xl font-semibold text-slate-100">
            No Vulnerabilities Detected
          </h2>
          <p className="text-sm text-slate-400 max-w-xl mx-auto leading-relaxed">
            Static inspection evaluated {result.linesAnalyzed} line(s) across{' '}
            {result.scriptsExtracted} extracted script block(s) and found no matching SQL Injection,
            Cross-Site Scripting, Command Injection, Hardcoded Secret, or Insecure eval() patterns.
          </p>
        </div>
      ) : (
        <>
          {/* Recharts Severity Breakdown Pie Chart */}
          <SeverityPieChart
            summary={result.summary}
            selectedSeverities={selectedSeverities}
            onToggleSeverity={onToggleSeverity}
          />

          {/* Severity Filter Toolbar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <SeverityFilter
              summary={result.summary}
              selectedSeverities={selectedSeverities}
              onToggleSeverity={onToggleSeverity}
              onSelectAll={onSelectAllSeverities}
            />

            {hasActiveFilter && (
              <button
                type="button"
                onClick={onResetFilters}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-[#E6C77E] bg-[#111622] border border-slate-800 rounded-md hover:border-[#C8A253]/50 transition-colors self-start sm:self-auto cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" aria-hidden="true" />
                <span>Reset filters</span>
              </button>
            )}
          </div>

          {/* Filtered Findings List */}
          {filteredVulnerabilities.length === 0 ? (
            <div className="bg-[#111622] border border-slate-800 rounded-lg p-8 text-center space-y-2">
              <p className="text-sm text-slate-300">No findings match the current filter.</p>
              <button
                type="button"
                onClick={onResetFilters}
                className="text-xs font-medium text-[#E6C77E] hover:underline cursor-pointer"
              >
                Reset filters
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredVulnerabilities.map((vuln) => {
                const severityStyle = getSeverityStyle(vuln.severity);
                return (
                  <article
                    key={vuln.id}
                    className={`bg-[#111622] border border-slate-800 border-l-[3px] ${severityStyle.cardAccentClass} rounded-lg overflow-hidden`}
                  >
                    <div className="px-6 py-4 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                        <SeverityBadge severity={vuln.severity} />
                        <h3 className="text-sm font-semibold text-slate-100">{vuln.type}</h3>
                        <span className="text-slate-600" aria-hidden="true">
                          &middot;
                        </span>
                      <a
                        href={vuln.cweUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-xs font-mono text-[#E6C77E] hover:underline whitespace-nowrap shrink-0"
                      >
                        <span>{vuln.cweId}</span>
                        <ExternalLink className="w-3 h-3" aria-hidden="true" />
                      </a>
                    </div>

                    <div className="text-xs font-mono tabular-nums text-slate-400">
                      Line {vuln.line}, Col {vuln.column}
                      {vuln.sourceBlock ? ` · ${vuln.sourceBlock}` : ''}
                    </div>
                  </div>

                  <div className="p-6 space-y-4">
                    {vuln.snippet && (
                      <pre className="bg-[#090C12] border border-slate-800/90 rounded-md px-4 py-3 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
                        <code>{vuln.snippet}</code>
                      </pre>
                    )}

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-sm leading-relaxed">
                      <div>
                        <div className="text-xs font-semibold text-slate-400 mb-1">
                          Risk Analysis
                        </div>
                        <p className="text-slate-300 text-[13px]">{vuln.description}</p>
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-emerald-400 mb-1">
                          Remediation Guidance
                        </div>
                        <p className="text-slate-300 text-[13px]">{vuln.remediation}</p>
                      </div>
                    </div>
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </>
      )}
    </motion.section>
  );
}
