'use client';

import { useMemo, useState } from 'react';
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
  Search,
  ShieldAlert,
} from 'lucide-react';
import { exportReportAsJson, exportReportAsPdf } from '@/lib/reportExporter';
import type { ScanResult, Severity } from '@/scanner/types';
import SeverityFilter from './SeverityFilter';
import SeverityPieChart from './SeverityPieChart';

interface ScanResultViewProps {
  result: ScanResult;
  onReset: () => void;
}

function SeverityIndicator({ severity }: { severity: Severity }) {
  if (severity === 'Critical') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-400 whitespace-nowrap shrink-0">
        <AlertOctagon className="w-3.5 h-3.5" aria-hidden="true" />
        <span>Critical</span>
      </span>
    );
  }
  if (severity === 'High') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-400 whitespace-nowrap shrink-0">
        <AlertTriangle className="w-3.5 h-3.5" aria-hidden="true" />
        <span>High</span>
      </span>
    );
  }
  if (severity === 'Medium') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-sky-400 whitespace-nowrap shrink-0">
        <ShieldAlert className="w-3.5 h-3.5" aria-hidden="true" />
        <span>Medium</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400 whitespace-nowrap shrink-0">
      <Info className="w-3.5 h-3.5" aria-hidden="true" />
      <span>Low</span>
    </span>
  );
}

export default function ScanResultView({ result, onReset }: ScanResultViewProps) {
  const [selectedSeverities, setSelectedSeverities] = useState<Severity[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [exportingPdf, setExportingPdf] = useState(false);

  const handleToggleSeverity = (level: Severity) => {
    setSelectedSeverities((prev) =>
      prev.includes(level) ? prev.filter((item) => item !== level) : [...prev, level]
    );
  };

  const filteredVulnerabilities = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return result.vulnerabilities.filter((v) => {
      if (selectedSeverities.length > 0 && !selectedSeverities.includes(v.severity)) {
        return false;
      }
      if (!q) return true;
      return (
        v.type.toLowerCase().includes(q) ||
        v.cweId.toLowerCase().includes(q) ||
        v.snippet.toLowerCase().includes(q) ||
        v.description.toLowerCase().includes(q) ||
        String(v.line).includes(q)
      );
    });
  }, [result.vulnerabilities, selectedSeverities, searchQuery]);

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
            <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-red-400">
              {result.summary.critical}
            </div>
          </div>
          <div className="py-1 md:py-2 md:px-6">
            <div className="text-xs text-slate-400">High Severity</div>
            <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-amber-400">
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
            onToggleSeverity={handleToggleSeverity}
          />

          {/* Filter & Search Toolbar */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <SeverityFilter
              summary={result.summary}
              selectedSeverities={selectedSeverities}
              onToggleSeverity={handleToggleSeverity}
              onSelectAll={() => setSelectedSeverities([])}
            />

            <div className="relative lg:w-72">
              <Search
                className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none"
                aria-hidden="true"
              />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by CWE, line, or snippet..."
                aria-label="Filter findings"
                className="w-full pl-9 pr-3 py-2 text-xs bg-[#111622] border border-slate-800 rounded-md text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-[#C8A253]/70"
              />
            </div>
          </div>

          {/* Filtered Findings List */}
          {filteredVulnerabilities.length === 0 ? (
            <div className="bg-[#111622] border border-slate-800 rounded-lg p-8 text-center space-y-2">
              <p className="text-sm text-slate-300">No findings match the current filter.</p>
              <button
                type="button"
                onClick={() => {
                  setSelectedSeverities([]);
                  setSearchQuery('');
                }}
                className="text-xs font-medium text-[#E6C77E] hover:underline cursor-pointer"
              >
                Reset filters
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              {filteredVulnerabilities.map((vuln) => (
                <article
                  key={vuln.id}
                  className="bg-[#111622] border border-slate-800 rounded-lg overflow-hidden"
                >
                  <div className="px-6 py-4 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <SeverityIndicator severity={vuln.severity} />
                      <span className="text-slate-600" aria-hidden="true">
                        &middot;
                      </span>
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
              ))}
            </div>
          )}
        </>
      )}
    </motion.section>
  );
}
