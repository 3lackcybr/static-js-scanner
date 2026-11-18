'use client';

import { useEffect } from 'react';
import { motion } from 'motion/react';
import {
  BookOpen,
  Database,
  ExternalLink,
  FileCode2,
  ShieldCheck,
  X,
} from 'lucide-react';
import type { CweInfo } from '@/scanner/types';

interface HelpDocumentationModalProps {
  open: boolean;
  cweEntries: CweInfo[];
  onClose: () => void;
}

export default function HelpDocumentationModal({
  open,
  cweEntries,
  onClose,
}: HelpDocumentationModalProps) {
  useEffect(() => {
    if (!open) return;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="help-docs-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-2xl max-h-[85vh] bg-[#111622] border border-slate-800 rounded-lg shadow-2xl flex flex-col overflow-hidden"
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800/80 flex items-center justify-between gap-4 bg-[#0D121C]">
          <div className="flex items-center gap-2.5 min-w-0">
            <BookOpen className="w-5 h-5 text-[#C8A253] shrink-0" aria-hidden="true" />
            <div>
              <h2
                id="help-docs-title"
                className="font-[family-name:var(--font-display)] text-lg font-semibold text-slate-100"
              >
                Help Documentation
              </h2>
              <p className="text-xs text-slate-400">
                Static Vulnerability Scanning Tool &middot; Inspection &amp; Reporting Guide
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close help documentation"
            className="p-1.5 rounded-md text-slate-400 hover:text-slate-100 hover:bg-slate-800/70 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" aria-hidden="true" />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-slate-300 leading-relaxed">
          {/* Supported Input Sources */}
          <section className="space-y-2.5">
            <div className="flex items-center gap-2 text-sm font-semibold text-[#E6C77E]">
              <FileCode2 className="w-4 h-4 shrink-0" aria-hidden="true" />
              <h3>1. Supported Input Sources</h3>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3.5 rounded-md bg-[#0A0E17] border border-slate-800/80 space-y-1">
                <div className="font-semibold text-slate-100">File Upload</div>
                <p className="text-slate-400">
                  Accepts <code className="text-[#E6C77E]">.js</code>,{' '}
                  <code className="text-[#E6C77E]">.mjs</code>,{' '}
                  <code className="text-[#E6C77E]">.cjs</code>,{' '}
                  <code className="text-[#E6C77E]">.html</code>,{' '}
                  <code className="text-[#E6C77E]">.htm</code>, and{' '}
                  <code className="text-[#E6C77E]">.php</code> files up to 16 MB.
                </p>
              </div>
              <div className="p-3.5 rounded-md bg-[#0A0E17] border border-slate-800/80 space-y-1">
                <div className="font-semibold text-slate-100">Remote URL</div>
                <p className="text-slate-400">
                  Fetches external scripts or HTML pages over HTTP/HTTPS with a 15-second timeout
                  and extracts embedded scripts automatically.
                </p>
              </div>
              <div className="p-3.5 rounded-md bg-[#0A0E17] border border-slate-800/80 space-y-1">
                <div className="font-semibold text-slate-100">Paste Source</div>
                <p className="text-slate-400">
                  Analyze code snippets directly in memory with language-specific extraction or
                  trigger the built-in Sample Audit anytime.
                </p>
              </div>
            </div>
          </section>

          {/* Static Detection Rules */}
          <section className="space-y-2.5">
            <div className="flex items-center gap-2 text-sm font-semibold text-[#E6C77E]">
              <ShieldCheck className="w-4 h-4 shrink-0" aria-hidden="true" />
              <h3>2. CWE Detection Coverage</h3>
            </div>
            <p className="text-slate-400">
              Source files are parsed into an Acorn Abstract Syntax Tree (with tolerant pattern
              fallback) without executing untrusted code. Findings map to MITRE CWE identifiers:
            </p>
            <div className="divide-y divide-slate-800/80 rounded-md border border-slate-800 bg-[#0A0E17]">
              {cweEntries.map((entry) => (
                <div
                  key={entry.id}
                  className="px-4 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[#E6C77E]">{entry.id}</span>
                      <span className="font-semibold text-slate-100">{entry.name}</span>
                      <span
                        className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                          entry.severity === 'Critical'
                            ? 'text-purple-200 border-purple-500/50 bg-purple-950/60'
                            : 'text-red-300 border-red-500/50 bg-red-950/50'
                        }`}
                      >
                        {entry.severity}
                      </span>
                    </div>
                    <p className="text-slate-400">{entry.description}</p>
                  </div>
                  <a
                    href={entry.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-[#E6C77E] hover:underline shrink-0"
                  >
                    <span>MITRE</span>
                    <ExternalLink className="w-3 h-3" aria-hidden="true" />
                  </a>
                </div>
              ))}
            </div>
          </section>

          {/* Local Storage, Visualizations & Exports */}
          <section className="space-y-2.5">
            <div className="flex items-center gap-2 text-sm font-semibold text-[#E6C77E]">
              <Database className="w-4 h-4 shrink-0" aria-hidden="true" />
              <h3>3. History, Visualizations &amp; Exports</h3>
            </div>
            <ul className="space-y-1.5 text-slate-400 list-disc pl-5">
              <li>
                <strong className="text-slate-200">Local IndexedDB History:</strong> Up to 50
                completed scan reports are persisted locally in your browser so you can recall or
                clear past audits from the sidebar.
              </li>
              <li>
                <strong className="text-slate-200">Interactive Severity Filtering:</strong> Use the
                Recharts severity pie chart or severity filter toggles in the results view to narrow
                findings across Critical, High, Medium, and Low tiers.
              </li>
              <li>
                <strong className="text-slate-200">Vulnerability Density Heatmap:</strong> Inspect
                concentration across audited files and severity tiers from the D3.js heatmap on the
                dashboard.
              </li>
              <li>
                <strong className="text-slate-200">Report Archiving:</strong> Export any scan
                report as a formatted PDF dossier or structured JSON payload for sharing.
              </li>
            </ul>
          </section>
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-slate-800/80 bg-[#0D121C] flex items-center justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold rounded-md bg-[#C8A253] text-[#090C12] hover:bg-[#D6B466] transition-colors cursor-pointer"
          >
            Close Documentation
          </button>
        </div>
      </motion.div>
    </div>
  );
}
