'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'motion/react';
import {
  AlertOctagon,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Clock,
  Code2,
  ExternalLink,
  FileCode2,
  Globe,
  Loader2,
  Play,
  ShieldCheck,
  Upload,
  X,
} from 'lucide-react';
import { filterVulnerabilities } from '@/lib/findingsFilter';
import {
  clearScanHistory,
  deleteScanReport,
  listScanReports,
  saveScanReport,
  type StoredScanReport,
} from '@/lib/scanHistoryDb';
import type { CweInfo, ScanProgressEvent, ScanResult, Severity } from '@/scanner/types';
import HelpDocumentationModal from './HelpDocumentationModal';
import QuickActionsPanel from './QuickActionsPanel';
import ResultsSearchBar from './ResultsSearchBar';
import ScanHistoryPanel from './ScanHistoryPanel';
import ScanProgressBar from './ScanProgressBar';
import ScanResultView from './ScanResultView';
import VulnerabilityHeatmap from './VulnerabilityHeatmap';

interface ScannerClientProps {
  cweEntries: CweInfo[];
}

type InputMode = 'file' | 'url' | 'paste';

type StreamMessage =
  | ({ type: 'progress' } & ScanProgressEvent)
  | { type: 'result'; result: ScanResult }
  | { type: 'error'; error: string };

const SAMPLE_VULNERABLE_CODE = `// Sample audit snippet containing multiple static vulnerability patterns
const apiKey = "sk_live_9948120491abcdef8812";

function loadUserProfile(db, userId) {
  const query = "SELECT id, email FROM users WHERE id = " + userId;
  return db.query(query);
}

function renderAnnouncement(rawHtml) {
  document.getElementById("notice").innerHTML = rawHtml;
}

function runDiagnostics(targetHost) {
  const { exec } = require("child_process");
  exec("ping -c 1 " + targetHost);
}

function evaluateDynamicFormula(expr) {
  return eval(expr);
}
`;

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export default function ScannerClient({ cweEntries }: ScannerClientProps) {
  const [mode, setMode] = useState<InputMode>('file');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [urlInput, setUrlInput] = useState('');
  const [pastedCode, setPastedCode] = useState('');
  const [snippetFilename, setSnippetFilename] = useState('audit-sample.js');
  const [isDragging, setIsDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [scanProgress, setScanProgress] = useState<ScanProgressEvent | null>(null);
  const [uploadByteDetail, setUploadByteDetail] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [expandedCwe, setExpandedCwe] = useState<string | null>(cweEntries[0]?.id ?? null);

  // IndexedDB Scan History State
  const [historyReports, setHistoryReports] = useState<StoredScanReport[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [storageError, setStorageError] = useState<string | null>(null);
  const [activeReportId, setActiveReportId] = useState<string | null>(null);
  const [showScanHistory, setShowScanHistory] = useState(true);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [helpDocsOpen, setHelpDocsOpen] = useState(false);
  const [resultSearchQuery, setResultSearchQuery] = useState('');
  const [selectedSeverities, setSelectedSeverities] = useState<Severity[]>([]);

  const filteredResultVulnerabilities = useMemo(() => {
    if (!result) return [];
    return filterVulnerabilities(result.vulnerabilities, selectedSeverities, resultSearchQuery);
  }, [result, selectedSeverities, resultSearchQuery]);

  const handleToggleSeverity = (level: Severity) => {
    setSelectedSeverities((prev) =>
      prev.includes(level) ? prev.filter((item) => item !== level) : [...prev, level]
    );
  };

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    let active = true;
    listScanReports()
      .then((reports) => {
        if (!active) return;
        setHistoryReports(reports);
        setStorageError(null);
      })
      .catch(() => {
        if (!active) return;
        setStorageError('Browser IndexedDB storage is unavailable.');
      })
      .finally(() => {
        if (active) setHistoryLoading(false);
      });

    return () => {
      active = false;
    };
  }, []);

  const handleFileSelected = (file: File | null) => {
    setSelectedFile(file);
    setError(null);
  };

  const handleDrop = (e: React.DragEvent<HTMLLabelElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0] ?? null;
    if (file) {
      handleFileSelected(file);
    }
  };

  const persistCompletedScan = async (payload: ScanResult) => {
    setScanProgress({
      stage: 'finalizing',
      label: 'Scan complete.',
      percent: 100,
    });
    setSelectedSeverities([]);
    setResultSearchQuery('');
    setResult(payload);

    try {
      const stored = await saveScanReport(payload);
      setHistoryReports((prev) => [stored, ...prev.filter((r) => r.id !== stored.id)].slice(0, 50));
      setActiveReportId(stored.id);
      setStorageError(null);
    } catch {
      setStorageError('Scan completed, but failed to persist report to IndexedDB.');
    }
  };

  const uploadFormWithProgress = (formData: FormData): Promise<ScanResult> => {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/scan?stream=1', true);

      let processedLength = 0;
      let lineBuffer = '';
      let resolvedResult: ScanResult | null = null;
      let streamError: string | null = null;

      const processNdjsonChunk = (chunkText: string) => {
        lineBuffer += chunkText;
        const lines = lineBuffer.split('\n');
        lineBuffer = lines.pop() ?? '';

        for (const rawLine of lines) {
          const trimmed = rawLine.trim();
          if (!trimmed) continue;
          try {
            const msg = JSON.parse(trimmed) as StreamMessage;
            if (msg.type === 'progress') {
              setUploadByteDetail(null);
              setScanProgress({
                stage: msg.stage,
                label: msg.label,
                percent: msg.percent,
              });
            } else if (msg.type === 'result') {
              resolvedResult = msg.result;
            } else if (msg.type === 'error') {
              streamError = msg.error;
            }
          } catch {
            // Ignore partial line until complete
          }
        }
      };

      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable && event.total > 0) {
          const ratio = event.loaded / event.total;
          const mappedPercent = Math.max(5, Math.min(40, Math.round(5 + ratio * 35)));
          setUploadByteDetail(`${formatBytes(event.loaded)} / ${formatBytes(event.total)}`);
          setScanProgress({
            stage: 'uploading',
            label: ratio < 1 ? 'Uploading source file...' : 'Upload complete, starting inspection...',
            percent: mappedPercent,
          });
        }
      };

      xhr.onprogress = () => {
        const delta = xhr.responseText.slice(processedLength);
        processedLength = xhr.responseText.length;
        if (delta) {
          processNdjsonChunk(delta);
        }
      };

      xhr.onload = () => {
        const remaining = xhr.responseText.slice(processedLength);
        if (remaining) {
          processNdjsonChunk(remaining);
        }
        if (lineBuffer.trim()) {
          processNdjsonChunk('\n');
        }

        if (streamError) {
          reject(new Error(streamError));
          return;
        }
        if (resolvedResult) {
          resolve(resolvedResult);
          return;
        }

        // Fallback if server returned non-streaming JSON error (e.g., 400 validation)
        try {
          const fallback = JSON.parse(xhr.responseText) as ScanResult & { error?: string };
          if (xhr.status >= 400 || fallback.error) {
            reject(new Error(fallback.error || 'Failed to scan the target.'));
            return;
          }
          resolve(fallback);
        } catch {
          reject(new Error('Failed to parse scan response.'));
        }
      };

      xhr.onerror = () => {
        reject(new Error('Network error occurred while uploading source for scanning.'));
      };

      xhr.send(formData);
    });
  };

  const fetchStreamedScan = async (
    formData: FormData | null,
    jsonBody?: { code: string; filename: string }
  ): Promise<ScanResult> => {
    const response = await fetch('/api/scan?stream=1', {
      method: 'POST',
      headers: jsonBody ? { 'Content-Type': 'application/json' } : undefined,
      body: jsonBody ? JSON.stringify(jsonBody) : formData,
    });

    if (!response.ok || !response.body) {
      const payload = (await response.json().catch(() => ({}))) as { error?: string };
      throw new Error(payload.error || 'Failed to scan the target.');
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let finalResult: ScanResult | null = null;

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';

      for (const rawLine of lines) {
        const trimmed = rawLine.trim();
        if (!trimmed) continue;
        const msg = JSON.parse(trimmed) as StreamMessage;
        if (msg.type === 'progress') {
          setScanProgress({
            stage: msg.stage,
            label: msg.label,
            percent: msg.percent,
          });
        } else if (msg.type === 'result') {
          finalResult = msg.result;
        } else if (msg.type === 'error') {
          throw new Error(msg.error);
        }
      }
    }

    if (buffer.trim()) {
      const msg = JSON.parse(buffer.trim()) as StreamMessage;
      if (msg.type === 'result') finalResult = msg.result;
      else if (msg.type === 'error') throw new Error(msg.error);
    }

    if (!finalResult) {
      throw new Error('Scan completed without returning a valid report.');
    }
    return finalResult;
  };

  const runScanRequest = async (
    formData: FormData | null,
    jsonBody?: { code: string; filename: string },
    isFileUpload = false
  ) => {
    setError(null);
    setUploadByteDetail(null);
    setLoading(true);
    setScanProgress({
      stage: isFileUpload ? 'uploading' : 'extracting',
      label: isFileUpload ? 'Preparing file upload...' : 'Initializing static analysis...',
      percent: 8,
    });

    try {
      const payload =
        isFileUpload && formData
          ? await uploadFormWithProgress(formData)
          : await fetchStreamedScan(formData, jsonBody);
      await persistCompletedScan(payload);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred.');
    } finally {
      setLoading(false);
      setUploadByteDetail(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (mode === 'file') {
      if (!selectedFile) {
        setError('Select a .js, .html, or .php file to inspect.');
        return;
      }
      const formData = new FormData();
      formData.append('file', selectedFile);
      await runScanRequest(formData, undefined, true);
      return;
    }

    if (mode === 'url') {
      if (!urlInput.trim()) {
        setError('Enter a valid http:// or https:// URL to scan.');
        return;
      }
      const formData = new FormData();
      formData.append('url', urlInput.trim());
      await runScanRequest(formData, undefined, false);
      return;
    }

    if (!pastedCode.trim()) {
      setError('Paste source code to analyze.');
      return;
    }
    await runScanRequest(null, { code: pastedCode, filename: snippetFilename }, false);
  };

  const handleRunSampleAudit = async () => {
    setResult(null);
    setActiveReportId(null);
    setMode('paste');
    setSnippetFilename('sample-audit.js');
    setPastedCode(SAMPLE_VULNERABLE_CODE);
    await runScanRequest(
      null,
      {
        code: SAMPLE_VULNERABLE_CODE,
        filename: 'sample-audit.js',
      },
      false
    );
  };

  const handleReset = () => {
    setResult(null);
    setActiveReportId(null);
    setSelectedSeverities([]);
    setResultSearchQuery('');
    setError(null);
    setScanProgress(null);
    setSelectedFile(null);
    setUrlInput('');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleRecallReport = (entry: StoredScanReport) => {
    setResult(entry.result);
    setActiveReportId(entry.id);
    setSelectedSeverities([]);
    setResultSearchQuery('');
    setError(null);
    setMobileSidebarOpen(false);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleDeleteReport = async (id: string) => {
    try {
      await deleteScanReport(id);
      setHistoryReports((prev) => prev.filter((item) => item.id !== id));
      if (activeReportId === id) {
        setActiveReportId(null);
        setResult(null);
      }
    } catch {
      setStorageError('Unable to delete the selected report from IndexedDB.');
    }
  };

  const handleClearAllHistory = async () => {
    try {
      await clearScanHistory();
      setHistoryReports([]);
      setActiveReportId(null);
    } catch {
      setStorageError('Unable to clear scan history from IndexedDB.');
    }
  };

  return (
    <>
      {/* 3-Zone Top Navigation Bar */}
      <header className="border-b border-slate-800/80 bg-[#090C12]/90 backdrop-blur-sm sticky top-0 z-30">
        <div className="max-w-[1440px] mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-3 md:gap-8">
          <a
            href="#top"
            onClick={(e) => {
              e.preventDefault();
              setResult(null);
              setActiveReportId(null);
              window.scrollTo({ top: 0, behavior: 'smooth' });
            }}
            className="flex items-center gap-2 text-slate-100 hover:text-[#E6C77E] transition-colors whitespace-nowrap min-w-0"
          >
            <ShieldCheck className="w-5 h-5 text-[#C8A253] shrink-0" aria-hidden="true" />
            <span className="font-[family-name:var(--font-display)] text-xs sm:text-base font-semibold tracking-wide truncate">
              Static Vulnerability Scanning Tool
            </span>
          </a>

          <nav
            aria-label="Primary navigation"
            className="hidden md:flex items-center gap-7 text-sm font-medium text-slate-400"
          >
            <a
              href="#scanner"
              onClick={() => {
                setResult(null);
                setActiveReportId(null);
              }}
              className="hover:text-slate-100 hover:underline underline-offset-8 decoration-[#C8A253]/70 transition-colors whitespace-nowrap shrink-0"
            >
              Scanner
            </a>
            <a
              href="#coverage"
              onClick={() => {
                setResult(null);
                setActiveReportId(null);
              }}
              className="hover:text-slate-100 hover:underline underline-offset-8 decoration-[#C8A253]/70 transition-colors whitespace-nowrap shrink-0"
            >
              Coverage Rules
            </a>
            <a
              href="#heatmap"
              onClick={() => {
                setResult(null);
                setActiveReportId(null);
              }}
              className="hover:text-slate-100 hover:underline underline-offset-8 decoration-[#C8A253]/70 transition-colors whitespace-nowrap shrink-0"
            >
              Heatmap
            </a>
            <a
              href="#methodology"
              onClick={() => {
                setResult(null);
                setActiveReportId(null);
              }}
              className="hover:text-slate-100 hover:underline underline-offset-8 decoration-[#C8A253]/70 transition-colors whitespace-nowrap shrink-0"
            >
              Methodology
            </a>
          </nav>

          <div className="flex items-center shrink-0">
            <button
              type="button"
              onClick={handleRunSampleAudit}
              disabled={loading}
              className="inline-flex items-center gap-1.5 sm:gap-2 px-3 py-1.5 sm:px-4 sm:py-2 text-xs font-semibold text-[#090C12] bg-[#C8A253] rounded-md hover:bg-[#D6B466] transition-colors disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5" aria-hidden="true" />
              <span className="hidden sm:inline">Run Sample Audit</span>
              <span className="sm:hidden">Sample</span>
            </button>
          </div>
        </div>
      </header>

      <main id="top" className="flex-1 max-w-[1440px] w-full mx-auto px-4 sm:px-6 py-8 lg:py-10">
        {/* Toolbar row for mobile/tablet sidebar drawer trigger */}
        <div className="xl:hidden flex items-center justify-end gap-3 mb-4">
          <button
            type="button"
            onClick={() => setMobileSidebarOpen(true)}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-slate-200 bg-[#111622] border border-slate-800 rounded-md hover:border-[#C8A253]/50 transition-colors whitespace-nowrap cursor-pointer"
          >
            <Clock className="w-3.5 h-3.5 text-[#C8A253]" aria-hidden="true" />
            <span>Quick Actions &amp; History</span>
            <span className="font-mono tabular-nums text-slate-400">
              ({historyReports.length})
            </span>
          </button>
        </div>

        <div className="flex flex-col xl:flex-row items-start gap-8">
          {/* Primary Workspace Column */}
          <div className="flex-1 min-w-0 w-full space-y-12">
            {result ? (
              <div className="space-y-6">
                <ResultsSearchBar
                  query={resultSearchQuery}
                  onQueryChange={setResultSearchQuery}
                  vulnerabilities={result.vulnerabilities}
                  matchCount={filteredResultVulnerabilities.length}
                />
                <ScanResultView
                  result={result}
                  filteredVulnerabilities={filteredResultVulnerabilities}
                  selectedSeverities={selectedSeverities}
                  searchQuery={resultSearchQuery}
                  onToggleSeverity={handleToggleSeverity}
                  onSelectAllSeverities={() => setSelectedSeverities([])}
                  onResetFilters={() => {
                    setSelectedSeverities([]);
                    setResultSearchQuery('');
                  }}
                  onReset={handleReset}
                />
              </div>
            ) : (
              <>
                {/* Authoritative Editorial Header */}
                <section id="scanner" className="max-w-3xl space-y-3">
                  <p className="text-xs font-medium tracking-wide text-[#C8A253]">
                    AST-Driven Static Security Inspection
                  </p>
                  <h1 className="font-[family-name:var(--font-display)] text-3xl sm:text-4xl lg:text-[42px] font-semibold text-slate-100 leading-tight tracking-wide text-balance">
                    Static Vulnerability Scanning Tool
                  </h1>
                  <p className="text-sm sm:text-base text-slate-400 leading-relaxed max-w-2xl">
                    Inspect JavaScript, HTML, and PHP source code for SQL Injection, Cross-Site
                    Scripting, Command Injection, Hardcoded Secrets, and Insecure dynamic evaluation
                    without executing untrusted files.
                  </p>
                </section>

                {/* Primary 2-Column Workspace */}
                <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
                  {/* Left Column: Inspection Console */}
                  <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
                    className="lg:col-span-7 bg-[#111622] border border-slate-800 rounded-lg p-6 sm:p-8"
                  >
                    <div className="flex flex-col gap-4 pb-6 border-b border-slate-800/80">
                      <div>
                        <h2 className="text-lg font-semibold text-slate-100">Source Inspection</h2>
                        <p className="text-xs text-slate-400 mt-0.5">
                          Choose an input source to begin static analysis.
                        </p>
                      </div>

                      {/* Segmented Input Mode Switch */}
                      <div
                        role="tablist"
                        aria-label="Scan input mode"
                        className="grid grid-cols-3 sm:inline-flex w-full sm:w-auto items-center p-1 bg-[#0A0E17] border border-slate-800 rounded-md self-start"
                      >
                        <button
                          type="button"
                          role="tab"
                          aria-selected={mode === 'file'}
                          disabled={loading}
                          onClick={() => {
                            setMode('file');
                            setError(null);
                          }}
                          className={`inline-flex items-center justify-center gap-1.5 px-2 sm:px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60 ${
                            mode === 'file'
                              ? 'bg-[#1A2233] text-[#E6C77E] border border-[#C8A253]/30'
                              : 'text-slate-400 hover:text-slate-200 border border-transparent'
                          }`}
                        >
                          <FileCode2
                            className="hidden sm:inline-block w-3.5 h-3.5"
                            aria-hidden="true"
                          />
                          <span>Upload File</span>
                        </button>
                        <button
                          type="button"
                          role="tab"
                          aria-selected={mode === 'url'}
                          disabled={loading}
                          onClick={() => {
                            setMode('url');
                            setError(null);
                          }}
                          className={`inline-flex items-center justify-center gap-1.5 px-2 sm:px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60 ${
                            mode === 'url'
                              ? 'bg-[#1A2233] text-[#E6C77E] border border-[#C8A253]/30'
                              : 'text-slate-400 hover:text-slate-200 border border-transparent'
                          }`}
                        >
                          <Globe className="hidden sm:inline-block w-3.5 h-3.5" aria-hidden="true" />
                          <span>Remote URL</span>
                        </button>
                        <button
                          type="button"
                          role="tab"
                          aria-selected={mode === 'paste'}
                          disabled={loading}
                          onClick={() => {
                            setMode('paste');
                            setError(null);
                          }}
                          className={`inline-flex items-center justify-center gap-1.5 px-2 sm:px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60 ${
                            mode === 'paste'
                              ? 'bg-[#1A2233] text-[#E6C77E] border border-[#C8A253]/30'
                              : 'text-slate-400 hover:text-slate-200 border border-transparent'
                          }`}
                        >
                          <Code2 className="hidden sm:inline-block w-3.5 h-3.5" aria-hidden="true" />
                          <span>Paste Source</span>
                        </button>
                      </div>
                    </div>

                    {error && (
                      <div
                        role="alert"
                        className="mt-6 flex items-start justify-between gap-3 px-4 py-3 rounded-md bg-red-950/40 border border-red-500/40 text-red-200 text-xs"
                      >
                        <div className="flex items-start gap-2.5">
                          <AlertTriangle
                            className="w-4 h-4 text-red-400 shrink-0 mt-0.5"
                            aria-hidden="true"
                          />
                          <span>{error}</span>
                        </div>
                        <button
                          type="button"
                          aria-label="Dismiss error"
                          onClick={() => setError(null)}
                          className="text-red-300 hover:text-white cursor-pointer"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    )}

                    <form onSubmit={handleSubmit} className="mt-6 space-y-6">
                      {mode === 'file' && (
                        <div className="space-y-3">
                          <label
                            htmlFor="fileUpload"
                            onDragOver={(e) => {
                              e.preventDefault();
                              setIsDragging(true);
                            }}
                            onDragLeave={() => setIsDragging(false)}
                            onDrop={handleDrop}
                            className={`flex flex-col items-center justify-center min-h-[180px] px-6 py-8 rounded-lg border border-dashed transition-colors cursor-pointer text-center ${
                              isDragging
                                ? 'border-[#C8A253] bg-[#C8A253]/5'
                                : 'border-slate-700 bg-[#0A0E17]/70 hover:border-slate-500'
                            }`}
                          >
                            <Upload className="w-7 h-7 text-[#C8A253] mb-3" aria-hidden="true" />
                            <span className="text-sm font-medium text-slate-200">
                              {selectedFile ? selectedFile.name : 'Select or drop a source file'}
                            </span>
                            <span className="text-xs text-slate-400 mt-1">
                              Supports .js, .html, .htm, and .php files up to 16 MB
                            </span>
                            {selectedFile && (
                              <span className="mt-2 text-xs font-mono tabular-nums text-[#E6C77E]">
                                {formatBytes(selectedFile.size)} ready for inspection
                              </span>
                            )}
                            <input
                              ref={fileInputRef}
                              id="fileUpload"
                              type="file"
                              className="sr-only"
                              accept=".js,.html,.htm,.php,.mjs,.cjs"
                              onChange={(e) => handleFileSelected(e.target.files?.[0] ?? null)}
                              disabled={loading}
                            />
                          </label>

                          {selectedFile && !loading && (
                            <div className="flex justify-end">
                              <button
                                type="button"
                                onClick={() => {
                                  setSelectedFile(null);
                                  if (fileInputRef.current) fileInputRef.current.value = '';
                                }}
                                className="text-xs text-slate-400 hover:text-slate-200 cursor-pointer"
                              >
                                Clear selected file
                              </button>
                            </div>
                          )}
                        </div>
                      )}

                      {mode === 'url' && (
                        <div className="space-y-2.5">
                          <label
                            htmlFor="remoteUrl"
                            className="block text-xs font-medium text-slate-300"
                          >
                            Target Script or Web Page URL
                          </label>
                          <input
                            id="remoteUrl"
                            type="url"
                            value={urlInput}
                            onChange={(e) => {
                              setUrlInput(e.target.value);
                              setError(null);
                            }}
                            placeholder="https://raw.githubusercontent.com/user/repo/main/app.js"
                            disabled={loading}
                            className="w-full px-4 py-3 text-sm font-mono bg-[#0A0E17] border border-slate-700 rounded-md text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-[#C8A253] disabled:opacity-60"
                          />
                          <p className="text-xs text-slate-400">
                            Fetches remote JavaScript, HTML, or PHP content over HTTPS/HTTP (15s
                            timeout, 16 MB limit).
                          </p>
                        </div>
                      )}

                      {mode === 'paste' && (
                        <div className="space-y-3">
                          <div className="flex items-center justify-between gap-3">
                            <label
                              htmlFor="pastedSource"
                              className="text-xs font-medium text-slate-300"
                            >
                              Source Code Buffer
                            </label>
                            <div className="flex items-center gap-3">
                              <select
                                aria-label="Source language extension"
                                value={snippetFilename}
                                onChange={(e) => setSnippetFilename(e.target.value)}
                                disabled={loading}
                                className="px-2.5 py-1 text-xs font-mono bg-[#0A0E17] border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-[#C8A253]"
                              >
                                <option value="snippet.js">.js</option>
                                <option value="page.html">.html</option>
                                <option value="handler.php">.php</option>
                              </select>
                              <button
                                type="button"
                                disabled={loading}
                                onClick={() => setPastedCode(SAMPLE_VULNERABLE_CODE)}
                                className="text-xs text-[#E6C77E] hover:underline cursor-pointer whitespace-nowrap disabled:opacity-60"
                              >
                                Insert sample
                              </button>
                            </div>
                          </div>
                          <textarea
                            id="pastedSource"
                            rows={8}
                            value={pastedCode}
                            onChange={(e) => {
                              setPastedCode(e.target.value);
                              setError(null);
                            }}
                            placeholder="Paste JavaScript, HTML <script> markup, or PHP code to inspect..."
                            disabled={loading}
                            className="w-full px-4 py-3 text-xs font-mono bg-[#0A0E17] border border-slate-700 rounded-md text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-[#C8A253] leading-relaxed disabled:opacity-60"
                          />
                        </div>
                      )}

                      {/* Live Scan Progress Indicator */}
                      {loading && scanProgress && (
                        <ScanProgressBar progress={scanProgress} byteDetail={uploadByteDetail} />
                      )}

                      <div className="pt-2 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                        <span className="text-xs text-slate-400">
                          Files are analyzed statically in memory and never executed.
                        </span>
                        <button
                          type="submit"
                          disabled={loading}
                          className="inline-flex items-center justify-center gap-2 px-6 py-2.5 text-sm font-semibold text-[#090C12] bg-[#C8A253] rounded-md hover:bg-[#D6B466] transition-colors disabled:opacity-60 whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          {loading ? (
                            <>
                              <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
                              <span>Scanning...</span>
                            </>
                          ) : (
                            <span>Start Scan</span>
                          )}
                        </button>
                      </div>
                    </form>
                  </motion.div>

                  {/* Right Column: Coverage & CWE Rule Matrix */}
                  <aside
                    id="coverage"
                    className="lg:col-span-5 bg-[#111622] border border-slate-800 rounded-lg overflow-hidden"
                  >
                    <div className="px-6 py-5 border-b border-slate-800/80">
                      <h2 className="text-lg font-semibold text-slate-100">Detection Coverage</h2>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Select any rule class to inspect its CWE definition and mitigation standard.
                      </p>
                    </div>

                    <div className="divide-y divide-slate-800/80">
                      {cweEntries.map((entry) => {
                        const isOpen = expandedCwe === entry.id;
                        return (
                          <div key={entry.id}>
                            <button
                              type="button"
                              onClick={() => setExpandedCwe(isOpen ? null : entry.id)}
                              aria-expanded={isOpen}
                              className="w-full px-6 py-4 flex items-center justify-between gap-4 text-left hover:bg-[#161D2D] transition-colors cursor-pointer"
                            >
                              <div className="min-w-0">
                                <div className="text-sm font-medium text-slate-100 truncate">
                                  {entry.name}
                                </div>
                                <div className="flex items-center gap-2 mt-1 text-xs text-slate-400">
                                  <span className="font-mono tabular-nums text-[#E6C77E]">
                                    {entry.id}
                                  </span>
                                  <span aria-hidden="true">&middot;</span>
                                  {entry.severity === 'Critical' ? (
                                    <span className="inline-flex items-center gap-1 text-purple-400 font-medium">
                                      <AlertOctagon className="w-3 h-3" aria-hidden="true" />
                                      <span>Critical</span>
                                    </span>
                                  ) : (
                                    <span className="inline-flex items-center gap-1 text-red-400 font-medium">
                                      <AlertTriangle className="w-3 h-3" aria-hidden="true" />
                                      <span>High</span>
                                    </span>
                                  )}
                                </div>
                              </div>
                              {isOpen ? (
                                <ChevronUp
                                  className="w-4 h-4 text-slate-400 shrink-0"
                                  aria-hidden="true"
                                />
                              ) : (
                                <ChevronDown
                                  className="w-4 h-4 text-slate-400 shrink-0"
                                  aria-hidden="true"
                                />
                              )}
                            </button>

                            {isOpen && (
                              <div className="px-6 pb-4 pt-1 text-xs text-slate-300 space-y-2 bg-[#0D121C]">
                                <p className="text-slate-400 leading-relaxed">
                                  {entry.description}
                                </p>
                                <a
                                  href={entry.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 font-mono text-[#E6C77E] hover:underline"
                                >
                                  <span>MITRE {entry.id} Specification</span>
                                  <ExternalLink className="w-3 h-3" aria-hidden="true" />
                                </a>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </aside>
                </section>

                {/* D3.js Vulnerability Density Heatmap */}
                <VulnerabilityHeatmap
                  reports={historyReports}
                  loading={historyLoading}
                  onSelectReport={handleRecallReport}
                  onRunSampleAudit={handleRunSampleAudit}
                />

                {/* Static Analysis Methodology Section */}
                <section id="methodology" className="pt-8 border-t border-slate-800/80 space-y-6">
                  <div className="max-w-2xl space-y-1.5">
                    <h2 className="font-[family-name:var(--font-display)] text-2xl font-semibold text-slate-100">
                      Static Analysis Methodology
                    </h2>
                    <p className="text-sm text-slate-400">
                      Every scan follows a deterministic three-stage pipeline designed to preserve
                      exact source coordinates without code execution.
                    </p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-8 pt-2">
                    <div className="space-y-2">
                      <h3 className="text-sm font-semibold text-[#E6C77E]">
                        01. Extraction &amp; Normalization
                      </h3>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        HTML <code>&lt;script&gt;</code> blocks, inline DOM event handlers, and
                        embedded scripts inside PHP templates are isolated while preserving line
                        offsets. Minified bundles are formatted before inspection.
                      </p>
                    </div>

                    <div className="space-y-2">
                      <h3 className="text-sm font-semibold text-[#E6C77E]">
                        02. Acorn AST Traversal
                      </h3>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        Extracted code is parsed into an abstract syntax tree supporting ES modules
                        and classic scripts, with tolerant line-level pattern fallback for partial
                        snippets.
                      </p>
                    </div>

                    <div className="space-y-2">
                      <h3 className="text-sm font-semibold text-[#E6C77E]">
                        03. CWE Attribution &amp; Guidance
                      </h3>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        Matched sinks, dynamic queries, command invocations, and embedded
                        credentials are deduplicated, mapped to MITRE CWE definitions, and paired
                        with remediation advice.
                      </p>
                    </div>
                  </div>
                </section>
              </>
            )}
          </div>

          {/* Desktop Sidebar: Quick Actions + Collapsible History Side Panel */}
          <aside
            aria-label="Scanner sidebar"
            className="hidden xl:flex xl:flex-col gap-4 w-[300px] shrink-0 sticky top-24"
          >
            <QuickActionsPanel
              reportCount={historyReports.length}
              historyVisible={showScanHistory}
              onClearHistory={handleClearAllHistory}
              onToggleHistory={() => setShowScanHistory((prev) => !prev)}
              onOpenHelp={() => setHelpDocsOpen(true)}
            />

            {showScanHistory && (
              <ScanHistoryPanel
                reports={historyReports}
                loading={historyLoading}
                storageError={storageError}
                activeReportId={activeReportId}
                onRecall={handleRecallReport}
                onDelete={handleDeleteReport}
                onClearAll={handleClearAllHistory}
                onCollapse={() => setShowScanHistory(false)}
              />
            )}
          </aside>
        </div>
      </main>

      {/* Mobile / Tablet Slide-Over Sidebar Drawer */}
      {mobileSidebarOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Scanner Sidebar"
          className="xl:hidden fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-xs"
          onClick={() => setMobileSidebarOpen(false)}
        >
          <div
            className="w-full max-w-sm h-full bg-[#0A0E17] border-l border-slate-800 p-4 overflow-y-auto space-y-4"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between gap-3 pb-2 border-b border-slate-800/80">
              <span className="text-xs font-semibold tracking-wide uppercase text-slate-300">
                Workspace Sidebar
              </span>
              <button
                type="button"
                onClick={() => setMobileSidebarOpen(false)}
                aria-label="Close sidebar"
                className="p-1.5 rounded-md text-slate-400 hover:text-slate-100 hover:bg-slate-800/70 transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" aria-hidden="true" />
              </button>
            </div>

            <QuickActionsPanel
              reportCount={historyReports.length}
              historyVisible={showScanHistory}
              onClearHistory={handleClearAllHistory}
              onToggleHistory={() => setShowScanHistory((prev) => !prev)}
              onOpenHelp={() => {
                setMobileSidebarOpen(false);
                setHelpDocsOpen(true);
              }}
            />

            {showScanHistory && (
              <ScanHistoryPanel
                reports={historyReports}
                loading={historyLoading}
                storageError={storageError}
                activeReportId={activeReportId}
                onRecall={handleRecallReport}
                onDelete={handleDeleteReport}
                onClearAll={handleClearAllHistory}
                onCollapse={() => setShowScanHistory(false)}
              />
            )}
          </div>
        </div>
      )}

      <HelpDocumentationModal
        open={helpDocsOpen}
        cweEntries={cweEntries}
        onClose={() => setHelpDocsOpen(false)}
      />

      {/* Clean Quiet Footer — no group member or institution text */}
      <footer className="border-t border-slate-800/80 py-6 mt-auto">
        <div className="max-w-[1440px] mx-auto px-4 sm:px-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-500">
          <span>&copy; 2026 Static Vulnerability Scanning Tool</span>
          <span>OWASP &amp; MITRE CWE Reference Mapping &middot; MIT License</span>
        </div>
      </footer>
    </>
  );
}
