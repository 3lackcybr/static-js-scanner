'use client';

import { useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Clock,
  PanelRightClose,
  Trash2,
} from 'lucide-react';
import type { StoredScanReport } from '@/lib/scanHistoryDb';

interface ScanHistoryPanelProps {
  reports: StoredScanReport[];
  loading: boolean;
  storageError: string | null;
  activeReportId: string | null;
  onRecall: (report: StoredScanReport) => void;
  onDelete: (id: string) => void;
  onClearAll: () => void;
  onCollapse?: () => void;
}

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export default function ScanHistoryPanel({
  reports,
  loading,
  storageError,
  activeReportId,
  onRecall,
  onDelete,
  onClearAll,
  onCollapse,
}: ScanHistoryPanelProps) {
  const [confirmClear, setConfirmClear] = useState(false);

  return (
    <div className="bg-[#111622] border border-slate-800 rounded-lg flex flex-col overflow-hidden">
      <div className="px-5 py-4 border-b border-slate-800/80 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <Clock className="w-4 h-4 text-[#C8A253] shrink-0" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-slate-100 truncate">Scan History</h2>
          <span className="text-xs font-mono tabular-nums text-slate-400">
            ({reports.length})
          </span>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {reports.length > 0 && !confirmClear && (
            <button
              type="button"
              onClick={() => setConfirmClear(true)}
              className="text-xs text-slate-400 hover:text-red-300 transition-colors whitespace-nowrap cursor-pointer"
            >
              Clear All
            </button>
          )}
          {reports.length > 0 && confirmClear && (
            <div className="flex items-center gap-2 text-xs">
              <button
                type="button"
                onClick={() => {
                  setConfirmClear(false);
                  onClearAll();
                }}
                className="font-semibold text-red-400 hover:text-red-300 cursor-pointer whitespace-nowrap"
              >
                Confirm
              </button>
              <button
                type="button"
                onClick={() => setConfirmClear(false)}
                className="text-slate-400 hover:text-slate-200 cursor-pointer whitespace-nowrap"
              >
                Cancel
              </button>
            </div>
          )}
          {onCollapse && (
            <button
              type="button"
              onClick={onCollapse}
              aria-label="Hide scan history panel"
              title="Hide scan history"
              className="p-1 text-slate-400 hover:text-slate-100 transition-colors cursor-pointer"
            >
              <PanelRightClose className="w-4 h-4" aria-hidden="true" />
            </button>
          )}
        </div>
      </div>

      {storageError && (
        <div className="px-5 py-3 bg-amber-950/30 border-b border-amber-500/30 text-xs text-amber-300">
          {storageError}
        </div>
      )}

      {loading ? (
        <div className="p-5 space-y-3" aria-busy="true">
          <div className="h-14 rounded bg-[#0A0E17] border border-slate-800/70 animate-pulse" />
          <div className="h-14 rounded bg-[#0A0E17] border border-slate-800/70 animate-pulse" />
          <div className="h-14 rounded bg-[#0A0E17] border border-slate-800/70 animate-pulse" />
        </div>
      ) : reports.length === 0 ? (
        <div className="p-6 text-center space-y-1.5">
          <p className="text-xs font-medium text-slate-300">No stored reports yet</p>
          <p className="text-xs text-slate-500 leading-relaxed">
            Completed scans are saved locally in your browser via IndexedDB for instant recall.
          </p>
        </div>
      ) : (
        <ul className="divide-y divide-slate-800/80 max-h-[400px] overflow-y-auto">
          {reports.map((entry) => {
            const { result } = entry;
            const isActive = activeReportId === entry.id;
            const total = result.summary.total;
            const hasCritical = result.summary.critical > 0;
            const hasHigh = result.summary.high > 0;

            return (
              <li key={entry.id}>
                <div
                  className={`group flex items-start justify-between gap-2 px-5 py-3.5 transition-colors ${
                    isActive
                      ? 'bg-[#182032] border-y border-[#C8A253]/25'
                      : 'hover:bg-[#151C2B]'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => onRecall(entry)}
                    className="flex-1 min-w-0 text-left cursor-pointer focus:outline-none"
                  >
                    <div
                      className={`text-xs font-medium truncate ${
                        isActive ? 'text-[#E6C77E]' : 'text-slate-100 group-hover:text-white'
                      }`}
                      title={result.target}
                    >
                      {result.target}
                    </div>

                    <div className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-slate-400">
                      {total === 0 ? (
                        <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
                          <CheckCircle2 className="w-3 h-3" aria-hidden="true" />
                          <span>Clean (0)</span>
                        </span>
                      ) : hasCritical ? (
                        <span className="inline-flex items-center gap-1 text-red-400 font-medium font-mono tabular-nums">
                          <AlertOctagon className="w-3 h-3" aria-hidden="true" />
                          <span>{total} findings</span>
                        </span>
                      ) : hasHigh ? (
                        <span className="inline-flex items-center gap-1 text-amber-400 font-medium font-mono tabular-nums">
                          <AlertTriangle className="w-3 h-3" aria-hidden="true" />
                          <span>{total} findings</span>
                        </span>
                      ) : (
                        <span className="font-mono tabular-nums">{total} findings</span>
                      )}

                      <span aria-hidden="true">&middot;</span>
                      <span className="font-mono">.{result.fileKind}</span>
                      <span aria-hidden="true">&middot;</span>
                      <span className="font-mono tabular-nums">
                        {formatTimestamp(entry.scannedAt)}
                      </span>
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      onDelete(entry.id);
                    }}
                    aria-label={`Delete report for ${result.target}`}
                    title="Delete report"
                    className="p-1.5 text-slate-500 hover:text-red-400 transition-colors shrink-0 cursor-pointer"
                  >
                    <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
