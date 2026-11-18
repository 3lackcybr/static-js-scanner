'use client';

import { useState } from 'react';
import { BookOpen, Eye, EyeOff, Trash2, Zap } from 'lucide-react';

interface QuickActionsPanelProps {
  reportCount: number;
  historyVisible: boolean;
  onClearHistory: () => void;
  onToggleHistory: () => void;
  onOpenHelp: () => void;
}

export default function QuickActionsPanel({
  reportCount,
  historyVisible,
  onClearHistory,
  onToggleHistory,
  onOpenHelp,
}: QuickActionsPanelProps) {
  const [confirmClear, setConfirmClear] = useState(false);

  const hasReports = reportCount > 0;

  return (
    <section
      aria-label="Quick Actions"
      className="bg-[#111622] border border-slate-800 rounded-lg overflow-hidden"
    >
      <div className="px-5 py-4 border-b border-slate-800/80 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <Zap className="w-4 h-4 text-[#C8A253] shrink-0" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-slate-100 truncate">Quick Actions</h2>
        </div>
        <span className="text-[11px] font-mono tabular-nums text-slate-500">
          {reportCount} saved
        </span>
      </div>

      <div className="p-4 space-y-2.5">
        {/* Toggle Scan History Display */}
        <button
          type="button"
          onClick={onToggleHistory}
          aria-pressed={historyVisible}
          className="w-full flex items-center justify-between gap-3 px-3.5 py-2.5 text-xs font-medium rounded-md bg-[#0A0E17] border border-slate-800 text-slate-200 hover:border-[#C8A253]/50 hover:text-[#E6C77E] transition-colors cursor-pointer"
        >
          <span className="flex items-center gap-2.5 min-w-0">
            {historyVisible ? (
              <EyeOff className="w-3.5 h-3.5 text-[#C8A253] shrink-0" aria-hidden="true" />
            ) : (
              <Eye className="w-3.5 h-3.5 text-[#C8A253] shrink-0" aria-hidden="true" />
            )}
            <span className="truncate">
              {historyVisible ? 'Hide Scan History' : 'Show Scan History'}
            </span>
          </span>
          <span className="text-[11px] font-mono tabular-nums text-slate-400 shrink-0">
            {historyVisible ? 'Visible' : 'Hidden'}
          </span>
        </button>

        {/* Open Help Documentation */}
        <button
          type="button"
          onClick={onOpenHelp}
          className="w-full flex items-center justify-between gap-3 px-3.5 py-2.5 text-xs font-medium rounded-md bg-[#0A0E17] border border-slate-800 text-slate-200 hover:border-[#C8A253]/50 hover:text-[#E6C77E] transition-colors cursor-pointer"
        >
          <span className="flex items-center gap-2.5 min-w-0">
            <BookOpen className="w-3.5 h-3.5 text-[#C8A253] shrink-0" aria-hidden="true" />
            <span className="truncate">Help Documentation</span>
          </span>
          <span className="text-[11px] font-mono text-slate-400 shrink-0">Guide</span>
        </button>

        {/* Clear All Historical Results */}
        {!confirmClear || !hasReports ? (
          <button
            type="button"
            disabled={!hasReports}
            onClick={() => setConfirmClear(true)}
            className="w-full flex items-center justify-between gap-3 px-3.5 py-2.5 text-xs font-medium rounded-md bg-[#0A0E17] border border-slate-800 text-slate-200 hover:border-red-500/50 hover:text-red-300 transition-colors disabled:opacity-45 disabled:hover:border-slate-800 disabled:hover:text-slate-200 disabled:cursor-not-allowed cursor-pointer"
          >
            <span className="flex items-center gap-2.5 min-w-0">
              <Trash2 className="w-3.5 h-3.5 text-red-400 shrink-0" aria-hidden="true" />
              <span className="truncate">Clear Historical Results</span>
            </span>
            <span className="text-[11px] font-mono tabular-nums text-slate-400 shrink-0">
              ({reportCount})
            </span>
          </button>
        ) : (
          <div className="p-3 rounded-md bg-red-950/25 border border-red-500/40 space-y-2.5">
            <p className="text-[11px] text-red-200 leading-relaxed">
              Remove all {reportCount} saved scan {reportCount === 1 ? 'report' : 'reports'} from
              local browser storage?
            </p>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  setConfirmClear(false);
                  onClearHistory();
                }}
                className="flex-1 px-2.5 py-1.5 text-xs font-semibold rounded bg-red-500/90 text-white hover:bg-red-500 transition-colors cursor-pointer"
              >
                Confirm Clear
              </button>
              <button
                type="button"
                onClick={() => setConfirmClear(false)}
                className="flex-1 px-2.5 py-1.5 text-xs font-medium rounded bg-[#0A0E17] border border-slate-700 text-slate-300 hover:text-white transition-colors cursor-pointer"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}
