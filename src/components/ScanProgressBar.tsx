'use client';

import { motion } from 'motion/react';
import { Loader2 } from 'lucide-react';
import type { ScanProgressEvent, ScanProgressStage } from '@/scanner/types';

interface ScanProgressBarProps {
  progress: ScanProgressEvent;
  byteDetail?: string | null;
}

const STAGE_ORDER: Array<{ key: ScanProgressStage; label: string }> = [
  { key: 'uploading', label: 'Transfer' },
  { key: 'extracting', label: 'Extract' },
  { key: 'parsing', label: 'AST Parse' },
  { key: 'analyzing', label: 'CWE Rules' },
  { key: 'finalizing', label: 'Report' },
];

function stageIndex(stage: ScanProgressStage): number {
  if (stage === 'fetching') return 0;
  const idx = STAGE_ORDER.findIndex((s) => s.key === stage);
  return idx >= 0 ? idx : 0;
}

export default function ScanProgressBar({ progress, byteDetail }: ScanProgressBarProps) {
  const clamped = Math.max(2, Math.min(100, Math.round(progress.percent)));
  const currentIdx = stageIndex(progress.stage);

  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.16, ease: [0.16, 1, 0.3, 1] }}
      className="bg-[#0A0E17] border border-slate-800 rounded-md p-4 space-y-3"
      aria-live="polite"
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <Loader2 className="w-4 h-4 text-[#C8A253] animate-spin shrink-0" aria-hidden="true" />
          <span className="text-xs font-medium text-slate-200 truncate">{progress.label}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0 text-xs font-mono tabular-nums">
          {byteDetail && <span className="text-slate-400 hidden sm:inline">{byteDetail}</span>}
          <span className="text-[#E6C77E] font-semibold">{clamped}%</span>
        </div>
      </div>

      {/* GPU compositor-animated progress track */}
      <div
        role="progressbar"
        aria-label="Vulnerability scan progress"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={clamped}
        className="h-2 w-full rounded-full bg-slate-800/90 overflow-hidden"
      >
        <motion.div
          className="h-full w-full rounded-full bg-gradient-to-r from-[#9F7D34] via-[#C8A253] to-[#E6C77E]"
          style={{ transformOrigin: 'left center' }}
          initial={{ scaleX: 0.04 }}
          animate={{ scaleX: clamped / 100 }}
          transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
        />
      </div>

      {/* Unboxed stage breadcrumbs */}
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-slate-500">
        {STAGE_ORDER.map((step, idx) => {
          const isCurrent = idx === currentIdx;
          const isDone = idx < currentIdx;
          return (
            <span key={step.key} className="inline-flex items-center gap-2">
              {idx > 0 && (
                <span className="text-slate-700" aria-hidden="true">
                  &middot;
                </span>
              )}
              <span
                className={
                  isCurrent
                    ? 'text-[#E6C77E] font-semibold'
                    : isDone
                    ? 'text-emerald-400'
                    : 'text-slate-500'
                }
              >
                {step.label}
              </span>
            </span>
          );
        })}
      </div>
    </motion.div>
  );
}
