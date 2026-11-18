'use client';

import { AlertOctagon, AlertTriangle, Info, ShieldAlert } from 'lucide-react';
import type { ScanSummary, Severity } from '@/scanner/types';

interface SeverityFilterProps {
  summary: ScanSummary;
  selectedSeverities: Severity[];
  onToggleSeverity: (severity: Severity) => void;
  onSelectAll: () => void;
}

const SEVERITY_OPTIONS: Array<{
  level: Severity;
  activeClass: string;
  iconClass: string;
}> = [
  {
    level: 'Critical',
    activeClass: 'bg-red-950/50 text-red-300 border-red-500/40',
    iconClass: 'text-red-400',
  },
  {
    level: 'High',
    activeClass: 'bg-amber-950/50 text-amber-300 border-amber-500/40',
    iconClass: 'text-amber-400',
  },
  {
    level: 'Medium',
    activeClass: 'bg-sky-950/50 text-sky-300 border-sky-500/40',
    iconClass: 'text-sky-400',
  },
  {
    level: 'Low',
    activeClass: 'bg-slate-800 text-slate-200 border-slate-600',
    iconClass: 'text-slate-400',
  },
];

function getSeverityCount(summary: ScanSummary, level: Severity): number {
  switch (level) {
    case 'Critical':
      return summary.critical;
    case 'High':
      return summary.high;
    case 'Medium':
      return summary.medium;
    case 'Low':
      return summary.low;
  }
}

function LevelIcon({ level, className }: { level: Severity; className: string }) {
  if (level === 'Critical') return <AlertOctagon className={className} aria-hidden="true" />;
  if (level === 'High') return <AlertTriangle className={className} aria-hidden="true" />;
  if (level === 'Medium') return <ShieldAlert className={className} aria-hidden="true" />;
  return <Info className={className} aria-hidden="true" />;
}

export default function SeverityFilter({
  summary,
  selectedSeverities,
  onToggleSeverity,
  onSelectAll,
}: SeverityFilterProps) {
  const isAllActive = selectedSeverities.length === 0;

  return (
    <div
      role="group"
      aria-label="Filter findings by severity"
      className="flex flex-wrap items-center gap-1 p-1 bg-[#111622] border border-slate-800 rounded-md self-start"
    >
      <button
        type="button"
        aria-pressed={isAllActive}
        onClick={onSelectAll}
        className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer border ${
          isAllActive
            ? 'bg-[#1D2538] text-[#E6C77E] border-[#C8A253]/30'
            : 'text-slate-400 hover:text-slate-200 border-transparent'
        }`}
      >
        <span className="font-mono tabular-nums">All ({summary.total})</span>
      </button>

      {SEVERITY_OPTIONS.map(({ level, activeClass, iconClass }) => {
        const isActive = selectedSeverities.includes(level);
        const count = getSeverityCount(summary, level);

        return (
          <button
            key={level}
            type="button"
            aria-pressed={isActive}
            onClick={() => onToggleSeverity(level)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer border ${
              isActive
                ? activeClass
                : 'text-slate-400 hover:text-slate-200 border-transparent'
            }`}
          >
            <LevelIcon
              level={level}
              className={`w-3.5 h-3.5 ${isActive ? iconClass : 'text-slate-500'}`}
            />
            <span>{level}</span>
            <span className="font-mono tabular-nums">({count})</span>
          </button>
        );
      })}
    </div>
  );
}
