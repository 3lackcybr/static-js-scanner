'use client';

import { useMemo } from 'react';
import { Search, X } from 'lucide-react';
import { extractDetectedCweChips } from '@/lib/findingsFilter';
import type { Vulnerability } from '@/scanner/types';

interface ResultsSearchBarProps {
  query: string;
  onQueryChange: (next: string) => void;
  vulnerabilities: Vulnerability[];
  matchCount: number;
}

export default function ResultsSearchBar({
  query,
  onQueryChange,
  vulnerabilities,
  matchCount,
}: ResultsSearchBarProps) {
  const cweChips = useMemo(() => extractDetectedCweChips(vulnerabilities), [vulnerabilities]);
  const totalCount = vulnerabilities.length;
  const hasQuery = query.trim().length > 0;

  return (
    <section
      aria-label="Search scan results"
      className="bg-[#111622] border border-slate-800 rounded-lg p-4 sm:p-5 space-y-3"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <label
          htmlFor="scan-results-search"
          className="text-xs font-semibold text-slate-200 tracking-wide"
        >
          Lookup CWE Identifier or Vulnerability Type
        </label>
        <span className="text-xs font-mono tabular-nums text-slate-400">
          {totalCount === 0
            ? '0 findings in report'
            : `Showing ${matchCount} of ${totalCount} finding${totalCount === 1 ? '' : 's'}`}
        </span>
      </div>

      <div className="relative">
        <Search
          className="w-4 h-4 text-[#C8A253] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"
          aria-hidden="true"
        />
        <input
          id="scan-results-search"
          type="text"
          role="searchbox"
          value={query}
          disabled={totalCount === 0}
          onChange={(e) => onQueryChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape' && hasQuery) {
              onQueryChange('');
            }
          }}
          placeholder="Search by CWE ID (e.g. CWE-89, 79) or vulnerability type (e.g. SQL Injection, XSS)..."
          aria-label="Search scan results by CWE identifier or vulnerability type"
          className="w-full pl-10 pr-10 py-2.5 text-xs sm:text-sm bg-[#090C12] border border-slate-700/80 rounded-md text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-[#C8A253] disabled:opacity-50"
        />
        {hasQuery && (
          <button
            type="button"
            onClick={() => onQueryChange('')}
            aria-label="Clear search query"
            className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800/70 transition-colors cursor-pointer"
          >
            <X className="w-3.5 h-3.5" aria-hidden="true" />
          </button>
        )}
      </div>

      {cweChips.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
          <span className="text-[11px] text-slate-500 mr-1">Quick lookup:</span>
          {cweChips.map((chip) => {
            const isSelected = query.trim().toLowerCase() === chip.cweId.toLowerCase();
            return (
              <button
                key={chip.cweId}
                type="button"
                aria-pressed={isSelected}
                onClick={() => onQueryChange(isSelected ? '' : chip.cweId)}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-mono border transition-colors cursor-pointer ${
                  isSelected
                    ? 'bg-[#1D2538] text-[#E6C77E] border-[#C8A253]/50'
                    : 'bg-[#0A0E17] text-slate-300 border-slate-800 hover:border-[#C8A253]/40 hover:text-[#E6C77E]'
                }`}
              >
                <span>{chip.cweId}</span>
                <span className="text-slate-500">&middot;</span>
                <span className="font-sans">{chip.type}</span>
                <span className="text-slate-500">({chip.count})</span>
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}
