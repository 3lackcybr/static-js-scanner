'use client';

import { useEffect, useMemo, useState } from 'react';
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import { AlertOctagon, AlertTriangle, Info, PieChart as PieChartIcon, ShieldAlert } from 'lucide-react';
import type { ScanSummary, Severity } from '@/scanner/types';

interface SeverityPieChartProps {
  summary: ScanSummary;
  selectedSeverities: Severity[];
  onToggleSeverity: (severity: Severity) => void;
}

interface SeveritySlice {
  name: Severity;
  value: number;
  percent: number;
  color: string;
  textClass: string;
}

const SEVERITY_CONFIG: Array<{
  level: Severity;
  color: string;
  textClass: string;
}> = [
  { level: 'Critical', color: '#EF4444', textClass: 'text-red-400' },
  { level: 'High', color: '#F59E0B', textClass: 'text-amber-400' },
  { level: 'Medium', color: '#38BDF8', textClass: 'text-sky-400' },
  { level: 'Low', color: '#94A3B8', textClass: 'text-slate-400' },
];

function getCount(summary: ScanSummary, level: Severity): number {
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

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: SeveritySlice }>;
}

function SeverityTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload || payload.length === 0) return null;
  const item = payload[0].payload;
  return (
    <div className="bg-[#090C12] border border-[#C8A253]/50 rounded-md px-3 py-2 text-xs shadow-lg">
      <div className={`font-semibold ${item.textClass}`}>{item.name} Severity</div>
      <div className="mt-1 font-mono tabular-nums text-slate-200">
        {item.value} finding{item.value === 1 ? '' : 's'} &middot; {item.percent.toFixed(1)}%
      </div>
    </div>
  );
}

export default function SeverityPieChart({
  summary,
  selectedSeverities,
  onToggleSeverity,
}: SeverityPieChartProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const total = Math.max(0, summary.total);

  const allSlices = useMemo<SeveritySlice[]>(() => {
    return SEVERITY_CONFIG.map(({ level, color, textClass }) => {
      const value = getCount(summary, level);
      const percent = total > 0 ? (value / total) * 100 : 0;
      return {
        name: level,
        value,
        percent,
        color,
        textClass,
      };
    });
  }, [summary, total]);

  const chartData = useMemo(
    () => allSlices.filter((slice) => slice.value > 0),
    [allSlices]
  );

  // Also summarize High / Medium / Low rows explicitly (plus Critical when present)
  const legendRows = useMemo(
    () =>
      allSlices.filter(
        (slice) => slice.name !== 'Critical' || slice.value > 0
      ),
    [allSlices]
  );

  return (
    <section
      aria-label="Vulnerability severity distribution chart"
      className="bg-[#111622] border border-slate-800 rounded-lg p-6"
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <PieChartIcon className="w-4 h-4 text-[#C8A253]" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-slate-100">
            Severity Breakdown
          </h2>
        </div>
        <span className="text-xs text-slate-400">
          Click a slice or row to filter findings below
        </span>
      </div>

      <div className="pt-5 grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
        {/* Recharts Pie Chart */}
        <div className="md:col-span-5 relative h-[220px] flex items-center justify-center">
          {mounted && chartData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={chartData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={56}
                    outerRadius={84}
                    paddingAngle={chartData.length > 1 ? 3 : 0}
                    stroke="#111622"
                    strokeWidth={2}
                    onClick={(_, index) => {
                      const target = chartData[index];
                      if (target) onToggleSeverity(target.name);
                    }}
                    className="cursor-pointer focus:outline-none"
                  >
                    {chartData.map((entry) => {
                      const dimmed =
                        selectedSeverities.length > 0 &&
                        !selectedSeverities.includes(entry.name);
                      return (
                        <Cell
                          key={entry.name}
                          fill={entry.color}
                          fillOpacity={dimmed ? 0.3 : 1}
                        />
                      );
                    })}
                  </Pie>
                  <Tooltip content={<SeverityTooltip />} />
                </PieChart>
              </ResponsiveContainer>

              <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-2xl font-semibold font-mono tabular-nums text-slate-100">
                  {total}
                </span>
                <span className="text-[11px] text-slate-400">
                  Finding{total === 1 ? '' : 's'}
                </span>
              </div>
            </>
          ) : (
            <div className="h-[220px] w-[220px] rounded-full border border-slate-800 bg-[#0A0E17]/60 flex flex-col items-center justify-center">
              <span className="text-xl font-mono tabular-nums text-slate-300">{total}</span>
              <span className="text-xs text-slate-500">Findings</span>
            </div>
          )}
        </div>

        {/* Interactive Breakdown Table */}
        <div className="md:col-span-7 divide-y divide-slate-800/80 border border-slate-800/80 rounded-md overflow-hidden">
          {legendRows.map((row) => {
            const isSelected = selectedSeverities.includes(row.name);
            return (
              <button
                key={row.name}
                type="button"
                aria-pressed={isSelected}
                onClick={() => onToggleSeverity(row.name)}
                className={`w-full px-4 py-3 flex items-center justify-between gap-4 text-left transition-colors cursor-pointer ${
                  isSelected ? 'bg-[#182032]' : 'bg-[#0D121C] hover:bg-[#151C2B]'
                }`}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <span
                    className="w-2.5 h-2.5 rounded-xs shrink-0"
                    style={{ backgroundColor: row.color }}
                    aria-hidden="true"
                  />
                  <LevelIcon level={row.name} className={`w-3.5 h-3.5 shrink-0 ${row.textClass}`} />
                  <span className="text-xs font-medium text-slate-100">{row.name}</span>
                </div>

                <div className="flex items-center gap-4 text-xs font-mono tabular-nums shrink-0">
                  <span className="text-slate-200 font-semibold">{row.value}</span>
                  <span className="text-slate-400 w-14 text-right">
                    {row.percent.toFixed(1)}%
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </section>
  );
}
