import type { Severity } from '@/scanner/types';

export interface SeverityStyleMeta {
  level: Severity;
  label: Severity;
  badgeClass: string;
  cardAccentClass: string;
  textClass: string;
  filterActiveClass: string;
  hex: string;
  heatmapMinHex: string;
}

export const SEVERITY_STYLES: Record<Severity, SeverityStyleMeta> = {
  Critical: {
    level: 'Critical',
    label: 'Critical',
    badgeClass: 'bg-purple-950/70 text-purple-200 border-purple-500/55',
    cardAccentClass: 'border-l-purple-500',
    textClass: 'text-purple-400',
    filterActiveClass: 'bg-purple-950/60 text-purple-200 border-purple-500/50',
    hex: '#A855F7',
    heatmapMinHex: '#581C87',
  },
  High: {
    level: 'High',
    label: 'High',
    badgeClass: 'bg-red-950/60 text-red-300 border-red-500/50',
    cardAccentClass: 'border-l-red-500',
    textClass: 'text-red-400',
    filterActiveClass: 'bg-red-950/50 text-red-300 border-red-500/45',
    hex: '#EF4444',
    heatmapMinHex: '#7F1D1D',
  },
  Medium: {
    level: 'Medium',
    label: 'Medium',
    badgeClass: 'bg-amber-950/60 text-amber-300 border-amber-500/50',
    cardAccentClass: 'border-l-amber-500',
    textClass: 'text-amber-400',
    filterActiveClass: 'bg-amber-950/50 text-amber-300 border-amber-500/45',
    hex: '#F59E0B',
    heatmapMinHex: '#78350F',
  },
  Low: {
    level: 'Low',
    label: 'Low',
    badgeClass: 'bg-blue-950/60 text-blue-300 border-blue-500/50',
    cardAccentClass: 'border-l-blue-500',
    textClass: 'text-blue-400',
    filterActiveClass: 'bg-blue-950/50 text-blue-300 border-blue-500/45',
    hex: '#3B82F6',
    heatmapMinHex: '#1E3A8A',
  },
};

export const SEVERITY_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low'];

export function getSeverityStyle(severity: Severity): SeverityStyleMeta {
  return SEVERITY_STYLES[severity];
}
