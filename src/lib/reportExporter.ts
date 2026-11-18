import { jsPDF } from 'jspdf';
import type { ScanResult, Severity } from '@/scanner/types';

function sanitizeFilenameSegment(target: string): string {
  const base = target
    .replace(/^https?:\/\//i, '')
    .replace(/[^a-zA-Z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
  return base || 'scan';
}

function buildFilename(result: ScanResult, ext: 'json' | 'pdf'): string {
  const datePart = new Date(result.scannedAt || Date.now())
    .toISOString()
    .slice(0, 10);
  return `vulnerability-report-${sanitizeFilenameSegment(result.target)}-${datePart}.${ext}`;
}

export function exportReportAsJson(result: ScanResult): void {
  const archivePayload = {
    tool: 'Static Vulnerability Scanning Tool',
    exportedAt: new Date().toISOString(),
    ...result,
  };

  const blob = new Blob([JSON.stringify(archivePayload, null, 2)], {
    type: 'application/json',
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = buildFilename(result, 'json');
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function severityRgb(severity: Severity): [number, number, number] {
  switch (severity) {
    case 'Critical':
      return [185, 28, 28]; // crimson
    case 'High':
      return [180, 83, 9]; // amber
    case 'Medium':
      return [3, 105, 161]; // steel blue
    default:
      return [71, 85, 105]; // slate
  }
}

export function exportReportAsPdf(result: ScanResult): void {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'pt',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 42;
  const contentWidth = pageWidth - margin * 2;
  let y = 0;

  const ensureSpace = (needed: number) => {
    if (y + needed > pageHeight - 54) {
      doc.addPage();
      y = 48;
    }
  };

  // Top Header Band
  doc.setFillColor(12, 17, 29);
  doc.rect(0, 0, pageWidth, 108, 'F');

  // Burnished gold accent line
  doc.setFillColor(200, 162, 83);
  doc.rect(0, 108, pageWidth, 3, 'F');

  doc.setTextColor(200, 162, 83);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.text('STATIC VULNERABILITY SCANNING TOOL', margin, 32);

  doc.setTextColor(241, 245, 249);
  doc.setFont('times', 'bold');
  doc.setFontSize(20);
  doc.text('Security Audit Report', margin, 56);

  doc.setTextColor(148, 163, 184);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  const targetLine = doc.splitTextToSize(
    `Target: ${result.target}   |   Source: ${result.sourceType.toUpperCase()} (.${result.fileKind})   |   Scanned: ${new Date(
      result.scannedAt
    ).toLocaleString()}`,
    contentWidth
  );
  doc.text(targetLine, margin, 76);

  y = 132;

  // Executive Summary Grid (4 columns)
  const boxGap = 10;
  const boxWidth = (contentWidth - boxGap * 3) / 4;
  const summaryCards: Array<{
    label: string;
    value: string;
    color: [number, number, number];
  }> = [
    {
      label: 'TOTAL FINDINGS',
      value: String(result.summary.total),
      color: [15, 23, 42],
    },
    {
      label: 'CRITICAL',
      value: String(result.summary.critical),
      color: [185, 28, 28],
    },
    {
      label: 'HIGH',
      value: String(result.summary.high),
      color: [180, 83, 9],
    },
    {
      label: 'LINES ANALYZED',
      value: `${result.linesAnalyzed} (${result.scriptsExtracted})`,
      color: [51, 65, 85],
    },
  ];

  summaryCards.forEach((card, idx) => {
    const x = margin + idx * (boxWidth + boxGap);
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(x, y, boxWidth, 54, 4, 4, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text(card.label, x + 10, y + 18);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(15);
    doc.setTextColor(...card.color);
    doc.text(card.value, x + 10, y + 40);
  });

  y += 74;

  // Optional notices
  if (result.beautified || result.parseWarnings.length > 0) {
    const noticeText = [
      result.beautified ? 'Minified JavaScript was formatted for line attribution.' : null,
      result.parseWarnings.length > 0
        ? `Parser notices: ${result.parseWarnings.join(' | ')}`
        : null,
    ]
      .filter(Boolean)
      .join(' ');
    const noticeLines = doc.splitTextToSize(noticeText, contentWidth - 20);
    const noticeHeight = noticeLines.length * 12 + 18;
    ensureSpace(noticeHeight + 12);

    doc.setFillColor(255, 251, 235);
    doc.setDrawColor(253, 230, 138);
    doc.roundedRect(margin, y, contentWidth, noticeHeight, 4, 4, 'FD');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.setTextColor(146, 64, 14);
    doc.text(noticeLines, margin + 10, y + 15);
    y += noticeHeight + 16;
  }

  // Findings Section Title
  doc.setFont('times', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(15, 23, 42);
  doc.text('Detailed Security Findings', margin, y);
  y += 8;
  doc.setDrawColor(203, 213, 225);
  doc.line(margin, y, pageWidth - margin, y);
  y += 16;

  if (result.vulnerabilities.length === 0) {
    ensureSpace(72);
    doc.setFillColor(236, 253, 245);
    doc.setDrawColor(167, 243, 208);
    doc.roundedRect(margin, y, contentWidth, 64, 4, 4, 'FD');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(6, 95, 70);
    doc.text('No Vulnerabilities Detected', margin + 14, y + 24);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.text(
      `Static analysis scanned ${result.linesAnalyzed} line(s) across ${result.scriptsExtracted} extracted script block(s) with zero matches.`,
      margin + 14,
      y + 42
    );
  } else {
    result.vulnerabilities.forEach((vuln, index) => {
      const innerWidth = contentWidth - 24;
      const snippetLines = vuln.snippet
        ? doc.splitTextToSize(vuln.snippet, innerWidth - 16)
        : [];
      const riskLines = doc.splitTextToSize(vuln.description, innerWidth);
      const remLines = doc.splitTextToSize(vuln.remediation, innerWidth);

      const snippetBoxHeight = snippetLines.length > 0 ? snippetLines.length * 11 + 14 : 0;
      const cardHeight =
        34 +
        (snippetBoxHeight > 0 ? snippetBoxHeight + 10 : 0) +
        14 +
        riskLines.length * 11.5 +
        18 +
        remLines.length * 11.5 +
        14;

      ensureSpace(cardHeight + 12);

      // Card container
      doc.setFillColor(255, 255, 255);
      doc.setDrawColor(203, 213, 225);
      doc.roundedRect(margin, y, contentWidth, cardHeight, 4, 4, 'FD');

      // Card header row
      const [sr, sg, sb] = severityRgb(vuln.severity);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(9);
      doc.setTextColor(sr, sg, sb);
      doc.text(`${vuln.severity.toUpperCase()}`, margin + 12, y + 19);

      doc.setTextColor(15, 23, 42);
      doc.setFontSize(10.5);
      doc.text(`${index + 1}. ${vuln.type} (${vuln.cweId})`, margin + 68, y + 19);

      doc.setFont('courier', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(100, 116, 139);
      const locationText = `Line ${vuln.line}, Col ${vuln.column}`;
      doc.text(locationText, pageWidth - margin - 12, y + 19, { align: 'right' });

      doc.setDrawColor(226, 232, 240);
      doc.line(margin, y + 28, pageWidth - margin, y + 28);

      let cursorY = y + 40;

      if (snippetLines.length > 0) {
        doc.setFillColor(241, 245, 249);
        doc.setDrawColor(226, 232, 240);
        doc.roundedRect(margin + 12, cursorY - 10, innerWidth, snippetBoxHeight, 3, 3, 'FD');
        doc.setFont('courier', 'normal');
        doc.setFontSize(8.5);
        doc.setTextColor(15, 23, 42);
        doc.text(snippetLines, margin + 20, cursorY + 3);
        cursorY += snippetBoxHeight + 6;
      }

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(71, 85, 105);
      doc.text('Risk Analysis', margin + 12, cursorY);
      cursorY += 12;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.setTextColor(30, 41, 59);
      doc.text(riskLines, margin + 12, cursorY);
      cursorY += riskLines.length * 11.5 + 8;

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8.5);
      doc.setTextColor(6, 95, 70);
      doc.text('Remediation Guidance', margin + 12, cursorY);
      cursorY += 12;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.setTextColor(30, 41, 59);
      doc.text(remLines, margin + 12, cursorY);

      y += cardHeight + 12;
    });
  }

  // Page Footer across all pages
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i += 1) {
    doc.setPage(i);
    doc.setDrawColor(226, 232, 240);
    doc.line(margin, pageHeight - 36, pageWidth - margin, pageHeight - 36);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text('Static Vulnerability Scanning Tool · CWE Static Audit Archive', margin, pageHeight - 22);
    doc.text(`Page ${i} of ${totalPages}`, pageWidth - margin, pageHeight - 22, { align: 'right' });
  }

  doc.save(buildFilename(result, 'pdf'));
}
