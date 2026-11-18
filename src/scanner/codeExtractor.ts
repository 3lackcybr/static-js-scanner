import * as cheerio from 'cheerio';
import { js as beautifyJs } from 'js-beautify';
import type { ExtractedScript } from './types';

export function detectFileKind(filenameOrUrl: string, content: string): 'js' | 'html' | 'php' {
  const cleanName = filenameOrUrl.split('?')[0].split('#')[0].toLowerCase();
  if (cleanName.endsWith('.php')) return 'php';
  if (cleanName.endsWith('.html') || cleanName.endsWith('.htm')) return 'html';
  if (cleanName.endsWith('.js') || cleanName.endsWith('.mjs') || cleanName.endsWith('.cjs')) return 'js';

  const trimmed = content.trimStart();
  if (/<\?php/i.test(content) || /<\?=/.test(content)) return 'php';
  if (trimmed.startsWith('<!DOCTYPE') || /<html[\s>]/i.test(content) || /<script[\s>]/i.test(content)) {
    return 'html';
  }
  return 'js';
}

/**
 * Replaces PHP server-side blocks (<?php ... ?> and <?= ... ?>) with spaces/newlines
 * so line numbers of surrounding HTML and JavaScript remain identical.
 */
function neutralizePhpBlocks(source: string): string {
  return source.replace(/<\?(?:php|=)?[\s\S]*?\?>/gi, (match) => {
    const newlines = match.match(/\n/g);
    return newlines ? newlines.join('') + ' /* php */ ' : ' /* php */ ';
  });
}

function maybeBeautify(code: string): { code: string; wasBeautified: boolean } {
  const lines = code.split(/\r?\n/);
  const hasMinifiedLine = lines.some((l) => l.length > 350);
  if (hasMinifiedLine && lines.length <= 5) {
    try {
      const formatted = beautifyJs(code, {
        indent_size: 2,
        preserve_newlines: true,
        max_preserve_newlines: 2,
      });
      return { code: formatted, wasBeautified: true };
    } catch {
      return { code, wasBeautified: false };
    }
  }
  return { code, wasBeautified: false };
}

export function extractScripts(
  rawContent: string,
  fileKind: 'js' | 'html' | 'php'
): ExtractedScript[] {
  if (fileKind === 'js') {
    const { code, wasBeautified } = maybeBeautify(rawContent);
    return [
      {
        code,
        startLine: 1,
        label: 'JavaScript Source',
        wasBeautified,
      },
    ];
  }

  const prepared = fileKind === 'php' ? neutralizePhpBlocks(rawContent) : rawContent;
  const scripts: ExtractedScript[] = [];

  // Regex extraction preserves exact 1-based line offsets for each <script> block
  const scriptRegex = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let match: RegExpExecArray | null;
  let blockIndex = 0;

  while ((match = scriptRegex.exec(prepared)) !== null) {
    const attrs = match[1] || '';
    const innerCode = match[2] || '';
    const prefix = prepared.slice(0, match.index);
    const openTagMatch = match[0].match(/^<script\b[^>]*>/i);
    const openTagLines = openTagMatch ? (openTagMatch[0].match(/\n/g)?.length ?? 0) : 0;
    const startLine = (prefix.match(/\n/g)?.length ?? 0) + 1 + openTagLines;

    if (!innerCode.trim()) {
      // External <script src="..."> with empty body — nothing inline to scan
      continue;
    }

    // Skip non-JS script types such as application/ld+json or text/template
    const typeMatch = attrs.match(/\btype\s*=\s*["']([^"']+)["']/i);
    if (typeMatch) {
      const scriptType = typeMatch[1].toLowerCase().trim();
      if (
        scriptType &&
        !scriptType.includes('javascript') &&
        !scriptType.includes('ecmascript') &&
        scriptType !== 'module'
      ) {
        continue;
      }
    }

    blockIndex += 1;
    const { code, wasBeautified } = maybeBeautify(innerCode);
    scripts.push({
      code,
      startLine,
      label: `<script> block #${blockIndex}`,
      wasBeautified,
    });
  }

  // Also check inline event handlers via cheerio (onclick, onload, onerror, etc.)
  try {
    const $ = cheerio.load(prepared);
    const eventAttrs = [
      'onload',
      'onerror',
      'onclick',
      'onmouseover',
      'onfocus',
      'onsubmit',
      'onchange',
      'oninput',
    ];
    const inlineSnippets: string[] = [];
    $('*').each((_, el) => {
      for (const attr of eventAttrs) {
        const val = $(el).attr(attr);
        if (val && val.trim()) {
          inlineSnippets.push(val.trim());
        }
      }
    });

    if (inlineSnippets.length > 0) {
      scripts.push({
        code: inlineSnippets.join(';\n'),
        startLine: 1,
        label: 'Inline HTML Event Handlers',
        wasBeautified: false,
      });
    }
  } catch {
    // Ignore cheerio edge-case failures on malformed HTML
  }

  return scripts;
}
