import { NextRequest, NextResponse } from 'next/server';
import { scanSource, type ScanInput } from '@/scanner/coreEngine';
import type { ScanProgressEvent } from '@/scanner/types';
import { fetchRemoteSource } from '@/scanner/webFetcher';

const ALLOWED_EXTENSIONS = new Set(['.js', '.html', '.htm', '.php', '.mjs', '.cjs']);
const MAX_BYTES = (Number(process.env.MAX_UPLOAD_SIZE_MB) || 16) * 1024 * 1024;

function getExtension(filename: string): string {
  const idx = filename.lastIndexOf('.');
  return idx >= 0 ? filename.slice(idx).toLowerCase() : '';
}

type PreparedScan =
  | { kind: 'ready'; input: ScanInput }
  | { kind: 'url'; url: string };

async function parseRequest(req: NextRequest): Promise<PreparedScan> {
  const contentType = req.headers.get('content-type') || '';

  if (contentType.includes('multipart/form-data')) {
    const formData = await req.formData();
    const file = formData.get('file');
    const urlInput = formData.get('url');

    if (file instanceof File && file.size > 0) {
      if (file.size > MAX_BYTES) {
        throw new Error('File exceeds the 16 MB maximum upload limit.');
      }

      const ext = getExtension(file.name);
      if (!ALLOWED_EXTENSIONS.has(ext)) {
        throw new Error(
          `Unsupported file type '${ext || 'unknown'}'. Please upload a .js, .html, or .php file.`
        );
      }

      const content = await file.text();
      if (!content.trim()) {
        throw new Error('Uploaded file is empty.');
      }

      return {
        kind: 'ready',
        input: {
          content,
          target: file.name,
          sourceType: 'file',
        },
      };
    }

    if (typeof urlInput === 'string' && urlInput.trim()) {
      return { kind: 'url', url: urlInput.trim() };
    }

    throw new Error('Please select a .js, .html, or .php file or enter a valid URL to scan.');
  }

  const body = (await req.json()) as { url?: string; code?: string; filename?: string };

  if (body.url && body.url.trim()) {
    return { kind: 'url', url: body.url.trim() };
  }

  if (body.code && body.code.trim()) {
    if (Buffer.byteLength(body.code, 'utf-8') > MAX_BYTES) {
      throw new Error('Source code exceeds the 16 MB maximum size limit.');
    }
    return {
      kind: 'ready',
      input: {
        content: body.code,
        target: body.filename || 'snippet.js',
        sourceType: 'file',
      },
    };
  }

  throw new Error('Provide either a file upload or a URL to scan.');
}

export async function POST(req: NextRequest) {
  const wantsStream = req.nextUrl.searchParams.get('stream') === '1';

  if (!wantsStream) {
    try {
      const prepared = await parseRequest(req);
      let scanInput: ScanInput;
      if (prepared.kind === 'url') {
        const fetched = await fetchRemoteSource(prepared.url);
        scanInput = {
          content: fetched.content,
          target: fetched.targetUrl,
          sourceType: 'url',
        };
      } else {
        scanInput = prepared.input;
      }

      const result = scanSource(scanInput);
      return NextResponse.json(result);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : 'An unexpected error occurred during scanning.';
      return NextResponse.json({ error: message }, { status: 400 });
    }
  }

  // Streaming NDJSON response emitting real progress events during scan
  let prepared: PreparedScan;
  try {
    prepared = await parseRequest(req);
  } catch (err) {
    const message =
      err instanceof Error ? err.message : 'An unexpected error occurred during scanning.';
    return NextResponse.json({ error: message }, { status: 400 });
  }

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const writeEvent = (payload: Record<string, unknown>) => {
        controller.enqueue(encoder.encode(`${JSON.stringify(payload)}\n`));
      };

      const emitProgress = (event: ScanProgressEvent) => {
        writeEvent({ type: 'progress', ...event });
      };

      try {
        let scanInput: ScanInput;
        if (prepared.kind === 'url') {
          emitProgress({
            stage: 'fetching',
            label: 'Fetching remote source over HTTP(S)...',
            percent: 25,
          });
          const fetched = await fetchRemoteSource(prepared.url);
          scanInput = {
            content: fetched.content,
            target: fetched.targetUrl,
            sourceType: 'url',
          };
        } else {
          scanInput = prepared.input;
        }

        const result = scanSource(scanInput, emitProgress);
        writeEvent({ type: 'result', result });
      } catch (err) {
        const message =
          err instanceof Error ? err.message : 'An unexpected error occurred during scanning.';
        writeEvent({ type: 'error', error: message });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'application/x-ndjson; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
    },
  });
}
