const MAX_BYTES = (Number(process.env.MAX_UPLOAD_SIZE_MB) || 16) * 1024 * 1024;

const PRIVATE_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^0\.0\.0\.0$/,
  /^\[?::1\]?$/,
];

export interface FetchResult {
  content: string;
  targetUrl: string;
  contentType: string;
}

export async function fetchRemoteSource(rawUrl: string): Promise<FetchResult> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new Error('Invalid URL format. Please provide a valid http:// or https:// URL.');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only http:// and https:// URLs are supported.');
  }

  const hostname = parsed.hostname;
  if (PRIVATE_HOST_PATTERNS.some((pattern) => pattern.test(hostname))) {
    throw new Error('Scanning local or private network addresses is not permitted.');
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(parsed.toString(), {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Static-JS-Scanner/1.0',
        Accept: 'text/javascript, application/javascript, text/html, text/plain, */*',
      },
      redirect: 'follow',
    });

    if (!response.ok) {
      throw new Error(`Remote server returned HTTP ${response.status} ${response.statusText}.`);
    }

    const contentLength = response.headers.get('content-length');
    if (contentLength && Number(contentLength) > MAX_BYTES) {
      throw new Error('Remote file exceeds the 16 MB maximum size limit.');
    }

    const arrayBuffer = await response.arrayBuffer();
    if (arrayBuffer.byteLength > MAX_BYTES) {
      throw new Error('Remote file exceeds the 16 MB maximum size limit.');
    }

    const content = new TextDecoder('utf-8', { fatal: false }).decode(arrayBuffer);
    const contentType = response.headers.get('content-type') || 'text/plain';

    return {
      content,
      targetUrl: response.url || parsed.toString(),
      contentType,
    };
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error('Request timed out after 15 seconds while fetching the remote URL.');
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}
