import { NextRequest } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Upload ceiling for requests proxied to the backend. The backend accepts
// direct uploads up to ECDAT_MAX_DIRECT_MB (default 64 MiB; hex endpoints
// double their payload, hence the headroom). Chunked uploads are 2 MB per
// request so this cap is never the bottleneck for large files.
const MAX_PROXY_BODY_MB = Number(process.env.ECDAT_PROXY_MAX_BODY_MB || 96);
const MAX_PROXY_BODY_BYTES = MAX_PROXY_BODY_MB * 1024 * 1024;
const UPSTREAM_TIMEOUT_MS = Number(process.env.ECDAT_PROXY_TIMEOUT_MS || 300000);

async function forward(
  request: NextRequest,
  context: { params: Promise<{ path?: string[] }> | { path?: string[] } }
) {
  try {
    const rawParams = await Promise.resolve(context.params);
    const path = Array.isArray(rawParams?.path) ? rawParams.path : [];
    const base = (process.env.BACKEND_API_URL || 'http://127.0.0.1:8000/api').replace(/\/$/, '');
    const targetUrl = new URL(`${base}/${path.map(encodeURIComponent).join('/')}`);
    request.nextUrl.searchParams.forEach((val, key) => {
      targetUrl.searchParams.set(key, val);
    });
    const url = targetUrl.toString();

    let body: Uint8Array | undefined;
    if (['POST', 'PATCH', 'PUT'].includes(request.method)) {
      const reader = request.body?.getReader();
      const chunks: Uint8Array[] = [];
      let length = 0;
      if (reader) {
        while (true) {
          const chunk = await reader.read();
          if (chunk.done) break;
          length += chunk.value.byteLength;
          if (length > MAX_PROXY_BODY_BYTES) {
            await reader.cancel();
            return Response.json({ detail: `Request exceeds ${MAX_PROXY_BODY_MB} MiB proxy limit` }, { status: 413 });
          }
          chunks.push(chunk.value);
        }
      }
      body = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) {
        body.set(chunk, offset);
        offset += chunk.byteLength;
      }
    }

    const headers = new Headers();
    request.headers.forEach((value, key) => {
      const lower = key.toLowerCase();
      if (!['host', 'connection', 'content-length', 'transfer-encoding'].includes(lower)) {
        headers.set(key, value);
      }
    });

    const upstream = await fetch(url, {
      method: request.method,
      headers,
      body: body as BodyInit | undefined,
      cache: 'no-store',
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });

    const contentType = upstream.headers.get('content-type') || '';
    if (!upstream.ok && !contentType.includes('application/json')) {
      const rawText = await upstream.text();
      return Response.json(
        { detail: rawText || `Upstream returned HTTP ${upstream.status} ${upstream.statusText}` },
        { status: upstream.status }
      );
    }

    return new Response(upstream.body, {
      status: upstream.status,
      headers: {
        'Content-Type': contentType || 'application/json',
        'Cache-Control': 'no-store',
      },
    });
  } catch (err: any) {
    return Response.json(
      { detail: err?.message || 'Backend unavailable. Check BACKEND_API_URL and backend health.' },
      { status: 502 }
    );
  }
}

export const GET = forward;
export const POST = forward;
export const PATCH = forward;
export const DELETE = forward;
export const PUT = forward;

