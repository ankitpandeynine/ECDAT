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
    const configuredBase = process.env.BACKEND_API_URL || 'http://127.0.0.1:8000/api';
    let baseUrl: URL;
    try {
      baseUrl = new URL(configuredBase);
    } catch {
      return Response.json({ detail: 'BACKEND_API_URL must be a valid absolute URL.' }, { status: 500 });
    }
    if (!['http:', 'https:'].includes(baseUrl.protocol)) {
      return Response.json({ detail: 'BACKEND_API_URL must use HTTP or HTTPS.' }, { status: 500 });
    }
    const base = baseUrl.toString().replace(/\/$/, '');
    const targetUrl = new URL(`${base}/${path.map(encodeURIComponent).join('/')}`);
    request.nextUrl.searchParams.forEach((val, key) => {
      targetUrl.searchParams.append(key, val);
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
      if (!['host', 'connection', 'content-length', 'transfer-encoding', 'accept-encoding'].includes(lower)) {
        headers.set(key, value);
      }
    });
    // Avoid forwarding browser-only origin headers to the Render API. The API
    // authenticates with the optional Bearer token configured on both hosts.
    headers.delete('origin');
    headers.delete('referer');
    if (process.env.ECDAT_API_TOKEN) {
      headers.set('Authorization', `Bearer ${process.env.ECDAT_API_TOKEN}`);
    }

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

    const responseHeaders = new Headers();
    responseHeaders.set('Content-Type', contentType || 'application/json');
    responseHeaders.set('Cache-Control', 'no-store');
    const disposition = upstream.headers.get('content-disposition');
    if (disposition) responseHeaders.set('Content-Disposition', disposition);
    const exposeHeaders = upstream.headers.get('access-control-expose-headers');
    if (exposeHeaders) responseHeaders.set('Access-Control-Expose-Headers', exposeHeaders);
    return new Response(upstream.body, {
      status: upstream.status,
      headers: responseHeaders,
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

