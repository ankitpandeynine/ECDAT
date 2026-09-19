"""One bounded HEAD request to the same vetted IP used for TLS collection."""
import re
import time
import socket
from .network_prober import probe_tls_endpoint
from .network.resolver import create_connection
from .network.tls_analyzer import _tls_context as _context
from .environment_discovery import discover_environment

def _handshake(host, address, context, timeout):
    raw = create_connection(address, timeout)
    return context.wrap_socket(raw, server_hostname=host)

MAX_HEADERS = 16 * 1024
ALLOWED_HEADERS = {'server', 'via', 'x-powered-by', 'cf-ray', 'x-vercel-id',
                   'x-amz-cf-id', 'x-nf-request-id', 'fly-request-id', 'x-served-by', 'x-cache', 'strict-transport-security', 'location'}


def inspect_http(host, port, address, timeout=3.0):
    started = time.monotonic()
    result = {'status': 'unavailable', 'method': 'HEAD', 'path': '/',
              'headers': {}, 'hosting_hints': [], 'origin_provider': None,
              'origin_region': None, 'deployment_method': None,
              'average_daily_requests': None,
              'limitations': ['Public headers can be hidden or spoofed; a CDN does not identify the origin.',
                             'One HEAD request is not average traffic or a performance benchmark.',
                             'Redirects are recorded but never followed. Only HTTPS root is checked.',
                             'Headers are collected without certificate verification; use TLS trust evidence separately.']}
    try:
        with _handshake(host, address, _context(), timeout) as conn:
            authority = f'[{host}]' if ':' in host else host
            authority += f':{port}' if port != 443 else ''
            conn.sendall(f'HEAD / HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: ECDAT/3.1\r\nConnection: close\r\n\r\n'.encode('ascii'))
            raw = bytearray()
            while b'\r\n\r\n' not in raw:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError('HTTP header deadline exceeded')
                conn.settimeout(remaining)
                part = conn.recv(min(2048, MAX_HEADERS + 1 - len(raw)))
                if not part:
                    break
                raw.extend(part)
                if len(raw) > MAX_HEADERS:
                    raise ValueError('HTTP headers exceed 16 KiB')
            if b'\r\n\r\n' not in raw:
                raise ValueError('Incomplete HTTP headers')
            lines = raw.split(b'\r\n\r\n', 1)[0].decode('iso-8859-1').split('\r\n')
            status = re.fullmatch(r'HTTP/1\.[01] ([1-5][0-9]{2})(?: .*)?', lines[0])
            if not status:
                raise ValueError('Unsupported HTTP response')
            headers = {}
            for line in lines[1:]:
                name, sep, value = line.partition(':')
                if sep and name.lower() in ALLOWED_HEADERS:
                    headers[name.lower()] = re.sub(r'[\x00-\x1f\x7f]', '', value.strip())[:500]
            hints = []
            for header, provider in [('cf-ray', 'Cloudflare edge'), ('x-vercel-id', 'Vercel edge'), ('x-amz-cf-id', 'Amazon CloudFront edge')]:
                if header in headers:
                    hints.append({'provider': provider, 'confidence': 'inferred', 'evidence': f'{header}: {headers[header]}'})
            result.update(status='observed', status_code=int(status.group(1)), headers=headers,
                          hosting_hints=hints, response_header_ms=round((time.monotonic()-started)*1000, 1))
    except (OSError, ValueError) as exc:
        result['error'] = str(exc)
    return result


def scan_website(target, port=443):
    result = probe_tls_endpoint(target, port)
    if result.get('status') != 'error':
        # The TLS probe already resolved and vetted this exact address. Never resolve
        # the hostname a second time and never let a redirect select another target.
        ip = result['ip_address']
        address = (socket.AF_INET6, (ip, result['port'], 0, 0)) if ':' in ip else (socket.AF_INET, (ip, result['port']))
        deployment = inspect_http(result['host'], result['port'], address)
        environment = discover_environment(deployment['headers'])
        html = inspect_html(result['host'], result['port'], address)
        for signal in html['signals']:
            if not any(s['category'] == signal['category'] and s['value'] == signal['value'] for s in environment['signals']):
                environment['signals'].append(signal)
        environment['status'] = 'signals_found' if environment['signals'] else 'no_public_signals'
        deployment['environment'] = environment
        deployment['html_discovery'] = {k: v for k, v in html.items() if k != 'signals'}
        result['deployment'] = deployment
    return result


def inspect_html(host, port, address, timeout=3.0):
    """Sample at most 128 KiB from HTTPS root. No redirects or resource crawling."""
    started = time.monotonic()
    limit = 128 * 1024
    response = {'status': 'unavailable', 'sample_bytes': 0, 'signals': []}
    try:
        with _handshake(host, address, _context(), timeout) as conn:
            authority = f'[{host}]' if ':' in host else host
            authority += f':{port}' if port != 443 else ''
            conn.sendall(f'GET / HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: ECDAT/3.2\r\nAccept: text/html\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n'.encode('ascii'))
            data = bytearray()
            while b'\r\n\r\n' not in data:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0: raise TimeoutError('HTML header deadline exceeded')
                conn.settimeout(remaining)
                part = conn.recv(min(2048, MAX_HEADERS + 1 - len(data)))
                if not part: raise ValueError('Incomplete HTML response headers')
                data.extend(part)
                if len(data) > MAX_HEADERS: raise ValueError('HTML headers exceed 16 KiB')
            header, body = bytes(data).split(b'\r\n\r\n', 1)
            lines = header.decode('iso-8859-1').split('\r\n')
            if not re.match(r'^HTTP/1\.[01] 200(?: |$)', lines[0]):
                return dict(response, status='skipped', reason='Root did not return HTTP 200; redirects are not followed.')
            headers = {a.lower(): b.strip() for line in lines[1:] for a, sep, b in [line.partition(':')] if sep}
            if 'text/html' not in headers.get('content-type', '').lower():
                return dict(response, status='skipped', reason='Root is not declared text/html.')
            if headers.get('content-encoding', 'identity').lower() != 'identity':
                return dict(response, status='skipped', reason='Compressed HTML is not expanded by this bounded sampler.')
            body = bytearray(body)
            expected = int(headers['content-length']) if headers.get('content-length', '').isdigit() else None
            while len(body) < limit and (expected is None or len(body) < expected):
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0: break
                conn.settimeout(remaining)
                try: part = conn.recv(min(8192, limit - len(body)))
                except socket.timeout: break
                if not part: break
                body.extend(part)
            sampled = bytes(body[:limit])
            if 'chunked' in headers.get('transfer-encoding', '').lower():
                # Decode only complete chunks from the bounded wire sample.
                decoded, cursor = bytearray(), 0
                while cursor < len(sampled):
                    end = sampled.find(b'\r\n', cursor)
                    if end < 0: break
                    size = int(sampled[cursor:end].split(b';')[0], 16)
                    cursor = end + 2
                    if size == 0 or cursor + size + 2 > len(sampled): break
                    decoded.extend(sampled[cursor:cursor+size]); cursor += size + 2
                sampled = bytes(decoded)
            environment = discover_environment({}, sampled.decode('utf-8', 'replace'))
            return {'status': 'sampled', 'sample_bytes': len(sampled), 'signals': environment['signals'],
                    'limit_bytes': limit, 'reason': 'Bounded root HTML sample; scripts were not executed and resources were not crawled.'}
    except (OSError, ValueError) as exc:
        return dict(response, reason=str(exc)[:200])
