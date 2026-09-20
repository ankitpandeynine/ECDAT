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
ALLOWED_HEADERS = {
    'server', 'via', 'x-powered-by', 'cf-ray', 'cf-cache-status', 'x-vercel-id',
    'x-amz-cf-id', 'x-nf-request-id', 'fly-request-id', 'x-served-by', 'x-cache',
    'strict-transport-security', 'location', 'age', 'cache-control', 'alt-svc',
    'x-fastly-request-id', 'x-akamai-transformed',
    'content-security-policy', 'x-frame-options', 'x-content-type-options',
    'x-xss-protection', 'referrer-policy', 'permissions-policy',
    'cross-origin-opener-policy', 'cross-origin-resource-policy',
    'cross-origin-embedder-policy', 'expect-ct', 'report-to', 'nel'
}


def analyze_security_headers(headers: dict) -> dict:
    """Detailed cryptographic and web application security header scorecard."""
    hsts = headers.get('strict-transport-security', '')
    csp = headers.get('content-security-policy', '')
    xfo = headers.get('x-frame-options', '')
    xcto = headers.get('x-content-type-options', '')
    ref_pol = headers.get('referrer-policy', '')
    perm_pol = headers.get('permissions-policy', '')
    alt_svc = headers.get('alt-svc', '')
    coop = headers.get('cross-origin-opener-policy', '')
    corp = headers.get('cross-origin-resource-policy', '')

    score = 0
    max_score = 100
    cards = []

    # 1. HSTS
    if hsts:
        max_age_match = re.search(r'max-age=(\d+)', hsts, re.IGNORECASE)
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        include_sub = 'includesubdomains' in hsts.lower()
        preload = 'preload' in hsts.lower()
        if max_age >= 31536000 and include_sub:
            cards.append({'header': 'Strict-Transport-Security', 'status': 'OPTIMAL', 'score': 25, 'description': f'Enforced: {max_age}s ({round(max_age/86400)} days), includeSubDomains: {include_sub}, preload: {preload}'})
            score += 25
        elif max_age >= 86400:
            cards.append({'header': 'Strict-Transport-Security', 'status': 'ACCEPTABLE', 'score': 15, 'description': f'Active max-age: {max_age}s. Recommend >= 31536000 and includeSubDomains.'})
            score += 15
        else:
            cards.append({'header': 'Strict-Transport-Security', 'status': 'WEAK', 'score': 5, 'description': f'Short max-age: {max_age}s.'})
            score += 5
    else:
        cards.append({'header': 'Strict-Transport-Security', 'status': 'MISSING', 'score': 0, 'description': 'Missing HSTS header. Insecure against SSL stripping and man-in-the-middle attacks.'})

    # 2. CSP
    if csp:
        has_upgrade = 'upgrade-insecure-requests' in csp.lower()
        has_default = 'default-src' in csp.lower()
        has_wildcard = '*' in csp
        if has_default and not has_wildcard:
            cards.append({'header': 'Content-Security-Policy', 'status': 'STRONG', 'score': 25, 'description': 'Strict CSP with restrictive source boundaries.'})
            score += 25
        else:
            cards.append({'header': 'Content-Security-Policy', 'status': 'PRESENT', 'score': 15, 'description': f'CSP configured (upgrade-insecure: {has_upgrade}).'})
            score += 15
    else:
        cards.append({'header': 'Content-Security-Policy', 'status': 'MISSING', 'score': 0, 'description': 'Missing Content-Security-Policy. Vulnerable to cross-site scripting and unauthorized resource loading.'})

    # 3. X-Frame-Options
    if xfo:
        cards.append({'header': 'X-Frame-Options', 'status': 'OPTIMAL', 'score': 15, 'description': f'Configured ({xfo.upper()}) to prevent Clickjacking.'})
        score += 15
    else:
        cards.append({'header': 'X-Frame-Options', 'status': 'MISSING', 'score': 0, 'description': 'Missing anti-clickjacking protection.'})

    # 4. X-Content-Type-Options
    if 'nosniff' in xcto.lower():
        cards.append({'header': 'X-Content-Type-Options', 'status': 'OPTIMAL', 'score': 15, 'description': 'MIME-sniffing prevention (nosniff) active.'})
        score += 15
    else:
        cards.append({'header': 'X-Content-Type-Options', 'status': 'MISSING', 'score': 0, 'description': 'Missing nosniff flag; MIME confusion vulnerabilities possible.'})

    # 5. Referrer-Policy
    if ref_pol:
        cards.append({'header': 'Referrer-Policy', 'status': 'OPTIMAL', 'score': 10, 'description': f'Privacy preserved via {ref_pol}.'})
        score += 10
    else:
        cards.append({'header': 'Referrer-Policy', 'status': 'MISSING', 'score': 0, 'description': 'Missing referrer policy; sensitive query parameters may leak.'})

    # 6. HTTP/3 & QUIC
    http3_detected = False
    quic_version = None
    if alt_svc:
        if 'h3' in alt_svc.lower():
            http3_detected = True
            quic_match = re.search(r'h3(?:-[a-zA-Z0-9]+)?', alt_svc)
            quic_version = quic_match.group(0) if quic_match else 'h3'
            cards.append({'header': 'Alt-Svc (HTTP/3 & QUIC)', 'status': 'ADVANCED', 'score': 10, 'description': f'HTTP/3 QUIC transport enabled ({quic_version}) with modern 0-RTT and multiplexed stream resilience.'})
            score += 10
        else:
            cards.append({'header': 'Alt-Svc', 'status': 'PRESENT', 'score': 5, 'description': f'Alternative services advertised: {alt_svc[:60]}'})
            score += 5

    # Overall grade
    if score >= 90:
        grade = 'A+'
    elif score >= 75:
        grade = 'A'
    elif score >= 60:
        grade = 'B'
    elif score >= 40:
        grade = 'C'
    else:
        grade = 'F'

    return {
        'score': score,
        'max_score': max_score,
        'grade': grade,
        'cards': cards,
        'http3_enabled': http3_detected,
        'quic_version': quic_version,
        'coop': coop or None,
        'corp': corp or None,
        'permissions_policy': perm_pol or None,
    }


def estimate_probable_traffic(headers: dict, response_header_ms: float = 0.0, hosting_hints: list = None) -> dict:
    """Estimates probable website traffic volume, CDN infrastructure, and wire HNDL exposure."""
    server_h = str(headers.get('server', '')).lower()
    via_h = str(headers.get('via', '')).lower()
    cf_ray = headers.get('cf-ray', '')
    cf_cache = str(headers.get('cf-cache-status', '')).upper()
    x_cache = str(headers.get('x-cache', '')).lower()
    age_h = str(headers.get('age', ''))
    cache_control = str(headers.get('cache-control', '')).lower()

    cdn_provider = None
    if cf_ray or 'cloudflare' in server_h:
        cdn_provider = 'Cloudflare Anycast Global Edge'
    elif 'x-amz-cf-id' in headers or 'cloudfront' in via_h:
        cdn_provider = 'Amazon CloudFront CDN'
    elif 'x-vercel-id' in headers:
        cdn_provider = 'Vercel Edge Network'
    elif 'x-served-by' in headers or 'fastly' in via_h or 'fastly' in server_h:
        cdn_provider = 'Fastly Programmable Edge'
    elif any('akamai' in k for k in headers) or 'akamai' in server_h:
        cdn_provider = 'Akamai Intelligent Edge Platform'
    elif 'fly-request-id' in headers:
        cdn_provider = 'Fly.io Distributed Edge'
    elif 'gfe' in server_h or 'gws' in server_h:
        cdn_provider = 'Google Front End (GFE) / Cloud CDN'
    elif 'nginx' in server_h:
        cdn_provider = 'Nginx Reverse Proxy / Load Balancer'
    elif 'apache' in server_h:
        cdn_provider = 'Apache HTTP Server'
    elif 'envoy' in server_h:
        cdn_provider = 'Envoy Edge Proxy'
    elif hosting_hints and len(hosting_hints) > 0:
        cdn_provider = hosting_hints[0].get('provider')

    # Cache efficiency
    cache_efficiency = 'DYNAMIC / UNCACHED'
    if cf_cache in ('HIT', 'REVALIDATED'):
        cache_efficiency = f'CACHE {cf_cache} (Cloudflare Edge)'
    elif 'hit' in x_cache:
        cache_efficiency = 'CACHE HIT (CDN Edge Accelerated)'
    elif age_h.isdigit() and int(age_h) > 0:
        cache_efficiency = f'CACHED (Age: {age_h}s)'
    elif 'max-age' in cache_control and 'no-cache' not in cache_control:
        cache_efficiency = 'CLIENT/PROXY CACHEABLE'

    # Traffic Tier Estimation
    if cdn_provider in ('Cloudflare Anycast Global Edge', 'Akamai Intelligent Edge Platform', 'Google Front End (GFE) / Cloud CDN'):
        estimated_tier = 'Enterprise High Volume'
        probable_daily_requests = '5,000,000 – 50,000,000+ req/day'
        traffic_scale = 'HIGH'
        description = 'Global Anycast Edge CDN architecture engineered for multi-million daily requests with edge caching, DDoS mitigation, and global edge presence.'
    elif cdn_provider in ('Amazon CloudFront CDN', 'Fastly Programmable Edge', 'Vercel Edge Network', 'Fly.io Distributed Edge'):
        estimated_tier = 'Commercial Scale / Cloud Native'
        probable_daily_requests = '250,000 – 5,000,000 req/day'
        traffic_scale = 'MEDIUM-HIGH'
        description = 'Distributed cloud-native edge infrastructure handling high-throughput production API and web application workloads.'
    elif cdn_provider in ('Nginx Reverse Proxy / Load Balancer', 'Envoy Edge Proxy'):
        estimated_tier = 'Standard Web / Dedicated Proxy'
        probable_daily_requests = '25,000 – 250,000 req/day'
        traffic_scale = 'MODERATE'
        description = 'Origin-facing proxy architecture with direct session termination; standard enterprise production scale.'
    else:
        estimated_tier = 'Direct Origin / Low-to-Moderate Traffic'
        probable_daily_requests = '< 25,000 req/day'
        traffic_scale = 'LOW'
        description = 'Direct connection to origin server without intermediate global CDN acceleration.'

    # Latency rating
    if response_header_ms > 0:
        if response_header_ms < 50:
            latency_rating = 'Ultra Fast (<50ms - Local Edge Presence)'
        elif response_header_ms < 150:
            latency_rating = 'Good (50–150ms - Regional Edge)'
        elif response_header_ms < 350:
            latency_rating = 'Moderate (150–350ms - Transcontinental / Origin Transit)'
        else:
            latency_rating = 'Elevated (>350ms - High Latency Transit)'
    else:
        latency_rating = 'Undetermined'

    # HNDL Wire Exposure Risk
    if traffic_scale in ('HIGH', 'MEDIUM-HIGH'):
        hndl_wire_exposure = 'CRITICAL (High wire traffic volume — substantial retrospective decryption attack surface for adversaries harvesting ciphertext)'
    elif traffic_scale == 'MODERATE':
        hndl_wire_exposure = 'HIGH (Substantial ciphertext volume exposed to passive tap adversaries)'
    else:
        hndl_wire_exposure = 'MEDIUM (Targeted interception risk)'

    return {
        'estimated_tier': estimated_tier,
        'probable_daily_requests': probable_daily_requests,
        'traffic_scale': traffic_scale,
        'cdn_provider': cdn_provider or 'Direct Origin',
        'cache_efficiency': cache_efficiency,
        'response_latency_ms': response_header_ms,
        'latency_rating': latency_rating,
        'hndl_wire_exposure': hndl_wire_exposure,
        'infrastructure_description': description,
        'security_headers': {
            'hsts': 'strict-transport-security' in headers,
            'server_disclosed': bool(headers.get('server')),
            'powered_by_disclosed': bool(headers.get('x-powered-by'))
        }
    }


def inspect_http(host, port, address, timeout=3.0):
    started = time.monotonic()
    result = {'status': 'unavailable', 'method': 'HEAD', 'path': '/',
              'headers': {}, 'hosting_hints': [], 'origin_provider': None,
              'origin_region': None, 'deployment_method': None,
              'average_daily_requests': None, 'probable_traffic': None,
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
            
            resp_ms = round((time.monotonic()-started)*1000, 1)
            traffic_info = estimate_probable_traffic(headers, resp_ms, hints)
            security_info = analyze_security_headers(headers)
            result.update(
                status='observed',
                status_code=int(status.group(1)),
                headers=headers,
                hosting_hints=hints,
                response_header_ms=resp_ms,
                probable_traffic=traffic_info,
                average_daily_requests=traffic_info['probable_daily_requests'],
                security_assessment=security_info
            )
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
        deployment['probable_traffic'] = deployment.get('probable_traffic')
        deployment['security_assessment'] = deployment.get('security_assessment')
        result['deployment'] = deployment
        result['probable_traffic'] = deployment.get('probable_traffic')
        result['security_assessment'] = deployment.get('security_assessment')
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
