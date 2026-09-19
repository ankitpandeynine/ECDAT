"""DNS resolution and strict SSRF connection wrappers."""
import ipaddress
import json
import os
import socket
import subprocess
import sys


def clean_target_host(target: str):
    from urllib.parse import urlsplit
    target = target.strip()
    if not target:
        raise ValueError('Target is required')
    parsed = urlsplit(target if '://' in target else '//' + target)
    if parsed.scheme and parsed.scheme not in ('https', 'http'):
        raise ValueError('Only hostnames or HTTP(S) URLs are supported')
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError('Invalid target host')
    host = parsed.hostname.encode('idna').decode('ascii')
    return host, parsed.port or 443


def resolve_target(host: str, port: int):
    # Run DNS in a bounded child process: socket timeouts do not bound getaddrinfo.
    try:
        dns = subprocess.run([sys.executable, '-c',
            'import socket,json,sys; print(json.dumps(socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), type=socket.SOCK_STREAM)))',
            host, str(port)], capture_output=True, text=True, timeout=3, check=True)
        addresses = json.loads(dns.stdout)
    except (subprocess.SubprocessError, ValueError) as exc:
        raise ValueError('DNS resolution failed or exceeded 3 seconds') from exc
    allow = [ipaddress.ip_network(x.strip()) for x in os.getenv('ECDAT_ALLOWED_CIDRS', '').split(',') if x.strip()]
    approved = []
    for family, kind, proto, _, sockaddr in addresses:
        sockaddr = tuple(sockaddr)
        address = ipaddress.ip_address(sockaddr[0])
        if not address.is_global and not any(address in network for network in allow):
            raise ValueError('Private/local targets require an explicit ECDAT_ALLOWED_CIDRS allowlist')
        if (family, sockaddr) not in approved:
            approved.append((family, sockaddr))
    if not approved:
        raise ValueError('Target resolved to no usable addresses')
    return approved[0]


def create_connection(address, timeout: float):
    family, sockaddr = address
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect(sockaddr)
        return raw
    except Exception:
        raw.close()
        raise
