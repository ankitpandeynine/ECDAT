"""Bounded OpenSSL TLS 1.3 group probes against an already-vetted IP.

A hybrid handshake says nothing about PQ certificate authentication or other
clients' default negotiations. Failure never establishes universal non-support.
"""
import os
import re
import shutil
import subprocess
import threading
import time

GROUPS = ('X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024')
MAX_OUTPUT = 64 * 1024


def run_bounded(argv, timeout=3.0, completed=None):
    """No shell, inherited proxy, application request or unbounded capture."""
    env = dict(os.environ, LC_ALL='C')
    for name in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
        env.pop(name, None)
    output = bytearray()
    reason = None

    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, env=env) as proc:
        def reader():
            nonlocal reason
            while True:
                chunk = proc.stdout.read(min(4096, MAX_OUTPUT + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_OUTPUT:
                    reason = 'output_limit'
                    break
                if completed and completed(output.decode('utf-8', 'replace')):
                    break

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        t.join(timeout=timeout)
        if t.is_alive():
            reason = 'timeout'
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
            t.join(timeout=0.5)
        else:
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass
            proc.wait()

    return {'text': output[:MAX_OUTPUT].decode('utf-8', 'replace'), 'reason': reason}




def handshake_evidence(text):
    # Only a full TLS 1.3 handshake summary is accepted, never merely an offered
    # group name in an error message. -brief prints this after SSL_connect.
    return bool(re.search(r'^CONNECTION ESTABLISHED\s*$', text, re.M)
                and re.search(r'^Protocol version: TLSv1\.3\s*$', text, re.M)
                and re.search(r'^Ciphersuite: TLS_[A-Z0-9_]+\s*$', text, re.M)
                and re.search(r'^(?:Negotiated TLS1\.3 group|Server Temp Key|Peer Temp Key): [^\r\n]+\r?\n', text, re.M))


def probe_group(binary, host, ip, port, group, timeout=3.0):
    endpoint = f'[{ip}]:{port}' if ':' in ip else f'{ip}:{port}'
    argv = [binary, 's_client', '-connect', endpoint, '-servername', host,
            '-tls1_3', '-groups', group, '-brief', '-ign_eof']
    try:
        response = run_bounded(argv, timeout, handshake_evidence)
    except OSError as exc:
        return {'group': group, 'status': 'scanner_unavailable', 'reason': str(exc)[:200]}
    text = response['text']
    if response['reason'] == 'output_limit':
        return {'group': group, 'status': 'inconclusive', 'reason': 'Diagnostic output limit exceeded'}
    if handshake_evidence(text):
        selected = re.search(r'^(?:Negotiated TLS1\.3 group|Server Temp Key|Peer Temp Key): ([^,\r\n]+)', text, re.M).group(1).strip()
        aliases = {'prime256v1': 'P-256', 'secp256r1': 'P-256', 'X25519': 'X25519'}
        if aliases.get(selected, selected) != aliases.get(group, group):
            return {'group': group, 'status': 'inconclusive', 'reason': 'Unexpected negotiated group in diagnostic output'}
        return {'group': group, 'status': 'negotiated', 'negotiated_group': selected,
                'protocol': 'TLSv1.3', 'cipher': re.search(r'^Ciphersuite: (\S+)', text, re.M).group(1),
                'evidence': f'TLS 1.3 handshake completed with only {group} offered; negotiated group reported by OpenSSL.'}
    if any(x in text for x in ('group cannot be set', 'passed invalid argument', 'SSL_CONF_cmd', 'unknown option')):
        return {'group': group, 'status': 'scanner_unavailable', 'reason': 'This OpenSSL build/provider cannot probe this group. Use the supplied Docker runtime (OpenSSL 3.5+).'}
    if response['reason']:
        return {'group': group, 'status': 'inconclusive', 'reason': response['reason']}
    if re.search(r'(alert handshake failure|alert protocol version|no suitable key share)', text, re.I):
        return {'group': group, 'status': 'not_negotiated', 'reason': 'TLS peer rejected this single-group attempt; other PQ groups/clients were not ruled out.'}
    return {'group': group, 'status': 'inconclusive', 'reason': 'Connection failed or no complete negotiated-group evidence was returned.'}


def probe_pqc(host, ip, port, budget=12.0):
    binary = os.getenv('ECDAT_OPENSSL_BIN') or shutil.which('openssl')
    base = {'status': 'scanner_unavailable', 'supported_groups': [], 'tests': [],
            'scope': 'Explicit TLS 1.3 group capability tests on one IP and SNI, not a normal browser negotiation.',
            'limitations': ['Hybrid key exchange does not establish PQ signatures, PQ certificate chains or end-to-end application readiness.',
                            'Handshake capability is collected independently of certificate trust. Review the certificate trust result.',
                            'Only three ML-KEM hybrid groups and one classical control are tested.']}
    if not binary:
        return dict(base, reason='OpenSSL executable is missing. Rebuild the provided Docker image or set ECDAT_OPENSSL_BIN to OpenSSL 3.5+.')
    deadline = time.monotonic() + budget
    try:
        base['scanner_version'] = run_bounded([binary, 'version'], 1)['text'].strip()[:150]
    except OSError as exc:
        return dict(base, reason=str(exc)[:200])
    for group in (*GROUPS, 'X25519'):
        remaining = deadline - time.monotonic()
        base['tests'].append(probe_group(binary, host, ip, port, group, min(2.5, remaining)) if remaining > .1
                             else {'group': group, 'status': 'inconclusive', 'reason': 'Probe budget exhausted'})
    pq = base['tests'][:len(GROUPS)]
    base['supported_groups'] = [t['group'] for t in pq if t['status'] == 'negotiated']
    if base['supported_groups']:
        base['status'] = 'hybrid_supported'
        base['reason'] = 'A post-quantum/classical hybrid TLS key exchange completed successfully.'
    elif all(t['status'] == 'scanner_unavailable' for t in pq):
        base['reason'] = 'Scanner runtime cannot test ML-KEM groups. Rebuild the backend Docker image (OpenSSL 3.5+), or configure ECDAT_OPENSSL_BIN.'
    elif all(t['status'] == 'not_negotiated' for t in pq):
        base['status'] = 'tested_not_negotiated'
        base['reason'] = 'None of the three tested hybrid groups negotiated; this is not proof that all PQ configurations are unsupported.'
    else:
        base['status'] = 'inconclusive'
        base['reason'] = 'Some probes timed out, failed, or were unavailable; check individual attempts.'
    return base


def pqc_label(result):
    return {'hybrid_supported': 'Hybrid PQ key exchange verified',
            'tested_not_negotiated': 'Tested hybrid groups did not negotiate',
            'scanner_unavailable': 'Scanner upgrade required for PQ measurement',
            'inconclusive': 'PQ probes inconclusive'}[result['status']]
