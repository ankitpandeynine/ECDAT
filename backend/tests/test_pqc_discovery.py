import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import pytest
from test_pipeline import client, tls_server, finish
from engine import pqc_probe
from engine.environment_discovery import discover_environment
from engine.migration_planner import build_plan
from engine.pqc_migration import crypto_migration
from engine.website_inspector import inspect_html


def test_real_classical_control(tls_server):
    binary = os.getenv('ECDAT_OPENSSL_BIN') or shutil.which('openssl')
    result = pqc_probe.probe_group(binary, 'localhost', '127.0.0.1', tls_server, 'X25519')
    assert result['status'] == 'negotiated', result
    assert result['negotiated_group'] == 'X25519'


@pytest.mark.parametrize('group', pqc_probe.GROUPS)
def test_real_hybrid_handshake(tmp_path, tls_server, monkeypatch, client, group):
    binary = os.getenv('ECDAT_OPENSSL_BIN') or shutil.which('openssl')
    available = pqc_probe.run_bounded([binary, 'list', '-tls-groups'])['text'] if binary else ''
    if group not in available:
        if os.getenv('ECDAT_REQUIRE_PQC') == '1':
            pytest.fail('Production runtime must support ' + group)
        pytest.skip('Local OpenSSL lacks ML-KEM; production-image CI requires this real handshake test')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    args = [binary, 's_server', '-accept', f'127.0.0.1:{port}', '-cert', str(tmp_path/'cert.pem'),
            '-key', str(tmp_path/'key.pem'), '-tls1_3', '-groups', group, '-www', '-quiet']
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 3
        while True:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1): break
            except OSError:
                if time.monotonic() > deadline: pytest.fail('TLS fixture failed to start')
                time.sleep(.02)
        result = pqc_probe.probe_pqc('localhost', '127.0.0.1', port)
        assert result['status'] == 'hybrid_supported', result
        assert result['supported_groups'] == [group], result
        assert result['tests'][-1]['status'] == 'not_negotiated', result
        # Also exercise the real API job and plan path for one hybrid group.
        if group == pqc_probe.GROUPS[0]:
            monkeypatch.setenv('ECDAT_ALLOWED_CIDRS', '127.0.0.0/8')
            record = finish(client, client.post('/api/scan/network', json={'target':f'https://127.0.0.1:{port}'}))

            # Python SSL may lack this group locally; in the production container
            # both Python SSL and the CLI link OpenSSL 3.5+.
            if record['status'] == 'completed':
                assert record['result']['post_quantum']['status'] == 'hybrid_supported'
                plan = client.post('/api/migration/plans', json={'scan_ids':[record['id']]}).json()
                assert plan['cryptographic_migration']['tls_key_exchange']['status'] == 'hybrid_supported'
                assert any('ML-DSA' in u['target'] for u in plan['cryptographic_migration']['upgrades'])
            elif os.getenv('ECDAT_REQUIRE_PQC') == '1':
                pytest.fail(f"Production runtime must complete scan for {group}: {record.get('error')}")

    finally:
        proc.terminate()
        try: proc.wait(timeout=2)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait()


def test_error_or_timeout_never_claims_pq_support(monkeypatch):
    def fake(*args): return {'text': 'X25519MLKEM768 alert handshake failure\n', 'reason': None}
    monkeypatch.setattr(pqc_probe, 'run_bounded', fake)
    result = pqc_probe.probe_group('openssl','site.example','1.1.1.1',443,'X25519MLKEM768')
    assert result['status'] == 'not_negotiated'
    monkeypatch.setattr(pqc_probe,'run_bounded',lambda *a: {'text':'','reason':'timeout'})
    assert pqc_probe.probe_group('openssl','site.example','1.1.1.1',443,'X25519MLKEM768')['status'] == 'inconclusive'


def test_runtime_missing_is_not_target_failure(monkeypatch):
    monkeypatch.delenv('ECDAT_OPENSSL_BIN', raising=False)
    monkeypatch.setattr(pqc_probe.shutil, 'which', lambda name: None)
    assert pqc_probe.probe_pqc('site.example','1.1.1.1',443)['status'] == 'scanner_unavailable'


def test_probe_pins_address_and_preserves_sni(monkeypatch):
    seen = []
    def fake(args, *unused):
        seen.append(args)
        return {'text':'CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384\nNegotiated TLS1.3 group: X25519MLKEM768\n','reason':None}
    monkeypatch.setattr(pqc_probe, 'run_bounded', fake)
    result = pqc_probe.probe_group('openssl','site.example','2001:4860:4860::8888',443,'X25519MLKEM768')
    assert result['status'] == 'negotiated'
    args = seen[0]
    assert args[args.index('-connect')+1] == '[2001:4860:4860::8888]:443'
    assert args[args.index('-servername')+1] == 'site.example'
    assert args[args.index('-groups')+1] == 'X25519MLKEM768'
    assert '-proxy' not in args


def test_subprocess_output_and_time_are_bounded():
    result = pqc_probe.run_bounded([sys.executable,'-c','import sys; sys.stdout.write("x"*200000)'],1)
    assert result['reason'] == 'output_limit'
    assert len(result['text']) == pqc_probe.MAX_OUTPUT
    result = pqc_probe.run_bounded([sys.executable,'-c','import time; time.sleep(4)'],.1)
    assert result['reason'] == 'timeout'


def test_html_and_headers_environment_hints():
    env = discover_environment({'x-vercel-id':'fixture','x-powered-by':'Next.js'}, '<script src="/_next/static/chunks/app.js"></script>')
    assert any(s['value']=='Next.js / Node.js' for s in env['signals'])
    assert any(s['value']=='Vercel edge' for s in env['signals'])
    assert env['origin_provider'] is None and env['deployment_method'] is None
    assert discover_environment({}, '<p>We discuss Next.js and WordPress here.</p>')['signals'] == []


def test_auto_plan_inputs_and_algorithm_roles():
    network = {'id':'net','kind':'network','created_at':'2026-01-01','result':{'target':'test.example:443','protocol':'TLSv1.3','certificate':{'public_key':'RSAPublicKey-2048'},'deployment':{'headers':{'x-powered-by':'Express','cf-ray':'edge'}}}}
    source = {'id':'src','kind':'code','result':{'dependencies':[{'file':'requirements.txt','requirement':'psycopg>=3'},{'file':'requirements.txt','requirement':'fastapi>=0.1'}], 'findings':[{'primitive':'RSA-2048','file':'app.py','line':10},{'primitive':'AES-256','file':'crypto.py'}]}}
    inputs = {'database':'unknown','stack':None,'current_host':None,'target_host':None,'application_count':1,'traffic':None,'data_gb':None,'transfer_mbps':None}
    plan = build_plan([network,source],inputs)
    assert plan['inputs']['database'] == 'postgresql'
    assert 'FastAPI' in plan['inputs']['stack'] and 'Express' in plan['inputs']['stack']
    assert plan['input_sources']['database'] == 'inferred_from_linked_driver_dependency'
    assert plan['inputs']['current_host'] is None  # Never turn a CDN into an origin claim.
    assert inputs['database'] == 'unknown'  # Do not mutate caller input.
    rows = plan['cryptographic_migration']['upgrades']
    assert any(u['current']=='RSA-2048' and 'ML-KEM' in u['target'] for u in rows)
    assert any(u['current']=='RSA-2048' and 'ML-DSA' in u['target'] for u in rows)
    assert all('ML-KEM' not in u['target'] for u in rows if 'signatures' in u['role'].lower())
    assert next(u for u in rows if u['current']=='AES-256')['target'].startswith('AES-256')
    assert plan['traffic']['average_daily_requests'] is None
    override = build_plan([network,source],dict(inputs,stack='Owner verified stack',database='mysql'))
    assert override['inputs']['stack'] == 'Owner verified stack'
    assert override['inputs']['database'] == 'mysql'


def test_html_sampler_no_redirect_and_no_execution(monkeypatch):
    class Conn:
        def __init__(self, raw): self.raw=raw; self.requests=[]
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def settimeout(self,*args): pass
        def sendall(self,data): self.requests.append(data)
        def recv(self,size): part=self.raw[:size]; self.raw=self.raw[size:]; return part
    body=b'<script src="/_next/static/app.js"></script>'
    conn=Conn(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
    monkeypatch.setattr('engine.website_inspector._handshake',lambda *a:conn)
    result=inspect_html('test.example',443,(socket.AF_INET,('1.1.1.1',443)))
    assert any(s['value']=='Next.js / Node.js' for s in result['signals'])
    assert len(conn.requests)==1
    conn=Conn(b'HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/secrets\r\n\r\n')
    monkeypatch.setattr('engine.website_inspector._handshake',lambda *a:conn)
    assert inspect_html('test.example',443,(socket.AF_INET,('1.1.1.1',443)))['status']=='skipped'
    assert len(conn.requests)==1


@pytest.mark.parametrize('label', ['Server Temp Key', 'Peer Temp Key'])
def test_classical_summary_across_openssl_versions(monkeypatch, label):
    summary = f'CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384\n{label}: X25519, 253 bits\n'
    monkeypatch.setattr(pqc_probe, 'run_bounded', lambda *args: {'text': summary, 'reason': None})
    assert pqc_probe.probe_group('openssl', 'localhost', '127.0.0.1', 443, 'X25519')['status'] == 'negotiated'
    assert not pqc_probe.handshake_evidence(summary.rstrip('\n'))
