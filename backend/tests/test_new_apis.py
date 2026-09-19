"""
Tests for newly added FastAPI endpoints: Auth, Projects, Archive Lab, Reports.
"""
from fastapi.testclient import TestClient
import pytest
from main import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_auth_and_session_api(client):
    # 1. Login with default admin
    res = client.post('/api/auth/login', json={'email': 'admin@ecdat.local', 'password': 'admin123'})
    assert res.status_code == 200
    data = res.json()
    assert data['email'] == 'admin@ecdat.local'
    assert data['role'] == 'OWNER'
    token = data['token']

    # 2. Get current user
    me = client.get('/api/auth/me', headers={'Authorization': f'Bearer {token}'})
    assert me.status_code == 200
    assert me.json()['email'] == 'admin@ecdat.local'

    import uuid
    test_email = f"analyst-{uuid.uuid4().hex[:6]}@enterprise.com"
    # 3. Register a new user
    reg = client.post('/api/auth/register', json={
        'email': test_email,
        'password': 'SecurePassword2026!',
        'name': 'Alex Rivera',
        'role': 'SECURITY_ANALYST'
    })
    assert reg.status_code == 200
    assert reg.json()['email'] == test_email

    # 4. Logout
    logout = client.post('/api/auth/logout', headers={'Authorization': f'Bearer {token}'})
    assert logout.status_code == 200


def test_project_crud_api(client):
    # List projects
    res = client.get('/api/projects')
    assert res.status_code == 200
    projs = res.json()
    assert any(p['id'] == 'default' for p in projs)

    # Create project
    create_res = client.post('/api/projects', json={
        'id': 'api-test-proj',
        'name': 'Critical Infrastructure Node 1',
        'organization': 'National Cyber Division',
        'environment': 'Production',
        'business_criticality': 'Critical',
        'data_sensitivity': 'Classified',
        'data_lifetime_years': 25.0,
        'tags': ['energy', 'scada', 'pqc-phase1']
    })
    assert create_res.status_code == 201
    p = create_res.json()
    assert p['name'] == 'Critical Infrastructure Node 1'
    assert p['business_criticality'] == 'Critical'

    # Get single project
    get_res = client.get('/api/projects/api-test-proj')
    assert get_res.status_code == 200
    assert get_res.json()['id'] == 'api-test-proj'

    # Update project
    patch_res = client.patch('/api/projects/api-test-proj', json={'description': 'Updated operational description'})
    assert patch_res.status_code == 200
    assert patch_res.json()['description'] == 'Updated operational description'

    # Delete project
    del_res = client.delete('/api/projects/api-test-proj')
    assert del_res.status_code == 200
    assert client.get('/api/projects/api-test-proj').status_code == 404


def test_archive_lab_api(client):
    # Analyze archive
    res = client.post('/api/archive/analyze', json={'file_name': 'test.zip', 'project_id': 'default'})
    assert res.status_code == 200
    data = res.json()
    assert data['format'] == 'ZIP'
    assert 'content_status' in data

    # Protect archive (create Password Vault)
    prot = client.post('/api/archive/protect', json={
        'plain_text': 'TOP SECRET OPERATIONAL PLAN',
        'mode': 'PASSWORD_VAULT',
        'password': 'VaultPassword123!',
        'vault_name': 'mission_vault.ecvault'
    })
    assert prot.status_code == 200
    container = prot.json()
    assert container['format'] == 'ECVAULT'
    assert container['mode'] == 'PASSWORD_VAULT'

    # Verify vault with correct password
    ver = client.post('/api/archive/verify', json={
        'container': container,
        'password': 'VaultPassword123!'
    })
    assert ver.status_code == 200
    assert ver.json()['status'] == 'VERIFIED'

    # Verify vault with wrong password
    ver_bad = client.post('/api/archive/verify', json={
        'container': container,
        'password': 'WrongPassword!'
    })
    assert ver_bad.status_code == 200
    assert ver_bad.json()['status'] == 'FAILED'


def test_reports_api(client):
    res_list = client.get('/api/projects/default/reports')
    assert res_list.status_code == 200
    assert len(res_list.json()['supported_report_types']) >= 3

    gen = client.post('/api/projects/default/reports/generate', json={'report_type': 'EXECUTIVE_SUMMARY'})
    assert gen.status_code == 200
    data = gen.json()
    assert 'executive_summary' in data
    assert 'key_findings' in data


def test_empty_project_data_integrity(client):
    import uuid
    p_id = f"empty-integrity-{uuid.uuid4().hex[:6]}"
    client.post('/api/projects', json={'id': p_id, 'name': 'Empty Test Project'})
    
    # 1. Graph must be strictly empty (0 nodes, 0 links), NEVER mock nodes
    g_res = client.get(f'/api/projects/{p_id}/graph')
    assert g_res.status_code == 200
    g_data = g_res.json()
    assert len(g_data['nodes']) == 0
    assert len(g_data['links']) == 0

    # 2. Overview must have 0 assets, 0 findings, and empty action queue
    o_res = client.get(f'/api/projects/{p_id}/overview')
    assert o_res.status_code == 200
    o_data = o_res.json()
    assert o_data['kpis']['total_findings'] == 0
    assert o_data['asset_count'] == 0
    assert len(o_data['action_queue']) == 0


def test_demo_seeding_api(client):
    import uuid
    p_id = f"demo-seed-{uuid.uuid4().hex[:6]}"
    client.post('/api/projects', json={'id': p_id, 'name': 'Demo Seeding Project'})

    seed_res = client.post(f'/api/projects/{p_id}/demo/seed')
    assert seed_res.status_code == 200
    s_data = seed_res.json()
    assert s_data['status'] == 'demo_seeded'
    assert s_data['scans_created'] == 2

    # Verify real assets populated in graph and overview
    g_res = client.get(f'/api/projects/{p_id}/graph')
    assert g_res.status_code == 200
    g_data = g_res.json()
    assert len(g_data['nodes']) >= 2

    o_res = client.get(f'/api/projects/{p_id}/overview')
    assert o_res.status_code == 200
    o_data = o_res.json()
    assert len(o_data['action_queue']) >= 1
    assert "Shor" in o_data['action_queue'][0]['description']

