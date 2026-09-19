import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

backend_dir = Path(__file__).resolve().parents[1]
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from main import app

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('ECDAT_DB', str(tmp_path / 'scans.sqlite3'))
    monkeypatch.delenv('ECDAT_API_TOKEN', raising=False)
    with TestClient(app) as client:
        yield client
