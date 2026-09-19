import pytest
from engine.demo_flow import SihDemoRunner
from fastapi.testclient import TestClient
from main import app


def test_sih_demo_flow_runner():
    demo = SihDemoRunner.run_full_flow()
    assert demo.status == "completed"
    assert demo.total_steps == 10
    assert len(demo.steps) == 10

    # Step 1: Scan
    assert demo.steps[0].step_number == 1
    assert "findings" in demo.steps[0].data

    # Step 3: CBOM
    assert demo.cbom["bomFormat"] == "CycloneDX"
    assert len(demo.cbom["components"]) >= 3

    # Step 9: Verification
    assert demo.verification.verdict.value == "VERIFIED"
    assert len(demo.verification.retired_weaknesses) >= 2


def test_sih_demo_api_endpoint(client):
    res = client.post("/api/demo/sih-flow")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert len(data["steps"]) == 10
    assert data["verification"]["verdict"] == "VERIFIED"
