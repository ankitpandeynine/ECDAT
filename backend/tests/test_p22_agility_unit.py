import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from starlette.testclient import TestClient
import uuid
import pytest

from main import app
from engine.asset_graph import AssetGraphService, CryptoAsset
from engine.scan_store import ScanStore
from engine.agility.models import (
    AgilityDimension,
    AgilityState,
    AgilityConfidence,
    ChangeComplexity,
    DimensionalAgility,
    CryptoChangeSurface,
    AgilityAssessment,
    AgilityReason,
)
from engine.agility.rules_engine import AgilityRulesEngine
from engine.agility.evidence import AgilityEvidenceItem, extract_confidence
from engine.agility.dimensions import (
    assess_algorithm_agility,
    assess_configuration_agility,
    assess_dependency_agility,
    assess_protocol_agility,
    assess_certificate_agility,
    assess_deployment_agility,
    assess_validation_agility,
)
from engine.agility.change_surface import calculate_change_surface
from engine.agility.explainability import build_agility_explainability_report
from engine.agility.agility_pipeline import evaluate_agility



@pytest.fixture
def temp_graph(tmp_path):
    db_path = str(tmp_path / "test_agility_graph.sqlite3")
    store = ScanStore(path=db_path)
    yield store.graph
    store.close()




class TestAgilityModels:
    def test_dimensions_enum(self):
        assert len(AgilityDimension) == 7
        assert AgilityDimension.AGILITY_ALGORITHM == "AGILITY_ALGORITHM"
        assert AgilityDimension.AGILITY_VALIDATION == "AGILITY_VALIDATION"

    def test_states_enum_and_rank(self):
        assert AgilityState.OBSERVED.rank > AgilityState.SUPPORTED.rank
        assert AgilityState.SUPPORTED.rank > AgilityState.PARTIALLY_OBSERVED.rank
        assert AgilityState.PARTIALLY_OBSERVED.rank > AgilityState.CONSTRAINED.rank
        assert AgilityState.CONSTRAINED.rank > AgilityState.BLOCKED.rank

    def test_dimensional_agility_serialization(self):
        reason = AgilityReason(
            dimension=AgilityDimension.AGILITY_ALGORITHM.value,
            step="TEST_STEP",
            claim="Algorithm is abstracted",
            rule_id="AGL-ALG-001",
        )
        dim = DimensionalAgility(
            dimension=AgilityDimension.AGILITY_ALGORITHM,
            state=AgilityState.OBSERVED,
            confidence=AgilityConfidence.MEASURED,
            evidence_refs=["ev-1"],
            supporting_evidence=["EVP provider used"],
            reason_chain=[reason],
            derived_score=1.0,
        )
        data = dim.to_dict()
        assert data["state"] == "OBSERVED"
        assert data["derived_score"] == 1.0

        deserialized = DimensionalAgility.from_dict(data)
        assert deserialized.state == AgilityState.OBSERVED
        assert deserialized.dimension == AgilityDimension.AGILITY_ALGORITHM
        assert len(deserialized.reason_chain) == 1

    def test_change_surface_serialization(self):
        surf = CryptoChangeSurface(
            asset_id="asset-123",
            affected_files=["src/crypto.py"],
            affected_modules=["src"],
            call_sites_count=3,
            complexity=ChangeComplexity.LOW,
        )
        data = surf.to_dict()
        assert data["asset_id"] == "asset-123"
        assert data["complexity"] == "LOW"

        deserialized = CryptoChangeSurface.from_dict(data)
        assert deserialized.complexity == ChangeComplexity.LOW
        assert deserialized.affected_files == ["src/crypto.py"]


class TestRulesEngine:
    def test_rules_engine_loads_rules(self):
        engine = AgilityRulesEngine()
        assert engine.version == "2024.1"
        assert len(engine.rules) > 10

    def test_get_rules_for_dimension(self):
        engine = AgilityRulesEngine()
        alg_rules = engine.get_rules_for_dimension(AgilityDimension.AGILITY_ALGORITHM)
        assert len(alg_rules) >= 4
        assert any(r["rule_id"] == "AGL-ALG-001" for r in alg_rules)


class TestDimensionalAnalyzers:
    def test_algorithm_agility_abstraction(self):
        ev = [
            AgilityEvidenceItem({
                "id": "ev-1",
                "observation_type": "SOURCE_API_USE",
                "description": "Provider abstraction via EVP_default_properties_set observed",
                "state": "MEASURED",
                "level": "E4",
            })
        ]
        res = assess_algorithm_agility({"id": "a-1"}, ev)
        assert res.state in (AgilityState.OBSERVED, AgilityState.SUPPORTED)
        assert res.confidence == AgilityConfidence.MEASURED

    def test_algorithm_agility_hardcoded(self):
        ev = [
            AgilityEvidenceItem({
                "id": "ev-2",
                "observation_type": "SOURCE_API_USE",
                "description": "Direct call to AES_encrypt primitive",
                "state": "MEASURED",
                "level": "E3",
            })
        ]
        res = assess_algorithm_agility({"id": "a-2"}, ev)
        assert res.state == AgilityState.CONSTRAINED

    def test_configuration_agility_env_var(self):
        ev = [
            AgilityEvidenceItem({
                "id": "ev-3",
                "observation_type": "CONFIGURATION",
                "description": "Loaded cipher suite from environment variable CIPHER_NAME",
                "state": "INFERRED",
                "level": "E2",
            })
        ]
        res = assess_configuration_agility({"id": "a-3"}, ev)
        assert res.state == AgilityState.SUPPORTED

    def test_configuration_agility_fallback(self):
        ev = [
            AgilityEvidenceItem({
                "id": "ev-4a",
                "description": "Loaded from config_file settings.yaml",
                "state": "INFERRED",
                "level": "E2",
            }),
            AgilityEvidenceItem({
                "id": "ev-4b",
                "description": "Hardcoded fallback to AES-128 if missing",
                "state": "INFERRED",
                "level": "E2",
            })
        ]
        res = assess_configuration_agility({"id": "a-4"}, ev)
        assert res.state == AgilityState.PARTIALLY_OBSERVED

    def test_dependency_agility_package(self):
        ev = [
            AgilityEvidenceItem({
                "id": "ev-5",
                "description": "Standard package manager dependency declaration in requirements.txt",
                "state": "MEASURED",
                "level": "E3",
            })
        ]
        res = assess_dependency_agility({"id": "a-5"}, ev)
        assert res.state == AgilityState.SUPPORTED

    def test_protocol_agility_tls(self):
        ev = [
            AgilityEvidenceItem({
                "id": "ev-6",
                "description": "Live TLS negotiation observed with dynamic runtime cipher selection",
                "state": "MEASURED",
                "level": "E5",
            })
        ]
        res = assess_protocol_agility({"id": "a-6", "asset_type": "ENDPOINT"}, ev)
        assert res.state == AgilityState.OBSERVED

    def test_protocol_agility_not_applicable(self):
        # Pure symmetric cipher asset has no protocol context
        res = assess_protocol_agility({"id": "a-7", "asset_type": "ALGORITHM"}, [])
        assert res.state == AgilityState.NOT_APPLICABLE

    def test_certificate_agility_acme(self):
        ev = [
            AgilityEvidenceItem({
                "id": "ev-8",
                "description": "Automated certificate rotation via ACME protocol verified",
                "state": "MEASURED",
                "level": "E4",
            })
        ]
        res = assess_certificate_agility({"id": "a-8", "asset_type": "CERTIFICATE"}, ev)
        assert res.state == AgilityState.OBSERVED

    def test_deployment_agility_container(self):
        ev = [
            AgilityEvidenceItem({
                "id": "ev-9",
                "description": "Service deployed as container image with externalized configuration",
                "state": "MEASURED",
                "level": "E3",
            })
        ]
        res = assess_deployment_agility({"id": "a-9"}, ev)
        assert res.state == AgilityState.SUPPORTED

    def test_validation_agility_crypto_tests(self):
        ev = [
            AgilityEvidenceItem({
                "id": "ev-10",
                "description": "Dedicated crypto test suite with CAVP test vectors verified",
                "state": "MEASURED",
                "level": "E4",
            })
        ]
        res = assess_validation_agility({"id": "a-10"}, ev)
        assert res.state == AgilityState.OBSERVED


class TestAgilityPipelineAndPersistence:
    def test_pipeline_evaluation(self, temp_graph):
        asset = {"id": "test-asset-1", "name": "AES-GCM", "asset_type": "ALGORITHM"}
        evidence = [
            {
                "id": "ev-pipe-1",
                "description": "Provider abstraction EVP_CIPHER_CTX used",
                "state": "MEASURED",
                "level": "E4",
                "file_path": "src/crypto/aes.py",
            },
            {
                "id": "ev-pipe-2",
                "description": "Configuration option env_var CRYPTO_CIPHER",
                "state": "INFERRED",
                "level": "E2",
                "file_path": "src/config.py",
            }
        ]
        assessment = evaluate_agility(asset, evidence, graph_service=temp_graph)
        assert assessment.asset_id == "test-asset-1"
        assert assessment.overall_state in (AgilityState.SUPPORTED, AgilityState.OBSERVED)
        assert assessment.composite_score is not None
        assert assessment.derived_score_metadata["is_derived"] is True
        assert len(assessment.dimensions) == 7
        assert assessment.change_surface is not None
        assert "src/crypto/aes.py" in assessment.change_surface.affected_files

    def test_asset_graph_persistence_roundtrip(self, temp_graph):
        asset = {"id": "asset-persist-1", "name": "RSA-Sign", "asset_type": "ALGORITHM"}
        evidence = [{"id": "ev-p1", "description": "direct_primitive call", "state": "MEASURED", "level": "E3"}]
        assessment = evaluate_agility(asset, evidence)

        aid = temp_graph.save_agility_assessment(assessment)
        assert aid == assessment.assessment_id

        retrieved = temp_graph.get_agility_assessment("asset-persist-1")
        assert retrieved is not None
        assert retrieved["asset_id"] == "asset-persist-1"
        assert retrieved["overall_state"] == assessment.overall_state.value
        assert "AGILITY_ALGORITHM" in retrieved["dimensions"]

        surf = temp_graph.get_change_surface("asset-persist-1")
        assert surf is not None
        assert surf["asset_id"] == "asset-persist-1"


class TestAgilityAPIEndpoints:
    def test_legacy_agility_endpoint_untouched(self):
        with TestClient(app) as client:
            resp = client.post("/api/agility/evaluate", json={
                "hardcoded_primitives_count": 2,
                "abstracted_primitives_count": 8,
                "has_provider_abstraction": True,
                "has_pqc_hybrid_support": False,
                "automated_cert_rotation": True,
                "uses_config_driven_crypto": True,
            })
            assert resp.status_code == 200
            data = resp.json()
            assert "cai_score" in data
            assert "tier" in data
            assert "pillars" in data

    def test_evaluate_v2_endpoint(self):
        with TestClient(app) as client:
            resp = client.post("/api/agility/evaluate-v2", json={
                "asset": {"id": "api-asset-1", "name": "ChaCha20", "asset_type": "ALGORITHM"},
                "evidence": [
                    {
                        "id": "ev-api-1",
                        "description": "Loaded via crypto_factory abstraction",
                        "state": "MEASURED",
                        "level": "E4",
                    }
                ],
                "context": {"uses_config_driven_crypto": True}
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["asset_id"] == "api-asset-1"
            assert "overall_state" in data
            assert "dimensions" in data
            assert len(data["dimensions"]) == 7
            assert "change_surface" in data
