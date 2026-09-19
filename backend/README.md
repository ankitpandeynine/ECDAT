# ECDAT Backend Engine Documentation

The ECDAT backend is a high-performance Python FastAPI service providing evidence-based cryptographic discovery, post-quantum risk assessment, automated migration patching, and closed-loop differential verification.

---

## 1. Engine Modules Architecture

Located in `backend/engine/`:

- **`custom_loop.py`**: Orchestrates the autonomous one-click remediation loop (`CustomLoopRunner`). Automatically scans targets, generates CycloneDX 1.6 CBOM, assesses Mosca quantum risk, creates AST-safe migration patches, executes differential regression tests, and runs closed-loop verification.
- **`verifier.py`**: Implements the `ClosedLoopVerifier` comparing baseline evidence records with post-migration evidence records. Confirms retirement of deprecated primitives (MD5, DES, RSA-1024) and verifies that no regressions were introduced.
- **`patch_engine.py`**: The `AutoPatchEngine` provides deterministic cryptographic migration templates and executes differential regression test scripts via isolated subprocesses.
- **`quantum_estimator.py`**: The `QuantumResourceEstimator` computes the exact resources required by Shor's algorithm (logical qubits, physical qubits on surface codes, Toffoli gates, time-to-break) across variable physical error rates.
- **`quantum_risk.py`**: Implements Mosca's Theorem ($X + Y > Z$) and Harvest-Now, Decrypt-Later (HNDL) risk calculations.
- **`standards_mapping.py`**: Exposes regulatory compliance matrices mapping findings to NIST FIPS 203/204/205, NSA CNSA 2.0, BSI TR-02102, and PCI-DSS 4.0.
- **`runtime_tracer.py`**: Dynamic execution tracer capturing live cryptographic calls (e.g., OpenSSL `MD5`, `RSA_generate_key_ex`, Python `hashlib`).
- **`ebpf_tracer.py`**: Inspects kernel eBPF probe capabilities and instruments production containers via uprobes.
- **`binary_classifier.py`**: The `BinaryMLClassifier` extracts statistical and ML feature vectors (Shannon entropy, byte chi-square, opcode ratios) to identify hidden/stripped crypto in binaries.
- **`pcap_engine.py`**: Pure-Python PCAP parser dissecting TLS 1.2/1.3 handshakes, JA3/JA4 fingerprints, and post-quantum hybrid key exchange groups (`X25519MLKEM768`).
- **`source_scan.py` & `polyglot_scanner.py`**: AST and regex scanners detecting cryptographic primitives across Python, C/C++, Java, Go, JS/TS, and Rust.
- **`binary_deep.py`**: Deep binary analyzer parsing ELF sections, PE headers, crypto constants, and embedded keys.
- **`website_inspector.py`**: Active network TLS scanner enumerating cipher suites, TLS protocol versions, and X.509 certificate chains.
- **`cbom_generator.py`**: Generates schema-compliant CycloneDX 1.6 Cryptography Bill of Materials (CBOM).
- **`knowledge_graph.py` & `correlator.py`**: Builds the Crypto Asset Knowledge Graph with 5-tier cross-surface evidence correlation and reverse BFS blast-radius calculations.
- **`gemini_assistant.py`**: Integrates with Google AI Studio / Gemini API for AI-assisted cryptographic triage, quantum risk explanation, and migration advisory.

---

## 2. Running Backend Locally

```bash
# From repository root:
source .venv/bin/activate
cd backend
PYTHONPATH=. python main.py
```

Server binds to `http://0.0.0.0:8000`.
Swagger interactive documentation: `http://localhost:8000/docs`.

---

## 3. Running Backend Tests

```bash
cd backend
PYTHONPATH=. ../.venv/bin/python -m pytest tests/ -v
```
All **690 tests** run in under 35 seconds.
