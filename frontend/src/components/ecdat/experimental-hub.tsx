"use client";

import { useState, useEffect } from "react";
import {
  Activity,
  Cpu,
  Radio,
  Sparkles,
  GitPullRequest,
  Calculator,
  Binary,
  Play,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  ShieldAlert,
  Loader2,
  ExternalLink,
  Upload,
  Copy,
  Check,
  ShieldCheck,
} from "lucide-react";
import {
  requestApi,
  QuantumResourceEstimate,
  BenchmarkMetrics,
  CustomCryptoFinding,
  MigrationPatch,
} from "@/lib/api";

interface ExperimentalHubProps {
  project: string;
  token: string;
  initialTab?: "runtime" | "pcap" | "custom" | "autopatch" | "quantum" | "binary_ml";
  hideTabBar?: boolean;
}

export function ExperimentalHub({ project, token, initialTab = "quantum", hideTabBar = false }: ExperimentalHubProps) {
  const [activeTab, setActiveTab] = useState<
    "runtime" | "pcap" | "custom" | "autopatch" | "quantum" | "binary_ml"
  >(initialTab);

  // Sync initialTab when prop changes
  useEffect(() => {
    if (initialTab) {
      setActiveTab(initialTab);
    }
  }, [initialTab]);

  // Quantum Estimator State
  const [targetAlgo, setTargetAlgo] = useState("RSA-2048");
  const [errorRate, setErrorRate] = useState(0.001);
  const [cycleTime, setCycleTime] = useState(1.0);
  const [quantumResult, setQuantumResult] = useState<QuantumResourceEstimate | null>(null);
  const [loadingQuantum, setLoadingQuantum] = useState(false);

  // Custom Crypto State
  const [customCode, setCustomCode] = useState(
    `def encrypt_payload(data: bytes, key: bytes) -> bytes:\n    # Ad-hoc rolling XOR cipher\n    out = bytearray()\n    for i, b in enumerate(data):\n        out.append(b ^ key[i % len(key)] ^ ((i * 17) & 0xFF))\n    return bytes(out)`
  );
  const [customFinding, setCustomFinding] = useState<CustomCryptoFinding | null>(null);
  const [benchmarkMetrics, setBenchmarkMetrics] = useState<BenchmarkMetrics | null>(null);
  const [loadingCustom, setLoadingCustom] = useState(false);

  // Auto Patch State
  const [patchSource, setPatchSource] = useState(
    `import hashlib\ndef process_login(password: str):\n    # Weak legacy MD5 hash\n    token = hashlib.md5(password.encode()).hexdigest()\n    return token`
  );
  const [generatedPatch, setGeneratedPatch] = useState<MigrationPatch | null>(null);
  const [loadingPatch, setLoadingPatch] = useState(false);

  // Runtime / eBPF State
  const [runtimeResult, setRuntimeResult] = useState<any | null>(null);
  const [loadingRuntime, setLoadingRuntime] = useState(false);

  // PCAP State
  const [pcapResult, setPcapResult] = useState<any | null>(null);
  const [loadingPcap, setLoadingPcap] = useState(false);

  // Binary ML State
  const [binaryHex, setBinaryHex] = useState(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0" +
      "4889e54883ec2048897df8488975f0488b45f831c0eb0a488b55f04889d0"
  );
  const [binaryResult, setBinaryResult] = useState<any | null>(null);
  const [loadingBinary, setLoadingBinary] = useState(false);

  // Handlers
  async function handleEstimateQuantum() {
    setLoadingQuantum(true);
    try {
      const res = await requestApi<QuantumResourceEstimate>(
        "/risk/quantum-estimation",
        project,
        token,
        {
          target_algorithm: targetAlgo,
          physical_error_rate: errorRate,
          cycle_time_us: cycleTime,
        }
      );
      setQuantumResult(res);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setLoadingQuantum(false);
    }
  }

  async function handleAnalyzeCustomCrypto() {
    setLoadingCustom(true);
    try {
      const res = await requestApi<CustomCryptoFinding>(
        "/experimental/custom-crypto",
        project,
        token,
        { code: customCode, file_path: "service.py" }
      );
      setCustomFinding(res);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setLoadingCustom(false);
    }
  }

  async function handleRunBenchmark() {
    setLoadingCustom(true);
    try {
      const res = await requestApi<BenchmarkMetrics>(
        "/experimental/custom-crypto/benchmark",
        project,
        token
      );
      setBenchmarkMetrics(res);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setLoadingCustom(false);
    }
  }

  async function handleGeneratePatch() {
    setLoadingPatch(true);
    try {
      const res = await requestApi<MigrationPatch>(
        "/experimental/autopatch",
        project,
        token,
        { source_code: patchSource, file_path: "auth.py", language: "python", run_tests: true }
      );
      setGeneratedPatch(res);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setLoadingPatch(false);
    }
  }

  async function handleRunRuntimeTrace() {
    setLoadingRuntime(true);
    try {
      const res = await requestApi<any>(
        "/experimental/runtime-trace",
        project,
        token,
        {
          target_code:
            "import hashlib\ndef run(): return hashlib.sha256(b'payment_tx').hexdigest()\nrun()\n",
        }
      );
      setRuntimeResult(res);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setLoadingRuntime(false);
    }
  }

  const [pcapCopied, setPcapCopied] = useState<string | null>(null);

  async function handleRunSyntheticPcap(withPqc: boolean = true) {
    setLoadingPcap(true);
    try {
      const res = await requestApi<any>("/experimental/pcap", project, token, {
        with_pqc_hybrid: withPqc,
      });
      setPcapResult(res);
    } catch (err: any) {
      alert(err.message || "PCAP analysis failed");
    } finally {
      setLoadingPcap(false);
    }
  }

  async function handleUploadPcap(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setLoadingPcap(true);
    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      let hex = "";
      for (let i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, "0");
      }
      const res = await requestApi<any>("/experimental/pcap", project, token, {
        raw_hex: hex,
        file_name: file.name,
      });
      setPcapResult(res);
    } catch (err: any) {
      alert(err.message || "Failed to analyze PCAP file");
    } finally {
      setLoadingPcap(false);
    }
  }


  async function handleClassifyBinary() {
    setLoadingBinary(true);
    try {
      const res = await requestApi<any>(
        "/experimental/binary-ml",
        project,
        token,
        { raw_hex: binaryHex, file_name: "firmware_chunk.bin" }
      );
      setBinaryResult(res);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setLoadingBinary(false);
    }
  }

  const tabs = [
    { id: "quantum", label: "Quantum Estimation", icon: Calculator },
    { id: "custom", label: "Custom Crypto Detector", icon: Sparkles },
    { id: "autopatch", label: "Auto-Patch Engine", icon: GitPullRequest },
    { id: "runtime", label: "Runtime & eBPF", icon: Cpu },
    { id: "pcap", label: "Passive PCAP", icon: Radio },
    { id: "binary_ml", label: "Binary ML", icon: Binary },
  ] as const;

  return (
    <div className="space-y-6">
      {/* Header & Tabs */}
      {!hideTabBar && (
        <>
          <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-subtle pb-4">
            <div>
              <h2 className="text-xl font-bold flex items-center gap-2">
                <Sparkles className="text-cyan-400" size={22} />
                Experimental Innovations & Emerging Capabilities
              </h2>
              <p className="text-sm text-quiet">
                Cutting-edge capabilities from the ECDAT Architecture: runtime tracing, passive inspection,
                custom algorithm inference, and quantum resource estimation.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap gap-2 border-b border-subtle pb-3">
            {tabs.map((t) => {
              const Icon = t.icon;
              const isActive = activeTab === t.id;
              return (
                <button
                  key={t.id}
                  onClick={() => setActiveTab(t.id)}
                  className={`flex items-center gap-2 px-3.5 py-2 rounded-md text-sm font-medium transition-colors cursor-pointer ${
                    isActive
                      ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30"
                      : "text-quiet hover:text-foreground hover:bg-surface"
                  }`}
                >
                  <Icon size={16} />
                  {t.label}
                </button>
              );
            })}
          </div>
        </>
      )}

      {/* Tab: Quantum Resource Estimation */}
      {activeTab === "quantum" && (
        <div className="space-y-6">
          <div className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
            <h3 className="font-semibold text-foreground flex items-center gap-2">
              <Calculator size={18} className="text-cyan-400" />
              Shor's Algorithm Resource Estimator (Gidney & Ekerå 2021)
            </h3>
            <p className="text-sm text-quiet">
              Computes defensible computational resources (logical qubits, surface code distance,
              physical qubits, and execution runtime) required to break public-key mechanisms. Exposes
              all underlying mathematical assumptions.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <div>
                <label className="text-xs font-semibold uppercase tracking-wider text-quiet mb-1 block">
                  Target Algorithm
                </label>
                <select
                  value={targetAlgo}
                  onChange={(e) => setTargetAlgo(e.target.value)}
                  className="w-full rounded-md border border-subtle bg-canvas px-3 py-2 text-sm text-foreground"
                >
                  <option value="RSA-1024">RSA-1024 (Legacy Insecure)</option>
                  <option value="RSA-2048">RSA-2048 (Current Industry Standard)</option>
                  <option value="RSA-3072">RSA-3072 (NIST Minimum Classical)</option>
                  <option value="RSA-4096">RSA-4096 (High Classical Security)</option>
                  <option value="ECC-P256">ECC P-256 (NIST Curve)</option>
                  <option value="ED25519">Ed25519 (Edwards Curve)</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-semibold uppercase tracking-wider text-quiet mb-1 block">
                  Physical Error Rate (p)
                </label>
                <select
                  value={errorRate}
                  onChange={(e) => setErrorRate(parseFloat(e.target.value))}
                  className="w-full rounded-md border border-subtle bg-canvas px-3 py-2 text-sm text-foreground"
                >
                  <option value={0.001}>p = 10⁻³ (State-of-the-art Transmon)</option>
                  <option value={0.0001}>p = 10⁻⁴ (Fault-tolerant Target)</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-semibold uppercase tracking-wider text-quiet mb-1 block">
                  Surface Code Cycle Time (μs)
                </label>
                <input
                  type="number"
                  value={cycleTime}
                  onChange={(e) => setCycleTime(parseFloat(e.target.value) || 1.0)}
                  step="0.5"
                  min="0.1"
                  className="w-full rounded-md border border-subtle bg-canvas px-3 py-2 text-sm text-foreground"
                />
              </div>
            </div>

            <button
              onClick={handleEstimateQuantum}
              disabled={loadingQuantum}
              className="ec-button flex items-center gap-2 mt-2"
            >
              {loadingQuantum ? <Loader2 className="animate-spin" size={16} /> : <Play size={16} />}
              Calculate Quantum Resources
            </button>
          </div>

          {quantumResult && (
            <div className="rounded-lg border border-cyan-500/30 bg-cyan-950/10 p-5 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider text-cyan-400">
                  Resource Estimation Results · {quantumResult.target_algorithm}
                </span>
                <span className="text-xs text-quiet">
                  Estimated Runtime: {quantumResult.uncertainty_range_hours}
                </span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-3 rounded-md bg-canvas border border-subtle">
                  <div className="text-xs text-quiet">Logical Qubits</div>
                  <div className="text-xl font-mono font-bold text-foreground">
                    {quantumResult.logical_qubits.toLocaleString()}
                  </div>
                </div>
                <div className="p-3 rounded-md bg-canvas border border-subtle">
                  <div className="text-xs text-quiet">Physical Qubits (Surface Code)</div>
                  <div className="text-xl font-mono font-bold text-amber-400">
                    {(quantumResult.physical_qubits_estimate / 1e6).toFixed(1)}M qubits
                  </div>
                </div>
                <div className="p-3 rounded-md bg-canvas border border-subtle">
                  <div className="text-xs text-quiet">Surface Code Distance (d)</div>
                  <div className="text-xl font-mono font-bold text-foreground">
                    d = {quantumResult.surface_code_distance}
                  </div>
                </div>
                <div className="p-3 rounded-md bg-canvas border border-subtle">
                  <div className="text-xs text-quiet">Estimated Runtime</div>
                  <div className="text-xl font-mono font-bold text-emerald-400">
                    ~{quantumResult.estimated_runtime_hours} hrs
                  </div>
                </div>
              </div>

              <div className="text-xs text-quiet space-y-2 border-t border-subtle pt-3">
                <p className="font-semibold text-foreground">Scientific Literature Citations:</p>
                <ul className="list-disc pl-5 space-y-1">
                  {quantumResult.literature_citations.map((c, i) => (
                    <li key={i}>{c}</li>
                  ))}
                </ul>
                <p className="italic text-quiet pt-2">{quantumResult.disclaimer}</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Custom Crypto Detection */}
      {activeTab === "custom" && (
        <div className="space-y-6">
          <div className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
            <h3 className="font-semibold text-foreground flex items-center gap-2">
              <Sparkles size={18} className="text-cyan-400" />
              LLM & Semantic Hand-Rolled Crypto Detector
            </h3>
            <p className="text-sm text-quiet">
              Detects ad-hoc XOR rolling loops, mini Feistel ciphers, and custom PRNGs. Results are
              labeled explicitly as secondary INFERENCE requiring human review.
            </p>

            <textarea
              value={customCode}
              onChange={(e) => setCustomCode(e.target.value)}
              rows={6}
              className="w-full rounded-md border border-subtle bg-canvas p-3 text-xs font-mono text-foreground"
              placeholder="Paste custom candidate algorithm here..."
            />

            <div className="flex gap-3">
              <button
                onClick={handleAnalyzeCustomCrypto}
                disabled={loadingCustom}
                className="ec-button flex items-center gap-2"
              >
                {loadingCustom ? <Loader2 className="animate-spin" size={16} /> : <Play size={16} />}
                Analyze Candidate Snippet
              </button>

              <button
                onClick={handleRunBenchmark}
                disabled={loadingCustom}
                className="ec-button secondary flex items-center gap-2"
              >
                Run Evaluation Benchmark Suite
              </button>
            </div>
          </div>

          {customFinding && (
            <div
              className={`rounded-lg border p-4 space-y-2 ${
                customFinding.is_custom_crypto
                  ? "border-amber-500/30 bg-amber-950/10"
                  : "border-emerald-500/30 bg-emerald-950/10"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold flex items-center gap-2">
                  {customFinding.is_custom_crypto ? (
                    <AlertTriangle size={16} className="text-amber-400" />
                  ) : (
                    <CheckCircle2 size={16} className="text-emerald-400" />
                  )}
                  Classification: {customFinding.classification}
                </span>
                <span className="text-xs uppercase px-2 py-0.5 rounded bg-surface border border-subtle">
                  Confidence: {(customFinding.confidence * 100).toFixed(0)}% · Status: {customFinding.human_review_status}
                </span>
              </div>
              <p className="text-xs text-foreground">{customFinding.explanation}</p>
            </div>
          )}

          {benchmarkMetrics && (
            <div className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-subtle pb-2">
                <span className="font-semibold text-sm">Benchmark Precision / Recall Matrix</span>
                <span className="text-xs text-quiet">
                  Evaluated across {benchmarkMetrics.total_samples} curated test samples
                </span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-3 rounded bg-canvas border border-subtle text-center">
                  <div className="text-xs text-quiet">Precision</div>
                  <div className="text-lg font-bold text-cyan-400">
                    {(benchmarkMetrics.precision * 100).toFixed(1)}%
                  </div>
                </div>
                <div className="p-3 rounded bg-canvas border border-subtle text-center">
                  <div className="text-xs text-quiet">Recall</div>
                  <div className="text-lg font-bold text-emerald-400">
                    {(benchmarkMetrics.recall * 100).toFixed(1)}%
                  </div>
                </div>
                <div className="p-3 rounded bg-canvas border border-subtle text-center">
                  <div className="text-xs text-quiet">F1 Score</div>
                  <div className="text-lg font-bold text-foreground">
                    {(benchmarkMetrics.f1_score * 100).toFixed(1)}%
                  </div>
                </div>
                <div className="p-3 rounded bg-canvas border border-subtle text-center">
                  <div className="text-xs text-quiet">Accuracy</div>
                  <div className="text-lg font-bold text-foreground">
                    {(benchmarkMetrics.accuracy * 100).toFixed(1)}%
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Auto-Patch Engine */}
      {activeTab === "autopatch" && (
        <div className="space-y-6">
          <div className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
            <h3 className="font-semibold text-foreground flex items-center gap-2">
              <GitPullRequest size={18} className="text-cyan-400" />
              Deterministic Cryptographic Auto-Patch Engine
            </h3>
            <p className="text-sm text-quiet">
              Generates safe, template-driven transformations (e.g. MD5 → SHA-256, RSA-1024 →
              RSA-3072/ML-KEM), produces unified git diffs, and executes differential regression tests.
            </p>

            <textarea
              value={patchSource}
              onChange={(e) => setPatchSource(e.target.value)}
              rows={5}
              className="w-full rounded-md border border-subtle bg-canvas p-3 text-xs font-mono text-foreground"
            />

            <button
              onClick={handleGeneratePatch}
              disabled={loadingPatch}
              className="ec-button flex items-center gap-2"
            >
              {loadingPatch ? <Loader2 className="animate-spin" size={16} /> : <Play size={16} />}
              Generate Patch & Execute Regression Test
            </button>
          </div>

          {generatedPatch && (
            <div className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-subtle pb-3">
                <span className="text-sm font-bold text-foreground flex items-center gap-2">
                  <CheckCircle2 size={16} className="text-emerald-400" />
                  Pattern: {generatedPatch.pattern_id}
                </span>
                <span className="text-xs px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 font-medium">
                  Test Status: {generatedPatch.verification_status}
                </span>
              </div>

              <div>
                <span className="text-xs font-semibold text-quiet uppercase tracking-wider mb-1 block">
                  Unified Git Diff
                </span>
                <pre className="p-3 rounded bg-canvas border border-subtle text-xs font-mono text-foreground overflow-x-auto">
                  {generatedPatch.unified_diff}
                </pre>
              </div>

              <div>
                <span className="text-xs font-semibold text-quiet uppercase tracking-wider mb-1 block">
                  Regression Test Output
                </span>
                <pre className="p-3 rounded bg-canvas border border-subtle text-xs font-mono text-emerald-400">
                  {generatedPatch.test_output || "Verified cleanly."}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Runtime & eBPF */}
      {activeTab === "runtime" && (
        <div className="space-y-6">
          <div className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
            <h3 className="font-semibold text-foreground flex items-center gap-2">
              <Cpu size={18} className="text-cyan-400" />
              Runtime Crypto Tracing & eBPF Uprobes
            </h3>
            <p className="text-sm text-quiet">
              Observes live API invocations inside running Linux processes (libcrypto.so) or via
              LD_PRELOAD shim. Converts function calls into Unified EvidenceRecords.
            </p>

            <button
              onClick={handleRunRuntimeTrace}
              disabled={loadingRuntime}
              className="ec-button flex items-center gap-2"
            >
              {loadingRuntime ? <Loader2 className="animate-spin" size={16} /> : <Play size={16} />}
              Execute Controlled Runtime Trace
            </button>
          </div>

          {runtimeResult && (
            <div className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-subtle pb-2">
                <span className="text-sm font-bold text-foreground">
                  Runtime Observation Result · {runtimeResult.target_executable}
                </span>
                <span className="text-xs text-emerald-400 font-mono">
                  Events Captured: {runtimeResult.events?.length || 0}
                </span>
              </div>

              <div className="space-y-2">
                {runtimeResult.events?.map((ev: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded bg-canvas border border-subtle flex items-center justify-between text-xs"
                  >
                    <span className="font-mono text-cyan-400">{ev.function}()</span>
                    <span className="font-bold text-foreground">{ev.algorithm}</span>
                    <span className="text-quiet">{ev.role}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Passive PCAP */}
      {activeTab === "pcap" && (
        <div className="space-y-6">
          <div className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
            <h3 className="font-semibold text-foreground flex items-center gap-2">
              <Radio size={18} className="text-cyan-400" />
              Passive Network Discovery (PCAP Dissection)
            </h3>
            <p className="text-sm text-quiet">
              Extracts ClientHello, ServerHello, supported curves/groups, and JA3/JA4 fingerprints from
              authorized packet captures without active port probing. Supports TLS 1.2, TLS 1.3, and
              FIPS 203 ML-KEM hybrid key exchanges.
            </p>

            <div className="flex flex-wrap items-center gap-3 pt-1">
              <button
                onClick={() => handleRunSyntheticPcap(true)}
                disabled={loadingPcap}
                className="ec-button flex items-center gap-2"
              >
                {loadingPcap ? <Loader2 className="animate-spin" size={16} /> : <Play size={16} />}
                Simulate PQC Hybrid Handshake (X25519MLKEM768)
              </button>

              <button
                onClick={() => handleRunSyntheticPcap(false)}
                disabled={loadingPcap}
                className="ec-button secondary flex items-center gap-2"
              >
                {loadingPcap ? <Loader2 className="animate-spin" size={16} /> : <Play size={16} />}
                Simulate Classical Handshake (secp256r1)
              </button>

              <label className="ec-button secondary flex items-center gap-2 cursor-pointer">
                <Upload size={16} />
                <span>Upload PCAP File</span>
                <input
                  type="file"
                  accept=".pcap,.cap,.pcapng"
                  className="hidden"
                  onChange={handleUploadPcap}
                  disabled={loadingPcap}
                />
              </label>
            </div>
          </div>

          {pcapResult && (
            <div className="space-y-4">
              {/* Metric Badges */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center text-xs">
                <div className="p-3 rounded-lg bg-surface border border-subtle">
                  <div className="text-quiet mb-1">Packets Analyzed</div>
                  <div className="text-lg font-bold text-foreground">
                    {pcapResult.packets_analyzed ?? 0}
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-surface border border-subtle">
                  <div className="text-quiet mb-1">TLS Handshakes</div>
                  <div className="text-lg font-bold text-cyan-400">
                    {pcapResult.tls_handshakes_detected ?? 0}
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-surface border border-subtle">
                  <div className="text-quiet mb-1">PQC Hybrid Sessions</div>
                  <div className="text-lg font-bold text-emerald-400">
                    {pcapResult.pqc_sessions_count ?? 0}
                  </div>
                </div>
                <div className="p-3 rounded-lg bg-surface border border-subtle">
                  <div className="text-quiet mb-1">Quantum Vulnerable</div>
                  <div className="text-lg font-bold text-amber-400">
                    {pcapResult.quantum_vulnerable_count ?? 0}
                  </div>
                </div>
              </div>

              {/* Sessions Breakdown */}
              {Array.isArray(pcapResult.sessions) && pcapResult.sessions.length > 0 && (
                <div className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
                  <h4 className="font-semibold text-sm text-foreground flex items-center gap-2">
                    <Radio size={16} className="text-cyan-400" />
                    Dissected Handshake Sessions ({pcapResult.sessions.length})
                  </h4>

                  <div className="space-y-3">
                    {pcapResult.sessions.map((sess: any, idx: number) => (
                      <div
                        key={idx}
                        className="p-4 rounded-lg border border-subtle bg-canvas space-y-3 text-xs"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-subtle pb-2">
                          <div className="font-mono text-foreground font-semibold flex items-center gap-2">
                            <span>{sess.client_ip}:{sess.client_port}</span>
                            <span className="text-quiet">➔</span>
                            <span className="text-cyan-400">{sess.server_ip}:{sess.server_port}</span>
                            {sess.sni && (
                              <span className="px-2 py-0.5 rounded bg-surface border border-subtle text-quiet text-[11px]">
                                SNI: {sess.sni}
                              </span>
                            )}
                          </div>

                          <div className="flex items-center gap-2">
                            {sess.has_pqc_hybrid ? (
                              <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-semibold border border-emerald-500/20 flex items-center gap-1">
                                <ShieldCheck size={12} /> Post-Quantum Hybrid
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 font-semibold border border-amber-500/20 flex items-center gap-1">
                                <ShieldAlert size={12} /> Classical Only
                              </span>
                            )}
                          </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[12px]">
                          <div>
                            <span className="text-quiet block mb-0.5 font-medium">Negotiated Cipher Suite:</span>
                            <span className="font-mono text-foreground font-semibold">
                              {sess.selected_cipher || "N/A"}
                            </span>
                          </div>

                          <div>
                            <span className="text-quiet block mb-0.5 font-medium">Key Exchange Groups:</span>
                            <div className="flex flex-wrap gap-1">
                              {sess.supported_groups?.map((g: string, gIdx: number) => (
                                <span
                                  key={gIdx}
                                  className={`font-mono px-1.5 py-0.5 rounded text-[11px] ${
                                    g.includes("MLKEM")
                                      ? "bg-emerald-500/15 text-emerald-400 font-bold border border-emerald-500/30"
                                      : "bg-surface text-quiet border border-subtle"
                                  }`}
                                >
                                  {g}
                                </span>
                              )) || <span className="text-quiet">None detected</span>}
                            </div>
                          </div>
                        </div>

                        {/* Fingerprints */}
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-2 border-t border-subtle/50 text-[11px]">
                          {sess.ja3_fingerprint && (
                            <div className="flex items-center justify-between p-2 rounded bg-surface border border-subtle">
                              <div className="truncate mr-2">
                                <span className="text-quiet font-bold">JA3: </span>
                                <span className="font-mono text-cyan-400">{sess.ja3_fingerprint}</span>
                              </div>
                              <button
                                onClick={() => {
                                  navigator.clipboard.writeText(sess.ja3_fingerprint);
                                  setPcapCopied(`ja3-${idx}`);
                                  setTimeout(() => setPcapCopied(null), 1500);
                                }}
                                className="text-quiet hover:text-foreground p-1"
                                title="Copy JA3"
                              >
                                {pcapCopied === `ja3-${idx}` ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                              </button>
                            </div>
                          )}

                          {sess.ja4_fingerprint && (
                            <div className="flex items-center justify-between p-2 rounded bg-surface border border-subtle">
                              <div className="truncate mr-2">
                                <span className="text-quiet font-bold">JA4: </span>
                                <span className="font-mono text-emerald-400">{sess.ja4_fingerprint}</span>
                              </div>
                              <button
                                onClick={() => {
                                  navigator.clipboard.writeText(sess.ja4_fingerprint);
                                  setPcapCopied(`ja4-${idx}`);
                                  setTimeout(() => setPcapCopied(null), 1500);
                                }}
                                className="text-quiet hover:text-foreground p-1"
                                title="Copy JA4"
                              >
                                {pcapCopied === `ja4-${idx}` ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Evidence Records */}
              {Array.isArray(pcapResult.evidence_records) && pcapResult.evidence_records.length > 0 && (
                <div className="rounded-lg border border-subtle bg-surface p-5 space-y-3">
                  <h4 className="font-semibold text-sm text-foreground flex items-center gap-2">
                    <ShieldCheck size={16} className="text-emerald-400" />
                    Generated Evidence Records ({pcapResult.evidence_records.length})
                  </h4>
                  <div className="space-y-2">
                    {pcapResult.evidence_records.map((ev: any, idx: number) => (
                      <div
                        key={idx}
                        className="p-3 rounded bg-canvas border border-subtle flex flex-col sm:flex-row sm:items-center justify-between text-xs gap-2"
                      >
                        <div>
                          <span className="font-mono font-bold text-cyan-400">{ev.algorithm}</span>
                          <span className="text-quiet ml-2">({ev.cryptographic_role})</span>
                          <p className="text-quiet text-[11px] mt-0.5">{ev.description}</p>
                        </div>
                        <span className="px-2 py-0.5 rounded bg-surface border border-subtle text-quiet text-[11px] self-start sm:self-center">
                          Confidence: {ev.confidence}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Raw JSON */}
              <div className="rounded-lg border border-subtle bg-surface p-5 space-y-3">
                <span className="text-sm font-bold text-foreground">Raw PCAP Dissection Payload</span>
                <pre className="p-3 rounded bg-canvas border border-subtle text-xs font-mono text-foreground overflow-x-auto max-h-72">
                  {JSON.stringify(pcapResult, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}


      {/* Tab: Binary ML */}
      {activeTab === "binary_ml" && (
        <div className="space-y-6">
          <div className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
            <h3 className="font-semibold text-foreground flex items-center gap-2">
              <Binary size={18} className="text-cyan-400" />
              Deep Binary ML Classifier & Entropy Profiler
            </h3>
            <p className="text-sm text-quiet">
              Calculates Shannon entropy profiles, chi-square randomness statistics, and opcode density
              vectors (XOR, bitwise shifts) to detect compiled cryptographic primitives.
            </p>

            <div>
              <label className="text-xs font-semibold text-quiet uppercase tracking-wider mb-1 block">
                Hex Chunk Payload
              </label>
              <textarea
                value={binaryHex}
                onChange={(e) => setBinaryHex(e.target.value)}
                rows={3}
                className="w-full rounded-md border border-subtle bg-canvas p-3 text-xs font-mono text-foreground"
              />
            </div>

            <button
              onClick={handleClassifyBinary}
              disabled={loadingBinary}
              className="ec-button flex items-center gap-2"
            >
              {loadingBinary ? <Loader2 className="animate-spin" size={16} /> : <Play size={16} />}
              Analyze Binary Feature Vector
            </button>
          </div>

          {binaryResult && (
            <div className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-subtle pb-2">
                <span className="text-sm font-bold text-foreground">
                  Prediction: {binaryResult.predicted_category}
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400">
                  Probability: {(binaryResult.crypto_probability * 100).toFixed(0)}% (Confidence:{" "}
                  {binaryResult.confidence_level})
                </span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="p-2.5 rounded bg-canvas border border-subtle text-xs">
                  <div className="text-quiet">Overall Entropy</div>
                  <div className="font-mono font-bold text-foreground">
                    {binaryResult.feature_vector?.overall_entropy}
                  </div>
                </div>
                <div className="p-2.5 rounded bg-canvas border border-subtle text-xs">
                  <div className="text-quiet">Chi-Square Stat</div>
                  <div className="font-mono font-bold text-foreground">
                    {binaryResult.feature_vector?.chi_square_stat}
                  </div>
                </div>
                <div className="p-2.5 rounded bg-canvas border border-subtle text-xs">
                  <div className="text-quiet">XOR Instruction Ratio</div>
                  <div className="font-mono font-bold text-foreground">
                    {((binaryResult.feature_vector?.xor_instruction_ratio || 0) * 100).toFixed(1)}%
                  </div>
                </div>
                <div className="p-2.5 rounded bg-canvas border border-subtle text-xs">
                  <div className="text-quiet">Bitshift Ratio</div>
                  <div className="font-mono font-bold text-foreground">
                    {((binaryResult.feature_vector?.bitshift_instruction_ratio || 0) * 100).toFixed(1)}%
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
