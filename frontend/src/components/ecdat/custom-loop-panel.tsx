"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Binary,
  ShieldCheck,
  ArrowRight,
  Sparkles,
  Zap,
  Clock,
  ShieldAlert,
  Loader2,
  ExternalLink,
  ChevronRight,
  Terminal,
  Download,
  Flame,
  Layers,
  FileText
} from "lucide-react";

interface CustomLoopPanelProps {
  projectId: string;
}

const PRESET_OPTIONS = [
  {
    id: "python",
    type: "source",
    label: "Banking Payment Service (Python)",
    desc: "Vulnerable MD5 session hash + 1024-bit RSA keypair",
    file_name: "payment_service.py",
    language: "python",
    code: `# Enterprise Banking Payment Module (Python)
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_transaction_signature(account_id: str, amount: float) -> tuple[str, bytes]:
    # Deprecated Classical: Broken MD5 checksum
    payload = f"{account_id}:{amount}".encode("utf-8")
    tx_hash = hashlib.md5(payload).hexdigest()

    # Quantum Vulnerable: 1024-bit RSA keypair (High CRQC Risk)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024
    )
    return tx_hash, private_key.sign(payload, None)`
  },
  {
    id: "c_openssl",
    type: "source",
    label: "FinTech Core Gateway (C / OpenSSL)",
    desc: "Obsolete MD5 + 56-bit DES + RSA-1024",
    file_name: "src/payment.c",
    language: "c_cpp",
    code: `// Enterprise Banking Payment Module (C / OpenSSL)
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/rsa.h>

int process_payment_telemetry(const unsigned char *payload, size_t len) {
    // Weak Classical: Obsolete MD5 hash
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(payload, len, digest);

    // Weak Classical: 56-bit DES symmetric cipher
    DES_cblock key;
    DES_key_schedule schedule;
    DES_set_key_unchecked(&key, &schedule);

    // Quantum Vulnerable: 1024-bit RSA keypair
    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4);
    RSA_generate_key_ex(rsa, 1024, bne, NULL);

    return 0;
}`
  },
  {
    id: "binary",
    type: "binary",
    label: "Legacy Crypto Binary Executable (ELF x86_64)",
    desc: "Embedded DES and MD5 symbols requiring PQC compiler hardening",
    file_name: "bin/payment_gateway.elf",
    language: "binary",
    code: `7f454c4602010100000000000000000002003e00010000000000000000000000`
  }
];

export function CustomLoopPanel({ projectId }: CustomLoopPanelProps) {
  const router = useRouter();

  const [targetType, setTargetType] = useState<"source" | "binary">("source");
  const [selectedPreset, setSelectedPreset] = useState("python");
  const [codeContent, setCodeContent] = useState(PRESET_OPTIONS[0].code);
  const [fileName, setFileName] = useState(PRESET_OPTIONS[0].file_name);
  const [language, setLanguage] = useState(PRESET_OPTIONS[0].language);

  const [isRunning, setIsRunning] = useState(false);
  const [activeStep, setActiveStep] = useState<number>(0);
  const [loopResult, setLoopResult] = useState<any | null>(null);
  const [errorMsg, setErrorMsg] = useState("");

  const handleSelectPreset = (id: string) => {
    setSelectedPreset(id);
    const p = PRESET_OPTIONS.find((opt) => opt.id === id);
    if (p) {
      setTargetType(p.type as any);
      setCodeContent(p.code);
      setFileName(p.file_name);
      setLanguage(p.language);
    }
  };

  const handleRunLoop = async () => {
    setIsRunning(true);
    setErrorMsg("");
    setLoopResult(null);
    setActiveStep(1);

    // Simulated visual step progression while executing
    const stepTimer1 = setTimeout(() => setActiveStep(2), 500);
    const stepTimer2 = setTimeout(() => setActiveStep(3), 1100);
    const stepTimer3 = setTimeout(() => setActiveStep(4), 1800);

    try {
      const payload: any = {
        target_type: targetType,
        file_name: fileName,
        language: language,
        preset_name: selectedPreset,
      };

      if (targetType === "source") {
        payload.source_code = codeContent;
      } else {
        payload.binary_hex = codeContent;
      }

      const res = await fetch("/api/custom-loop/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        throw new Error(`Execution failed: ${res.statusText}`);
      }

      const data = await res.json();
      setLoopResult(data);
      setActiveStep(5); // all completed

      // Save to localStorage so dedicated changes page can pick it up immediately
      try {
        localStorage.setItem("ecdat_latest_loop_result", JSON.stringify(data));
      } catch (e) {
        // ignore
      }
    } catch (err: any) {
      setErrorMsg(err.message || "An unexpected error occurred during custom loop execution.");
    } finally {
      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);
      clearTimeout(stepTimer3);
      setIsRunning(false);
    }
  };

  const navigateToChangesPage = () => {
    router.push(`/projects/${projectId}/changes`);
  };

  return (
    <div className="space-y-6">
      {/* Hero Banner */}
      <div className="rounded-xl border border-subtle bg-gradient-to-r from-surface to-surface/40 p-6 backdrop-blur relative overflow-hidden">
        <div className="absolute -right-16 -top-16 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2 py-0.5 rounded text-[11px] font-mono uppercase font-semibold bg-cyan-500/15 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30">
                Autonomous Loop Engine
              </span>
              <span className="text-xs text-muted-foreground font-mono">1-Click Pipeline</span>
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-foreground">
              Autonomous Cryptographic Remediation Loop
            </h2>
            <p className="text-sm text-muted-foreground mt-1 max-w-2xl">
              Execute an end-to-end cycle in a single click: Scan source or binary → Generate CBOM & quantum risk report → Create AST-safe patches → Verify with closed-loop differential testing → Inspect before and after changes.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleRunLoop}
              disabled={isRunning}
              className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition-all shadow-lg shadow-cyan-600/20 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {isRunning ? (
                <>
                  <Loader2 size={18} className="animate-spin" />
                  Running Autonomous Loop...
                </>
              ) : (
                <>
                  <Play size={18} className="fill-current" />
                  Run Autonomous Loop
                </>
              )}
            </button>

            {loopResult && (
              <button
                onClick={navigateToChangesPage}
                className="inline-flex items-center gap-2 px-4 py-3 rounded-lg border border-cyan-500/40 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-700 dark:text-cyan-300 font-medium text-sm transition-all cursor-pointer"
              >
                <span>Inspect Changes</span>
                <ArrowRight size={16} />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Target Setup & Selection */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Preset & Mode Selection */}
        <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Layers size={16} className="text-cyan-600 dark:text-cyan-400" />
              Target Selection
            </h3>
            <div className="flex bg-canvas border border-subtle rounded-md p-0.5">
              <button
                onClick={() => setTargetType("source")}
                className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
                  targetType === "source"
                    ? "bg-cyan-600 text-white"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                Source
              </button>
              <button
                onClick={() => {
                  setTargetType("binary");
                  handleSelectPreset("binary");
                }}
                className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
                  targetType === "binary"
                    ? "bg-cyan-600 text-white"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                Binary
              </button>
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-xs font-medium text-muted-foreground">Select Preset Scenario</label>
            <div className="space-y-2">
              {PRESET_OPTIONS.map((opt) => (
                <button
                  key={opt.id}
                  onClick={() => handleSelectPreset(opt.id)}
                  className={`w-full text-left p-3 rounded-lg border text-xs transition-all cursor-pointer ${
                    selectedPreset === opt.id
                      ? "border-cyan-500 bg-cyan-500/10 text-foreground"
                      : "border-subtle bg-canvas hover:border-muted-foreground/30 text-muted-foreground"
                  }`}
                >
                  <div className="flex items-center justify-between font-semibold text-foreground">
                    <span>{opt.label}</span>
                    <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-surface border border-subtle">
                      {opt.language}
                    </span>
                  </div>
                  <p className="text-[11px] text-muted-foreground mt-1">{opt.desc}</p>
                </button>
              ))}
            </div>
          </div>

          <div className="pt-2 border-t border-subtle space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">Target File</span>
              <span className="font-mono text-foreground">{fileName}</span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">Analysis Mode</span>
              <span className="font-mono text-cyan-700 dark:text-cyan-400">Strict Deterministic AST</span>
            </div>
          </div>
        </div>

        {/* Right Columns (Span 2): Code / Hex Preview & Editor */}
        <div className="lg:col-span-2 rounded-xl border border-subtle bg-surface p-5 space-y-3 flex flex-col">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {targetType === "source" ? (
                <FileCode size={16} className="text-cyan-600 dark:text-cyan-400" />
              ) : (
                <Binary size={16} className="text-cyan-600 dark:text-cyan-400" />
              )}
              <h3 className="text-sm font-semibold text-foreground">
                {targetType === "source" ? "Source Code Input" : "Binary Hex Payload"}
              </h3>
            </div>
            <span className="text-xs text-muted-foreground font-mono">
              {targetType === "source" ? "Editable Snippet" : "Disassembly Stream"}
            </span>
          </div>

          <div className="flex-1 min-h-[220px]">
            <textarea
              value={codeContent}
              onChange={(e) => setCodeContent(e.target.value)}
              className="w-full h-full min-h-[220px] p-3 rounded-lg bg-canvas border border-subtle font-mono text-xs text-foreground placeholder:text-muted-foreground outline-none focus:border-cyan-500 transition-colors resize-none"
              spellCheck={false}
            />
          </div>

          <div className="flex items-center justify-between text-xs text-muted-foreground pt-1">
            <span>Click &quot;Run Autonomous Loop&quot; to execute scan, report, patch, and verify.</span>
            <span className="font-mono">{codeContent.split("\n").length} lines</span>
          </div>
        </div>
      </div>

      {/* Real-time Pipeline Progress Stepper */}
      <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
        <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <Sparkles size={16} className="text-cyan-600 dark:text-cyan-400" />
          Autonomous Pipeline Execution Stages
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Step 1 */}
          <div
            className={`p-4 rounded-lg border transition-all ${
              activeStep > 1 || (loopResult && activeStep === 5)
                ? "border-emerald-500/40 bg-emerald-500/5 text-foreground"
                : activeStep === 1
                ? "border-cyan-500 bg-cyan-500/10 text-foreground animate-pulse"
                : "border-subtle bg-canvas opacity-60 text-muted-foreground"
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono font-semibold">STAGE 01</span>
              {activeStep > 1 || (loopResult && activeStep === 5) ? (
                <CheckCircle2 size={16} className="text-emerald-600 dark:text-emerald-400" />
              ) : activeStep === 1 ? (
                <Loader2 size={16} className="animate-spin text-cyan-600 dark:text-cyan-400" />
              ) : (
                <Clock size={16} className="text-muted-foreground" />
              )}
            </div>
            <h4 className="text-sm font-medium text-foreground">Scan & Discover</h4>
            <p className="text-xs text-muted-foreground mt-1">
              Extract cryptographic primitives, algorithms, and key sizes.
            </p>
          </div>

          {/* Step 2 */}
          <div
            className={`p-4 rounded-lg border transition-all ${
              activeStep > 2 || (loopResult && activeStep === 5)
                ? "border-emerald-500/40 bg-emerald-500/5 text-foreground"
                : activeStep === 2
                ? "border-cyan-500 bg-cyan-500/10 text-foreground animate-pulse"
                : "border-subtle bg-canvas opacity-60 text-muted-foreground"
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono font-semibold">STAGE 02</span>
              {activeStep > 2 || (loopResult && activeStep === 5) ? (
                <CheckCircle2 size={16} className="text-emerald-600 dark:text-emerald-400" />
              ) : activeStep === 2 ? (
                <Loader2 size={16} className="animate-spin text-cyan-600 dark:text-cyan-400" />
              ) : (
                <Clock size={16} className="text-muted-foreground" />
              )}
            </div>
            <h4 className="text-sm font-medium text-foreground">CBOM & Quantum Risk</h4>
            <p className="text-xs text-muted-foreground mt-1">
              Generate CycloneDX 1.6 CBOM and compute Mosca deficit timeline.
            </p>
          </div>

          {/* Step 3 */}
          <div
            className={`p-4 rounded-lg border transition-all ${
              activeStep > 3 || (loopResult && activeStep === 5)
                ? "border-emerald-500/40 bg-emerald-500/5 text-foreground"
                : activeStep === 3
                ? "border-cyan-500 bg-cyan-500/10 text-foreground animate-pulse"
                : "border-subtle bg-canvas opacity-60 text-muted-foreground"
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono font-semibold">STAGE 03</span>
              {activeStep > 3 || (loopResult && activeStep === 5) ? (
                <CheckCircle2 size={16} className="text-emerald-600 dark:text-emerald-400" />
              ) : activeStep === 3 ? (
                <Loader2 size={16} className="animate-spin text-cyan-600 dark:text-cyan-400" />
              ) : (
                <Clock size={16} className="text-muted-foreground" />
              )}
            </div>
            <h4 className="text-sm font-medium text-foreground">Auto Patch & Test</h4>
            <p className="text-xs text-muted-foreground mt-1">
              Apply safe AST migration templates and execute differential tests.
            </p>
          </div>

          {/* Step 4 */}
          <div
            className={`p-4 rounded-lg border transition-all ${
              activeStep === 5 || loopResult
                ? "border-emerald-500/40 bg-emerald-500/5 text-foreground"
                : activeStep === 4
                ? "border-cyan-500 bg-cyan-500/10 text-foreground animate-pulse"
                : "border-subtle bg-canvas opacity-60 text-muted-foreground"
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono font-semibold">STAGE 04</span>
              {activeStep === 5 || loopResult ? (
                <CheckCircle2 size={16} className="text-emerald-600 dark:text-emerald-400" />
              ) : activeStep === 4 ? (
                <Loader2 size={16} className="animate-spin text-cyan-600 dark:text-cyan-400" />
              ) : (
                <Clock size={16} className="text-muted-foreground" />
              )}
            </div>
            <h4 className="text-sm font-medium text-foreground">Closed-Loop Verify</h4>
            <p className="text-xs text-muted-foreground mt-1">
              Re-scan and prove weakness elimination with zero regressions.
            </p>
          </div>
        </div>

        {errorMsg && (
          <div className="p-3 rounded-lg border border-red-500/30 bg-red-500/10 text-xs text-red-700 dark:text-red-400 flex items-center gap-2">
            <AlertTriangle size={16} />
            <span>{errorMsg}</span>
          </div>
        )}
      </div>

      {/* Loop Execution Results Summary */}
      {loopResult && (
        <div className="rounded-xl border border-cyan-500/40 bg-surface p-6 space-y-6 shadow-xl shadow-cyan-500/5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-subtle">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-600 dark:text-emerald-400">
                <ShieldCheck size={22} />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-lg font-bold text-foreground">Closed-Loop Verdict:</h3>
                  <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
                    {loopResult.verdict}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Run ID: <span className="font-mono text-foreground">{loopResult.run_id}</span> • Completed in {loopResult.total_duration_ms} ms
                </p>
              </div>
            </div>

            <button
              onClick={navigateToChangesPage}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition-all shadow-md cursor-pointer"
            >
              <span>Inspect Full Before & After Changes</span>
              <ArrowRight size={16} />
            </button>
          </div>

          {/* KPI Comparison Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 rounded-lg bg-canvas border border-subtle">
              <span className="text-xs text-muted-foreground">Critical Vulnerabilities</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-xl font-bold text-red-500 font-mono">
                  {loopResult.before_state.critical_vulnerabilities}
                </span>
                <span className="text-xs text-muted-foreground">→</span>
                <span className="text-xl font-bold text-emerald-600 dark:text-emerald-400 font-mono">
                  {loopResult.after_state.critical_vulnerabilities}
                </span>
              </div>
              <span className="text-[11px] text-emerald-600 dark:text-emerald-400 mt-1 block">
                Weakness eliminated
              </span>
            </div>

            <div className="p-4 rounded-lg bg-canvas border border-subtle">
              <span className="text-xs text-muted-foreground">Security Posture Score</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-xl font-bold text-muted-foreground font-mono">
                  {loopResult.before_state.security_score}
                </span>
                <span className="text-xs text-muted-foreground">→</span>
                <span className="text-xl font-bold text-cyan-600 dark:text-cyan-400 font-mono">
                  {loopResult.after_state.security_score}
                </span>
              </div>
              <span className="text-[11px] text-cyan-600 dark:text-cyan-400 mt-1 block">
                {loopResult.after_state.security_score - loopResult.before_state.security_score >= 0 ? "+" : ""}
                {loopResult.after_state.security_score - loopResult.before_state.security_score} points change
              </span>
            </div>

            <div className="p-4 rounded-lg bg-canvas border border-subtle">
              <span className="text-xs text-muted-foreground">Quantum Deficit (Mosca)</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-xl font-bold text-red-500 font-mono">
                  {loopResult.before_state.quantum_deficit_years}y
                </span>
                <span className="text-xs text-muted-foreground">→</span>
                <span className="text-xl font-bold text-emerald-600 dark:text-emerald-400 font-mono">
                  {loopResult.after_state.quantum_deficit_years}y
                </span>
              </div>
              <span className="text-[11px] text-emerald-600 dark:text-emerald-400 mt-1 block">
                Zero exposure deficit
              </span>
            </div>

            <div className="p-4 rounded-lg bg-canvas border border-subtle">
              <span className="text-xs text-muted-foreground">Retired Weaknesses</span>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-xl font-bold text-emerald-600 dark:text-emerald-400 font-mono">
                  {loopResult.verification_report.retired_weaknesses?.length ?? 0}
                </span>
                <span className="text-xs text-muted-foreground">primitives</span>
              </div>
              <span className="text-[11px] text-muted-foreground mt-1 block">
                Regressions detected: {loopResult.verification_report.regressions?.length ?? 0}
              </span>
            </div>
          </div>

          {/* Transformation preview banner */}
          <div className="p-4 rounded-lg bg-canvas border border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
            <div>
              <span className="font-semibold text-foreground">Transformation Applied: </span>
              <span className="text-muted-foreground">{loopResult.transformation_description}</span>
            </div>
            <button
              onClick={navigateToChangesPage}
              className="text-cyan-600 dark:text-cyan-400 hover:underline flex items-center gap-1 font-medium whitespace-nowrap cursor-pointer"
            >
              <span>View side-by-side diff & test results</span>
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
