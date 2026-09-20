import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import JSZip from "jszip";
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
  FileText,
  Upload,
  FolderArchive,
  Check,
  Copy,
  X
} from "lucide-react";

interface CustomLoopPanelProps {
  projectId: string;
}

const TARGET_SOLUTIONS = [
  {
    id: "NIST_PQC_HYBRID",
    name: "NIST FIPS 203/204 Hybrid (ML-KEM-768 + ML-DSA-65)",
    badge: "Recommended Standard",
    desc: "Lattice-based Post-Quantum KEM and Signatures combined with classical ECC/RSA protection."
  },
  {
    id: "FIPS_203_204",
    name: "Pure Quantum-Native Standard (ML-KEM-1024 / ML-DSA-87)",
    badge: "Category 5 Security",
    desc: "Maximum security lattice standard for high-assurance national security workloads."
  },
  {
    id: "TRANSITIONAL_AES_SHA",
    name: "Transitional Classical Hardening (AES-256-GCM + SHA-384 + RSA-3072)",
    badge: "Immediate Drop-in",
    desc: "Eliminates all classically broken algorithms (MD5/DES/RC4) and raises minimum RSA margin to 3072 bits."
  },
  {
    id: "CNSA_2_0",
    name: "NSA CNSA 2.0 Modernization Suite",
    badge: "DoD / NSA Standard",
    desc: "Complies with NSA Commercial National Security Algorithm Suite 2.0 for quantum-resistant migration by 2030."
  }
];

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
    id: "rust_iot",
    type: "source",
    label: "Embedded IoT Firmware (Rust)",
    desc: "Deprecated md5 crate + 1024-bit RSA private key",
    file_name: "src/telemetry.rs",
    language: "rust",
    code: `// Rust Embedded IoT Firmware
use md5;
use des::Des;
use rsa::RsaPrivateKey;

fn process_telemetry(data: &[u8]) -> Vec<u8> {
    let digest = md5::compute(data);
    let cipher = Des::new_from_slice(b"12345678").unwrap();
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
    digest.to_vec()
}`
  },
  {
    id: "csharp_api",
    type: "source",
    label: "Banking Payment API (C# .NET)",
    desc: "MD5.Create() + DESCryptoServiceProvider + RSA-1024",
    file_name: "PaymentProcessor.cs",
    language: "csharp",
    code: `// C# .NET Banking API
using System.Security.Cryptography;

public class PaymentProcessor {
    public byte[] ProcessTransaction(byte[] payload) {
        using var md5 = MD5.Create();
        using var des = DESCryptoServiceProvider.Create();
        using var rsa = new RSACryptoServiceProvider(1024);
        return md5.ComputeHash(payload);
    }
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
  const [targetSolution, setTargetSolution] = useState("NIST_PQC_HYBRID");
  const [codeContent, setCodeContent] = useState(PRESET_OPTIONS[0].code);
  const [fileName, setFileName] = useState(PRESET_OPTIONS[0].file_name);
  const [language, setLanguage] = useState(PRESET_OPTIONS[0].language);

  // Uploaded Files State
  const [uploadedFiles, setUploadedFiles] = useState<Array<{ name: string; path: string; content: string; language: string; size: number }>>([]);
  const [selectedFileIdx, setSelectedFileIdx] = useState<number>(0);
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  const [isRunning, setIsRunning] = useState(false);
  const [activeStep, setActiveStep] = useState<number>(0);
  const [loopResult, setLoopResult] = useState<any | null>(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [activeDiffFileIdx, setActiveDiffFileIdx] = useState<number>(0);
  const [copiedDiff, setCopiedDiff] = useState(false);
  const [downloadingZip, setDownloadingZip] = useState(false);

  const handleSelectPreset = (id: string) => {
    setSelectedPreset(id);
    setUploadedFiles([]);
    const p = PRESET_OPTIONS.find((opt) => opt.id === id);
    if (p) {
      setTargetType(p.type as any);
      setCodeContent(p.code);
      setFileName(p.file_name);
      setLanguage(p.language);
    }
  };

  const handleFileUpload = (files: FileList | File[]) => {
    const fileArr = Array.from(files);
    if (fileArr.length === 0) return;

    const EXT_MAP: Record<string, string> = {
      py: "python",
      java: "java",
      c: "c_cpp",
      cpp: "c_cpp",
      h: "c_cpp",
      hpp: "c_cpp",
      go: "golang",
      js: "javascript",
      ts: "javascript",
      jsx: "javascript",
      tsx: "javascript",
      rs: "rust",
      cs: "csharp",
      php: "php",
      rb: "ruby",
      swift: "swift",
      kt: "kotlin",
      kts: "kotlin",
      json: "json",
      txt: "universal"
    };

    const readers = fileArr.map((f) => {
      return new Promise<{ name: string; path: string; content: string; language: string; size: number }>((resolve) => {
        const reader = new FileReader();
        reader.onload = (e) => {
          const text = (e.target?.result as string) || "";
          const ext = f.name.split(".").pop()?.toLowerCase() || "";
          const lang = EXT_MAP[ext] || "universal";
          resolve({
            name: f.name,
            path: (f as any).webkitRelativePath || f.name,
            content: text,
            language: lang,
            size: f.size
          });
        };
        reader.readAsText(f);
      });
    });

    Promise.all(readers).then((loaded) => {
      setUploadedFiles(loaded);
      setSelectedFileIdx(0);
      if (loaded.length > 0) {
        setTargetType("source");
        setFileName(loaded[0].path);
        setLanguage(loaded[0].language);
        setCodeContent(loaded[0].content);
      }
    });
  };

  const handleRunLoop = async () => {
    setIsRunning(true);
    setErrorMsg("");
    setLoopResult(null);
    setActiveStep(1);

    const stepTimer1 = setTimeout(() => setActiveStep(2), 500);
    const stepTimer2 = setTimeout(() => setActiveStep(3), 1100);
    const stepTimer3 = setTimeout(() => setActiveStep(4), 1800);

    try {
      const payload: any = {
        target_type: targetType,
        file_name: fileName,
        language: language,
        preset_name: uploadedFiles.length > 0 ? undefined : selectedPreset,
        target_solution: targetSolution,
      };

      if (uploadedFiles.length > 0) {
        payload.files = uploadedFiles.map((f) => ({
          path: f.path,
          content: f.content,
          language: f.language,
        }));
      } else if (targetType === "source") {
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
      setActiveStep(5);

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

  const handleDownloadPatchedZip = async () => {
    if (!loopResult) return;
    setDownloadingZip(true);
    try {
      const zip = new JSZip();

      if (loopResult.file_patches && loopResult.file_patches.length > 0) {
        for (const fp of loopResult.file_patches) {
          zip.file(fp.path, fp.patched_code);
        }
      } else if (loopResult.after_state?.code) {
        zip.file(fileName, loopResult.after_state.code);
      }

      const reportMd = `# ECDAT Autonomous Remediation Report
Target Project: ${projectId}
Target File: ${fileName}
Verdict: ${loopResult.verdict}
Target Migration Standard: ${loopResult.target_solution || targetSolution}
Generated At: ${loopResult.timestamp}

## Executive Summary
- Total Cryptographic Primitives: ${loopResult.before_state?.findings_count || 0} -> ${loopResult.after_state?.findings_count || 0}
- Critical / Weak Primitives: ${loopResult.before_state?.critical_vulnerabilities || 0} -> ${loopResult.after_state?.critical_vulnerabilities || 0}
- Security Posture Score: ${loopResult.before_state?.security_score || 0}/100 -> ${loopResult.after_state?.security_score || 0}/100
- Quantum Readiness: ${loopResult.after_state?.pqc_readiness_pct || 100}%

## Applied Transformations
${loopResult.transformation_description || "AST-safe deterministic migration"}

## Unified Migration Diff
\`\`\`diff
${loopResult.unified_diff || "No diff generated"}
\`\`\`
`;
      zip.file("ECDAT_MIGRATION_REPORT.md", reportMd);

      const blob = await zip.generateAsync({ type: "blob" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${projectId}_autonomous_remediated.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error("Failed to generate zip", e);
    } finally {
      setDownloadingZip(false);
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
                onClick={() => {
                  setTargetType("source");
                  if (uploadedFiles.length > 0) {
                    setFileName(uploadedFiles[0].path);
                    setLanguage(uploadedFiles[0].language);
                    setCodeContent(uploadedFiles[0].content);
                  }
                }}
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

          {/* Target Migration Solution Selector */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-foreground flex items-center justify-between">
              <span>Target Solution Architecture</span>
              <span className="text-[10px] text-cyan-400 font-mono">PQC Agile</span>
            </label>
            <select
              value={targetSolution}
              onChange={(e) => setTargetSolution(e.target.value)}
              className="w-full text-xs p-2.5 rounded-lg border border-subtle bg-canvas text-foreground font-mono focus:border-cyan-500 outline-none"
            >
              {TARGET_SOLUTIONS.map((ts) => (
                <option key={ts.id} value={ts.id}>
                  {ts.name}
                </option>
              ))}
            </select>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              {TARGET_SOLUTIONS.find((ts) => ts.id === targetSolution)?.desc}
            </p>
          </div>

          {/* Upload Files or Folder Zone */}
          <div className="space-y-2 pt-2 border-t border-subtle">
            <label className="text-xs font-medium text-muted-foreground flex items-center justify-between">
              <span>Upload Custom Files / Folder</span>
              {uploadedFiles.length > 0 && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  {uploadedFiles.length} file{uploadedFiles.length > 1 ? "s" : ""} loaded
                </span>
              )}
            </label>

            <input
              ref={fileInputRef}
              type="file"
              multiple
              className="hidden"
              onChange={(e) => e.target.files && handleFileUpload(e.target.files)}
            />
            <input
              ref={folderInputRef}
              type="file"
              multiple
              // @ts-ignore
              webkitdirectory=""
              className="hidden"
              onChange={(e) => e.target.files && handleFileUpload(e.target.files)}
            />

            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={() => setIsDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDragging(false);
                if (e.dataTransfer.files) handleFileUpload(e.dataTransfer.files);
              }}
              className={`p-3.5 rounded-lg border-2 border-dashed text-center transition-all cursor-pointer ${
                isDragging
                  ? "border-cyan-500 bg-cyan-500/10"
                  : "border-subtle bg-canvas/60 hover:border-cyan-500/40"
              }`}
              onClick={() => fileInputRef.current?.click()}
            >
              <Upload className="h-5 w-5 mx-auto text-cyan-400 mb-1" />
              <div className="text-xs font-semibold text-foreground">
                Drag &amp; drop files or click to upload
              </div>
              <div className="text-[10px] text-muted-foreground mt-0.5">
                Accepts .py, .java, .c, .cpp, .go, .js, .rs, .cs, .php, .rb, .swift, .kt
              </div>
              <div className="mt-2 flex items-center justify-center gap-2">
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    fileInputRef.current?.click();
                  }}
                  className="px-2.5 py-1 rounded text-[10px] font-mono bg-surface border border-subtle hover:border-cyan-500 text-foreground"
                >
                  Browse Files
                </button>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    folderInputRef.current?.click();
                  }}
                  className="px-2.5 py-1 rounded text-[10px] font-mono bg-surface border border-subtle hover:border-cyan-500 text-foreground"
                >
                  Upload Folder
                </button>
              </div>
            </div>

            {/* Uploaded File Pills */}
            {uploadedFiles.length > 0 && (
              <div className="space-y-1 max-h-32 overflow-y-auto pr-1">
                {uploadedFiles.map((f, i) => (
                  <div
                    key={i}
                    onClick={() => {
                      setSelectedFileIdx(i);
                      setFileName(f.path);
                      setLanguage(f.language);
                      setCodeContent(f.content);
                    }}
                    className={`px-2 py-1 rounded text-[11px] font-mono flex items-center justify-between cursor-pointer border ${
                      selectedFileIdx === i
                        ? "border-cyan-500 bg-cyan-500/15 text-cyan-300"
                        : "border-subtle bg-canvas text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    <span className="truncate max-w-[170px]" title={f.path}>
                      {f.name}
                    </span>
                    <span className="text-[9px] uppercase px-1 rounded bg-surface border border-subtle">
                      {f.language}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="space-y-2 pt-2 border-t border-subtle">
            <label className="text-xs font-medium text-muted-foreground">Or Select Demo Preset</label>
            <div className="space-y-2">
              {PRESET_OPTIONS.map((opt) => (
                <button
                  key={opt.id}
                  onClick={() => handleSelectPreset(opt.id)}
                  className={`w-full text-left p-3 rounded-lg border text-xs transition-all cursor-pointer ${
                    selectedPreset === opt.id && uploadedFiles.length === 0
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
              <span className="text-muted-foreground">Active Target</span>
              <span className="font-mono text-foreground truncate max-w-[150px]" title={fileName}>
                {fileName}
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">Language / Runtime</span>
              <span className="font-mono text-cyan-400 uppercase">{language}</span>
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

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={handleDownloadPatchedZip}
                disabled={downloadingZip}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-sm transition-all shadow-md cursor-pointer disabled:opacity-50"
              >
                {downloadingZip ? (
                  <Loader2 size={16} className="animate-spin" />
                ) : (
                  <Download size={16} />
                )}
                <span>Download Remediated Code (.zip)</span>
              </button>
              <button
                onClick={navigateToChangesPage}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition-all shadow-md cursor-pointer"
              >
                <span>Inspect Full Before & After Changes</span>
                <ArrowRight size={16} />
              </button>
            </div>
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

          {/* Multi-file Patch Inspector */}
          {loopResult.file_patches && loopResult.file_patches.length > 0 && (
            <div className="rounded-lg border border-subtle bg-canvas overflow-hidden">
              <div className="flex flex-wrap items-center justify-between px-4 py-2.5 bg-surface/80 border-b border-subtle gap-2">
                <div className="flex items-center gap-2 overflow-x-auto py-1">
                  <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mr-2">Patched Files:</span>
                  {loopResult.file_patches.map((fp: any, idx: number) => (
                    <button
                      key={idx}
                      onClick={() => setActiveDiffFileIdx(idx)}
                      className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                        activeDiffFileIdx === idx
                          ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40"
                          : "bg-surface text-muted-foreground hover:text-foreground border border-subtle"
                      }`}
                    >
                      {fp.path}
                    </button>
                  ))}
                </div>
                <button
                  onClick={() => {
                    const diffText = loopResult.file_patches[activeDiffFileIdx]?.diff || loopResult.unified_diff || "";
                    navigator.clipboard.writeText(diffText);
                    setCopiedDiff(true);
                    setTimeout(() => setCopiedDiff(false), 2000);
                  }}
                  className="flex items-center gap-1.5 px-2.5 py-1 text-xs rounded bg-surface border border-subtle hover:border-cyan-500 text-foreground transition-colors shrink-0"
                >
                  {copiedDiff ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                  <span>{copiedDiff ? "Copied Diff" : "Copy Diff"}</span>
                </button>
              </div>
              <div className="p-4 font-mono text-xs overflow-x-auto max-h-80 bg-black/40">
                <pre className="text-foreground">
                  {(loopResult.file_patches[activeDiffFileIdx]?.diff || loopResult.unified_diff || "No diff generated.")
                    .split("\n")
                    .map((line: string, i: number) => {
                      let color = "text-muted-foreground";
                      if (line.startsWith("+")) color = "text-emerald-400 bg-emerald-500/10";
                      else if (line.startsWith("-")) color = "text-rose-400 bg-rose-500/10";
                      else if (line.startsWith("@")) color = "text-cyan-400";
                      return (
                        <div key={i} className={`px-1 py-0.5 rounded-sm ${color}`}>
                          {line}
                        </div>
                      );
                    })}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
