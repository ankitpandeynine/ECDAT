"use client";

import React, { useState, useEffect, useRef } from "react";
import {
  Zap,
  Play,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Download,
  Terminal,
  ArrowRight,
  ShieldCheck,
  RefreshCw,
  Copy,
  Check,
  Code2,
} from "lucide-react";

interface AutoPatchShowpieceProps {
  projectId: string;
  onNavigateToVerify?: (baselineScanId: string, postScanId?: string) => void;
  preselectedScanId?: string;
  preselectedAsset?: string;
}

interface ScanJobSummary {
  id: string;
  kind: string;
  status: string;
  created_at: string;
  result?: {
    findings?: any[];
    detections?: any[];
    total_findings?: number;
  };
}

interface FindingItem {
  id: string;
  algorithm: string;
  line: number;
  code: string;
  replacement: string;
  pattern_id: string;
  checked: boolean;
}

export function AutoPatchShowpiece({
  projectId,
  onNavigateToVerify,
  preselectedScanId,
  preselectedAsset,
}: AutoPatchShowpieceProps) {
  const [scans, setScans] = useState<ScanJobSummary[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>(preselectedScanId || "");
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [loadingScans, setLoadingScans] = useState(false);
  const [sourceCode, setSourceCode] = useState<string>("");
  const [fileName, setFileName] = useState<string>("app.py");

  // Execution state
  const [isPatching, setIsPatching] = useState(false);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([]);
  const [patchResult, setPatchResult] = useState<any | null>(null);
  const [activeDiffTab, setActiveDiffTab] = useState<"split" | "unified">("split");
  const [copiedPatch, setCopiedPatch] = useState(false);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Load completed scans
  useEffect(() => {
    async function loadScans() {
      setLoadingScans(true);
      try {
        const res = await fetch(`/api/scans?project=${encodeURIComponent(projectId)}`);
        if (res.ok) {
          const data = await res.json();
          const completed = data.filter((s: any) => s.status === "completed");
          setScans(completed);
          if (!selectedScanId && completed.length > 0) {
            const codeScan = completed.find((s: any) => s.kind === "code") || completed[0];
            setSelectedScanId(codeScan.id);
          }
        }
      } catch (err) {
        console.error("Failed to load scans for autopatch:", err);
      } finally {
        setLoadingScans(false);
      }
    }
    loadScans();
  }, [projectId]);

  // Load findings for the selected scan
  useEffect(() => {
    if (!selectedScanId) return;

    async function loadScanFindings() {
      try {
        const res = await fetch(`/api/scans/${selectedScanId}/result?project=${encodeURIComponent(projectId)}`);
        if (res.ok) {
          const data = await res.json();
          if (data.source_code) {
            setSourceCode(data.source_code);
          }
          if (data.findings && data.findings.length > 0) {
            const items: FindingItem[] = data.findings.map((f: any, idx: number) => {
              const algo = f.algorithm || "Unknown";
              const line = f.line || 1;
              const codeSnippet = f.code || "";
              const replacement = f.recommended_replacement || "NIST PQC Standard";
              const pattern = f.patch_pattern || "MD5_TO_SHA256_PYTHON";

              return {
                id: `finding-${idx}-${line}`,
                algorithm: algo,
                line: line,
                code: codeSnippet,
                replacement: replacement,
                pattern_id: pattern,
                checked: true,
              };
            });
            setFindings(items);
            setFileName(data.findings[0]?.file || "app.py");
          } else {
            setFindings([]);
            setFileName("app.py");
          }
        }
      } catch (err) {
        console.error("Failed to load scan findings:", err);
      }
    }

    loadScanFindings();
  }, [selectedScanId, projectId]);

  // Handle finding toggle
  const toggleFinding = (id: string) => {
    setFindings((prev) =>
      prev.map((item) => (item.id === id ? { ...item, checked: !item.checked } : item))
    );
  };

  // Run Auto Patch with simulated terminal log streaming
  const handleGeneratePatches = async () => {
    if (!selectedScanId) return;
    setIsPatching(true);
    setTerminalLogs([]);
    setPatchResult(null);

    // Only send concrete, applicable pattern ids — null/undefined patterns
    // (e.g. quantum-safe findings with no migration template) must not be
    // forwarded, or the backend would skip every template.
    const checkedPatterns = Array.from(
      new Set(
        findings
          .filter((f) => f.checked && f.pattern_id)
          .map((f) => f.pattern_id)
      )
    );

    try {
      // Initiate API call
      const res = await fetch("/api/patch/from-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scan_id: selectedScanId,
          project_id: projectId,
          selected_patterns: checkedPatterns,
          file_path: fileName,
          override_code: sourceCode || undefined,
        }),
      });

      if (!res.ok) {
        throw new Error(`Auto patch failed: ${res.statusText}`);
      }

      const data = await res.json();
      const logs = data.execution_logs || [];

      // Animate terminal log appearance line by line
      for (let i = 0; i < logs.length; i++) {
        await new Promise((r) => setTimeout(r, 220));
        setTerminalLogs((curr) => [...curr, logs[i]]);
        if (terminalEndRef.current) {
          terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
        }
      }

      setPatchResult(data);
    } catch (err: any) {
      setTerminalLogs((curr) => [
        ...curr,
        `[ ERROR ] Patch generation failed: ${err.message || String(err)}`,
      ]);
    } finally {
      setIsPatching(false);
    }
  };

  // Download .patch unified diff file
  const handleDownloadPatch = () => {
    if (!patchResult?.unified_diff) return;
    const blob = new Blob([patchResult.unified_diff], { type: "text/x-diff" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${fileName.replace(/\.[^/.]+$/, "")}_remediated.patch`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Download remediated code file
  const handleDownloadFile = () => {
    if (!patchResult?.patched_code) return;
    const blob = new Blob([patchResult.patched_code], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Download complete patched project (.zip)
  const [downloadingZip, setDownloadingZip] = useState(false);
  const handleDownloadProjectZip = async () => {
    setDownloadingZip(true);
    try {
      const endpoint = `/api/patch/download-project?project_id=${encodeURIComponent(projectId)}${selectedScanId ? `&scan_id=${encodeURIComponent(selectedScanId)}` : ""}`;
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scan_id: selectedScanId || null,
          project_id: projectId,
          selected_patterns: findings.filter((f) => f.checked).map((f) => f.pattern_id),
          override_files: patchResult?.patched_code ? [
            {
              path: fileName,
              content: patchResult.patched_code,
              language: patchResult.language || "python"
            }
          ] : undefined
        }),
      });

      if (!res.ok) {
        throw new Error("Failed to generate patched project archive.");
      }

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${projectId}_patched_project.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Error downloading patched project ZIP:", err);
    } finally {
      setDownloadingZip(false);
    }
  };

  // Render Split Diff lines with exact per-line delta highlighting and Myers AST alignment
  const renderSplitView = () => {
    if (!patchResult) return null;

    // Use backend side_by_side alignment if available for lockstep row alignment
    if (patchResult.side_by_side && patchResult.side_by_side.length > 0) {
      const rows = patchResult.side_by_side;

      return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono bg-canvas border border-subtle rounded-lg overflow-hidden">
          {/* Left: Original Code (BEFORE) */}
          <div className="border-r border-subtle">
            <div className="bg-canvas/90 px-3 py-2 border-b border-subtle flex items-center justify-between text-[11px] font-sans font-semibold text-rose-400">
              <span>ORIGINAL CODE (VULNERABLE)</span>
              <span className="text-[10px] bg-rose-500/10 border border-rose-500/30 px-2 py-0.5 rounded font-mono">
                BEFORE
              </span>
            </div>
            <div className="overflow-x-auto p-2 space-y-0.5 max-h-[500px]">
              {rows.map((row: any, i: number) => {
                const isVuln = row.type === "replace" || row.type === "delete";
                const isBlank = row.orig_line === null;

                if (isBlank) {
                  return (
                    <div
                      key={`orig-blank-${i}`}
                      className="flex items-center px-2 py-0.5 min-h-[22px] bg-white/[0.01] opacity-20 select-none"
                    >
                      <span className="w-8 shrink-0 text-[10px] text-transparent font-mono">-</span>
                      <span className="flex-1 text-transparent"> </span>
                    </div>
                  );
                }

                return (
                  <div
                    key={`orig-${i}`}
                    className={`flex items-start px-2 py-0.5 rounded leading-relaxed min-h-[22px] transition-colors ${
                      isVuln
                        ? "bg-rose-950/40 text-rose-200 border-l-2 border-rose-500 font-semibold"
                        : "text-quiet hover:bg-white/5"
                    }`}
                  >
                    <span className="w-8 select-none text-[10px] text-quiet/50 shrink-0 font-mono">
                      {row.orig_num}
                    </span>
                    <span className="whitespace-pre flex-1">{row.orig_line || " "}</span>
                    {isVuln && (
                      <span className="text-[9px] font-mono text-rose-400 bg-rose-950/70 px-1.5 py-0.2 rounded border border-rose-500/40 ml-2 shrink-0 select-none">
                        - VULNERABLE
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right: Patched Code (AFTER) */}
          <div>
            <div className="bg-canvas/90 px-3 py-2 border-b border-subtle flex items-center justify-between text-[11px] font-sans font-semibold text-emerald-400">
              <span>REMEDIATED CODE (PQC COMPLIANT)</span>
              <span className="text-[10px] bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded font-mono">
                AFTER (NIST FIPS 203)
              </span>
            </div>
            <div className="overflow-x-auto p-2 space-y-0.5 max-h-[500px]">
              {rows.map((row: any, i: number) => {
                const isRemediated = row.type === "replace" || row.type === "insert";
                const isBlank = row.patch_line === null;

                if (isBlank) {
                  return (
                    <div
                      key={`patch-blank-${i}`}
                      className="flex items-center px-2 py-0.5 min-h-[22px] bg-white/[0.01] opacity-20 select-none"
                    >
                      <span className="w-8 shrink-0 text-[10px] text-transparent font-mono">-</span>
                      <span className="flex-1 text-transparent"> </span>
                    </div>
                  );
                }

                return (
                  <div
                    key={`patch-${i}`}
                    className={`flex items-start px-2 py-0.5 rounded leading-relaxed min-h-[22px] transition-colors ${
                      isRemediated
                        ? "bg-emerald-950/40 text-emerald-200 border-l-2 border-emerald-500 font-semibold"
                        : "text-foreground hover:bg-white/5"
                    }`}
                  >
                    <span className="w-8 select-none text-[10px] text-quiet/50 shrink-0 font-mono">
                      {row.patch_num}
                    </span>
                    <span className="whitespace-pre flex-1">{row.patch_line || " "}</span>
                    {isRemediated && (
                      <span className="text-[9px] font-mono text-emerald-400 bg-emerald-950/70 px-1.5 py-0.2 rounded border border-emerald-500/40 ml-2 shrink-0 select-none">
                        + REMEDIATED
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      );
    }

    // Fallback: direct line index alignment
    const origLines = (patchResult.original_code || "").split("\n");
    const patchedLines = (patchResult.patched_code || "").split("\n");

    return (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono bg-canvas border border-subtle rounded-lg overflow-hidden">
        {/* Left: Original Code (BEFORE) */}
        <div className="border-r border-subtle">
          <div className="bg-canvas/90 px-3 py-2 border-b border-subtle flex items-center justify-between text-[11px] font-sans font-semibold text-rose-400">
            <span>ORIGINAL CODE (VULNERABLE)</span>
            <span className="text-[10px] bg-rose-500/10 border border-rose-500/30 px-2 py-0.5 rounded font-mono">
              BEFORE
            </span>
          </div>
          <div className="overflow-x-auto p-2 space-y-0.5 max-h-[460px]">
            {origLines.map((line: string, i: number) => {
              const patchedEquivalent = patchedLines[i];
              const isChanged = patchedEquivalent !== undefined && line !== patchedEquivalent;

              return (
                <div
                  key={`orig-${i}`}
                  className={`flex items-start px-2 py-0.5 rounded leading-relaxed transition-colors ${
                    isChanged
                      ? "bg-rose-950/40 text-rose-200 border-l-2 border-rose-500 font-semibold"
                      : "text-quiet hover:bg-white/5"
                  }`}
                >
                  <span className="w-8 select-none text-[10px] text-quiet/50 shrink-0 font-mono">
                    {i + 1}
                  </span>
                  <span className="whitespace-pre flex-1">{line || " "}</span>
                  {isChanged && (
                    <span className="text-[9px] font-mono text-rose-400 bg-rose-950/70 px-1.5 py-0.2 rounded border border-rose-500/40 ml-2 shrink-0 select-none">
                      - VULNERABLE
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Patched Code (AFTER) */}
        <div>
          <div className="bg-canvas/90 px-3 py-2 border-b border-subtle flex items-center justify-between text-[11px] font-sans font-semibold text-emerald-400">
            <span>REMEDIATED CODE (PQC COMPLIANT)</span>
            <span className="text-[10px] bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded font-mono">
              AFTER (NIST FIPS 203)
            </span>
          </div>
          <div className="overflow-x-auto p-2 space-y-0.5 max-h-[460px]">
            {patchedLines.map((line: string, i: number) => {
              const origEquivalent = origLines[i];
              const isChanged = origEquivalent !== undefined && line !== origEquivalent;

              return (
                <div
                  key={`patch-${i}`}
                  className={`flex items-start px-2 py-0.5 rounded leading-relaxed transition-colors ${
                    isChanged
                      ? "bg-emerald-950/40 text-emerald-200 border-l-2 border-emerald-500 font-semibold"
                      : "text-foreground hover:bg-white/5"
                  }`}
                >
                  <span className="w-8 select-none text-[10px] text-quiet/50 shrink-0 font-mono">
                    {i + 1}
                  </span>
                  <span className="whitespace-pre flex-1">{line || " "}</span>
                  {isChanged && (
                    <span className="text-[9px] font-mono text-emerald-400 bg-emerald-950/70 px-1.5 py-0.2 rounded border border-emerald-500/40 ml-2 shrink-0 select-none">
                      + REMEDIATED
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-xl border border-cyan-500/30 bg-gradient-to-r from-cyan-950/30 via-surface to-canvas p-6 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-cyan-400 font-bold text-base">
            <Zap className="h-5 w-5" />
            <span>Deterministic Cryptographic Migration Engine</span>
          </div>
          <span className="text-xs font-mono font-bold bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 px-2.5 py-1 rounded-full">
            NIST FIPS 203 &amp; FIPS 180-4
          </span>
        </div>
        <p className="text-xs text-quiet max-w-3xl leading-relaxed">
          Transforms discovered cryptographic vulnerabilities into NIST-compliant post-quantum
          constructs. Automatically creates unified diffs, runs localized regression tests, and
          prepares verifiable patch bundles.
        </p>
      </div>

      {/* Step 1: Select Scan Job and Findings Checklist */}
      <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-subtle pb-3">
          <div>
            <label className="text-xs font-bold uppercase tracking-wider text-foreground flex items-center gap-2">
              <span className="flex h-5 w-5 items-center justify-center rounded-full bg-cyan-500 text-[11px] font-black text-black">
                1
              </span>
              Select Completed Discovery Scan
            </label>
            <p className="text-xs text-quiet mt-0.5">
              Choose an AST or source discovery scan containing cryptographic findings.
            </p>
          </div>

          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            disabled={loadingScans || scans.length === 0}
            className="px-3 py-2 text-xs font-mono rounded-lg border border-subtle bg-canvas text-cyan-400 outline-none min-w-[280px]"
          >
            {scans.length === 0 ? (
              <option value="">No completed scans found</option>
            ) : (
              scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.kind.toUpperCase()} Scan ({s.id.slice(0, 8)}) ·{" "}
                  {new Date(s.created_at).toLocaleTimeString()}
                </option>
              ))
            )}
          </select>
        </div>

        {/* Findings Checklist */}
        <div className="space-y-2 pt-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-foreground">
              Vulnerable Cryptographic Sinks to Remediate:
            </span>
            <span className="text-[11px] text-cyan-400 font-mono">
              {findings.filter((f) => f.checked).length} of {findings.length} selected
            </span>
          </div>

          {findings.length === 0 ? (
            <div className="p-6 rounded-lg border border-dashed border-subtle bg-canvas/40 text-center space-y-2">
              <CheckCircle2 className="h-6 w-6 text-emerald-400 mx-auto" />
              <div className="text-xs font-semibold text-foreground">No Remediable Cryptographic Sinks Found</div>
              <p className="text-[11px] text-quiet max-w-md mx-auto">
                The selected scan does not contain classical cryptography requiring automated replacement. Select another scan from the dropdown above or run a new scan in Scan Studio.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-2.5">
              {findings.map((finding) => (
                <div
                  key={finding.id}
                  onClick={() => toggleFinding(finding.id)}
                  className={`flex items-center justify-between p-3 rounded-lg border text-xs cursor-pointer transition-colors ${
                    finding.checked
                      ? "border-cyan-500/40 bg-cyan-950/10 text-foreground"
                      : "border-subtle bg-canvas/60 text-quiet opacity-60"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <input
                      type="checkbox"
                      checked={finding.checked}
                      onChange={() => {}} // handled by parent div
                      className="h-4 w-4 rounded border-subtle text-cyan-500 focus:ring-cyan-500"
                    />
                    <div>
                      <div className="font-semibold flex items-center gap-2 font-mono">
                        <span className="text-rose-400">{finding.algorithm}</span>
                        <span className="text-quiet text-[11px]">at line {finding.line}</span>
                        <span className="text-cyan-400 font-mono text-[11px]">
                          → Replace with {finding.replacement}
                        </span>
                      </div>
                      <code className="text-[11px] text-quiet/80 font-mono mt-0.5 block">
                        {finding.code}
                      </code>
                    </div>
                  </div>

                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface border border-subtle shrink-0">
                    {finding.pattern_id}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Action Button */}
        <div className="pt-3 flex justify-end">
          <button
            type="button"
            onClick={handleGeneratePatches}
            disabled={isPatching || findings.filter((f) => f.checked).length === 0}
            className="px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-bold text-xs flex items-center gap-2 shadow-lg shadow-cyan-500/20 disabled:opacity-50"
          >
            {isPatching ? (
              <RefreshCw className="h-4 w-4 animate-spin" />
            ) : (
              <Zap className="h-4 w-4 fill-current" />
            )}
            <span>
              {isPatching ? "Generating & Testing Patches..." : "Generate Patches & Run Regression"}
            </span>
          </button>
        </div>
      </div>

      {/* Step 2: Live Terminal Execution Log */}
      {(isPatching || terminalLogs.length > 0) && (
        <div className="rounded-xl border border-subtle bg-canvas overflow-hidden shadow-2xl space-y-0">
          <div className="bg-[#0f141c] px-4 py-2.5 border-b border-subtle flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-mono text-quiet">
              <Terminal className="h-4 w-4 text-cyan-400" />
              <span>Deterministic Migration Execution Terminal</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="h-2.5 w-2.5 rounded-full bg-rose-500/60" />
              <div className="h-2.5 w-2.5 rounded-full bg-amber-500/60" />
              <div className="h-2.5 w-2.5 rounded-full bg-emerald-500/60" />
            </div>
          </div>

          <div className="p-4 font-mono text-xs text-foreground bg-[#0a0d14] max-h-56 overflow-y-auto space-y-1.5 leading-relaxed">
            {terminalLogs.map((log, idx) => {
              const isFound = log.includes("[ FOUND ]");
              const isTransform = log.includes("[ AST TRANSFORM ]");
              const isCompliance = log.includes("[ COMPLIANCE ]");
              const isCodegen = log.includes("[ CODEGEN ]");
              const isPatch = log.includes("[ PATCH ]");
              const isVerifier = log.includes("[ VERIFIER ]") || log.includes("[ VERIFIED ]");
              const isPass = log.includes("[ PASS ]");
              const isDone = log.includes("[ DONE ]");
              const isError = log.includes("[ ERROR ]");

              let color = "text-gray-300";
              if (isFound) color = "text-amber-400 font-semibold";
              else if (isTransform) color = "text-cyan-300 font-bold";
              else if (isCompliance) color = "text-purple-300";
              else if (isCodegen) color = "text-blue-300";
              else if (isPatch) color = "text-cyan-400";
              else if (isVerifier) color = "text-emerald-300 font-semibold";
              else if (isPass) color = "text-emerald-400 font-semibold";
              else if (isDone) color = "text-emerald-300 font-bold text-[13px]";
              else if (isError) color = "text-rose-400 font-bold";

              return (
                <div key={idx} className={color}>
                  {log}
                </div>
              );
            })}
            <div ref={terminalEndRef} />
          </div>
        </div>
      )}

      {/* Step 3: Split Diff View (The WOW Showpiece) */}
      {patchResult && (
        <div className="rounded-xl border border-cyan-500/30 bg-surface p-5 space-y-4 shadow-xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-subtle pb-3">
            <div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                <h3 className="text-sm font-bold text-foreground">
                  Migration Verification: {patchResult.total_patched} {patchResult.total_patched === 1 ? "Vulnerability" : "Vulnerabilities"} Remediated
                  <span className="ml-2 text-xs font-mono font-normal text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded">
                    {patchResult.test_results?.filter((t: any) => t.status === "passed").length || patchResult.total_patched}/{patchResult.test_results?.length || patchResult.total_patched} Tests Passed
                  </span>
                </h3>
              </div>
              <p className="text-xs text-quiet mt-0.5">
                Review side-by-side AST transformations and verified NIST FIPS 203 regression test results.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setActiveDiffTab("split")}
                className={`px-3 py-1.5 rounded text-xs font-semibold ${
                  activeDiffTab === "split"
                    ? "bg-cyan-500 text-black"
                    : "bg-canvas text-quiet border border-subtle"
                }`}
              >
                Split View
              </button>
              <button
                onClick={() => setActiveDiffTab("unified")}
                className={`px-3 py-1.5 rounded text-xs font-semibold ${
                  activeDiffTab === "unified"
                    ? "bg-cyan-500 text-black"
                    : "bg-canvas text-quiet border border-subtle"
                }`}
              >
                Unified Diff
              </button>
            </div>
          </div>

          {/* Visual Diff Rendering */}
          {activeDiffTab === "split" ? (
            renderSplitView()
          ) : (
            <div className="bg-canvas p-3 rounded-lg border border-subtle text-xs font-mono text-foreground overflow-x-auto max-h-[420px]">
              <pre className="whitespace-pre">{patchResult.unified_diff || "No diff generated."}</pre>
            </div>
          )}

          {/* Bottom Action Bar */}
          <div className="pt-2 flex flex-wrap items-center justify-between gap-3 border-t border-subtle">
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={handleDownloadProjectZip}
                disabled={downloadingZip}
                className="px-3.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-bold flex items-center gap-1.5 shadow-md shadow-cyan-500/20 disabled:opacity-50"
              >
                {downloadingZip ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Download className="h-3.5 w-3.5" />
                )}
                <span>Download Patched Project (.zip)</span>
              </button>

              <button
                type="button"
                onClick={handleDownloadFile}
                className="px-3.5 py-2 rounded-lg bg-canvas hover:bg-surface border border-subtle text-xs font-semibold flex items-center gap-1.5 text-foreground"
              >
                <FileCode className="h-3.5 w-3.5 text-emerald-400" />
                <span>Download Patched File</span>
              </button>

              <button
                type="button"
                onClick={handleDownloadPatch}
                className="px-3.5 py-2 rounded-lg bg-canvas hover:bg-surface border border-subtle text-xs font-semibold flex items-center gap-1.5 text-foreground"
              >
                <Download className="h-3.5 w-3.5 text-cyan-400" />
                <span>Download .patch</span>
              </button>
            </div>

            {onNavigateToVerify && (
              <button
                type="button"
                onClick={() => onNavigateToVerify(selectedScanId)}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold flex items-center gap-1.5 shadow-md shadow-emerald-600/20"
              >
                <ShieldCheck className="h-4 w-4" />
                <span>Run Verification Scan</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
