"use client";

import React, { useState, useEffect } from "react";
import {
  ArrowLeft,
  Zap,
  Download,
  Share2,
  FileCode,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Code2,
  CheckCircle2,
  ExternalLink,
  Layers,
  ChevronDown,
  ChevronRight,
  Clock,
  Sparkles,
} from "lucide-react";

interface ScanResultViewProps {
  scanId: string;
  projectId: string;
  onBack: () => void;
  onPatchAll?: (scanId: string) => void;
  onPatchAsset?: (scanId: string, algo: string) => void;
  onViewGraph?: () => void;
  onViewEvidence?: () => void;
}

export function ScanResultView({
  scanId,
  projectId,
  onBack,
  onPatchAll,
  onPatchAsset,
  onViewGraph,
  onViewEvidence,
}: ScanResultViewProps) {
  const [result, setResult] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedRows, setExpandedRows] = useState<Record<number, boolean>>({});

  useEffect(() => {
    async function loadResult() {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`/api/scans/${scanId}/result?project=${encodeURIComponent(projectId)}`);
        if (!res.ok) {
          throw new Error(`Failed to load scan results: ${res.statusText}`);
        }
        const data = await res.json();
        setResult(data);
      } catch (err: any) {
        setError(err.message || String(err));
      } finally {
        setLoading(false);
      }
    }
    loadResult();
  }, [scanId, projectId]);

  const toggleRow = (idx: number) => {
    setExpandedRows((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  if (loading) {
    return (
      <div className="rounded-xl border border-subtle bg-surface p-12 text-center space-y-4">
        <div className="inline-block h-8 w-8 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent" />
        <p className="text-xs text-quiet font-mono">Loading comprehensive cryptographic discovery result...</p>
      </div>
    );
  }

  if (error || !result) {
    return (
      <div className="rounded-xl border border-rose-500/30 bg-surface p-8 text-center space-y-4">
        <ShieldAlert className="h-8 w-8 text-rose-400 mx-auto" />
        <h3 className="text-sm font-bold text-rose-300">Could Not Load Scan Result</h3>
        <p className="text-xs text-quiet">{error || "No findings recorded for this scan job."}</p>
        <button
          onClick={onBack}
          className="px-4 py-2 rounded-lg bg-surface border border-subtle text-xs font-semibold"
        >
          Return to Scan Jobs
        </button>
      </div>
    );
  }

  const findings = result.findings || [];
  const totalFindings = findings.length;
  const critCount = result.critical_count || 0;
  const highCount = result.high_count || 0;
  const medCount = result.medium_count || 0;
  const safeCount = result.safe_count || 0;

  const critPct = totalFindings > 0 ? (critCount / totalFindings) * 100 : 0;
  const highPct = totalFindings > 0 ? (highCount / totalFindings) * 100 : 0;
  const medPct = totalFindings > 0 ? (medCount / totalFindings) * 100 : 0;
  const safePct = totalFindings > 0 ? (safeCount / totalFindings) * 100 : 0;

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb & Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-subtle pb-4">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-1.5 rounded-lg border border-subtle bg-surface hover:bg-canvas text-quiet hover:text-foreground transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold tracking-tight text-foreground font-mono">
                {result.kind?.toUpperCase()} Scan Result · #{scanId.slice(0, 8)}
              </h2>
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                {result.status?.toUpperCase()}
              </span>
            </div>
            <p className="text-xs text-quiet mt-0.5">
              Completed {new Date(result.finished_at || result.created_at).toLocaleString()} · Scanned {result.files_scanned} files
            </p>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {onPatchAll && (
            <button
              onClick={() => onPatchAll(scanId)}
              className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-bold flex items-center gap-1.5 shadow-md shadow-cyan-500/20"
            >
              <Zap className="h-3.5 w-3.5 fill-current" />
              <span>Patch All Issues</span>
            </button>
          )}

          {onViewGraph && (
            <button
              onClick={onViewGraph}
              className="px-3 py-1.5 rounded-lg bg-surface hover:bg-canvas border border-subtle text-xs font-semibold flex items-center gap-1.5 text-foreground"
            >
              <Layers className="h-3.5 w-3.5 text-cyan-400" />
              <span>View in Graph</span>
            </button>
          )}

          {onViewEvidence && (
            <button
              onClick={onViewEvidence}
              className="px-3 py-1.5 rounded-lg bg-surface hover:bg-canvas border border-subtle text-xs font-semibold flex items-center gap-1.5 text-foreground"
            >
              <Code2 className="h-3.5 w-3.5 text-emerald-400" />
              <span>View Evidence</span>
            </button>
          )}
        </div>
      </div>

      {/* Section A — Discovery Summary */}
      <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold uppercase tracking-wider text-quiet">
            Discovery Summary &amp; Risk Distribution
          </span>
          <span className="text-xs font-mono text-cyan-400">
            AST Coverage: {result.ast_coverage_pct}%
          </span>
        </div>

        {/* Metric counts */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          <div className="p-3 rounded-lg bg-canvas border border-subtle text-center">
            <div className="text-xl font-bold font-mono text-foreground">{result.files_scanned}</div>
            <div className="text-[11px] text-quiet mt-0.5">Files Scanned</div>
          </div>
          <div className="p-3 rounded-lg bg-canvas border border-subtle text-center">
            <div className="text-xl font-bold font-mono text-cyan-400">{totalFindings}</div>
            <div className="text-[11px] text-quiet mt-0.5">Algorithms Found</div>
          </div>
          <div className="p-3 rounded-lg bg-canvas border border-subtle text-center">
            <div className="text-xl font-bold font-mono text-rose-400">{critCount}</div>
            <div className="text-[11px] text-quiet mt-0.5">Critical (Shor)</div>
          </div>
          <div className="p-3 rounded-lg bg-canvas border border-subtle text-center">
            <div className="text-xl font-bold font-mono text-amber-400">{highCount}</div>
            <div className="text-[11px] text-quiet mt-0.5">High Risk</div>
          </div>
          <div className="p-3 rounded-lg bg-canvas border border-subtle text-center col-span-2 sm:col-span-1">
            <div className="text-xl font-bold font-mono text-emerald-400">{safeCount}</div>
            <div className="text-[11px] text-quiet mt-0.5">Quantum Safe</div>
          </div>
        </div>

        {/* Stacked risk bar */}
        <div className="space-y-1.5 pt-1">
          <div className="flex justify-between text-[11px] text-quiet">
            <span>Risk Composition</span>
            <span className="font-mono">
              {critCount} Critical · {highCount} High · {medCount} Medium · {safeCount} Safe
            </span>
          </div>
          <div className="h-3 w-full rounded-full bg-canvas overflow-hidden flex border border-subtle">
            {critPct > 0 && (
              <div
                style={{ width: `${critPct}%` }}
                className="bg-rose-500 h-full transition-all"
                title={`Critical: ${critCount}`}
              />
            )}
            {highPct > 0 && (
              <div
                style={{ width: `${highPct}%` }}
                className="bg-amber-500 h-full transition-all"
                title={`High: ${highCount}`}
              />
            )}
            {medPct > 0 && (
              <div
                style={{ width: `${medPct}%` }}
                className="bg-yellow-500 h-full transition-all"
                title={`Medium: ${medCount}`}
              />
            )}
            {safePct > 0 && (
              <div
                style={{ width: `${safePct}%` }}
                className="bg-emerald-500 h-full transition-all"
                title={`Safe: ${safeCount}`}
              />
            )}
          </div>
        </div>
      </div>

      {/* Section B — Discovered Algorithm Findings Table */}
      <div className="rounded-xl border border-subtle bg-surface overflow-hidden space-y-0">
        <div className="px-5 py-4 border-b border-subtle flex items-center justify-between">
          <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
            <FileCode className="h-4 w-4 text-cyan-400" />
            Discovered Cryptographic Findings ({totalFindings})
          </h3>
          <span className="text-xs text-quiet">Click any finding to inspect AST line evidence</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-subtle bg-canvas/60 text-quiet uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4 w-8"></th>
                <th className="py-3 px-4">Algorithm &amp; Key</th>
                <th className="py-3 px-4">Location</th>
                <th className="py-3 px-4">Risk Classification</th>
                <th className="py-3 px-4">Quantum Attack Vector</th>
                <th className="py-3 px-4">NIST Replacement</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-subtle font-mono">
              {findings.map((f: any, idx: number) => {
                const isExpanded = !!expandedRows[idx];
                const sev = f.severity || "HIGH";
                const isCrit = sev === "CRITICAL";
                const isHigh = sev === "HIGH";

                const badgeBg = isCrit
                  ? "bg-rose-500/10 text-rose-400 border-rose-500/20"
                  : isHigh
                  ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                  : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";

                return (
                  <React.Fragment key={idx}>
                    <tr
                      onClick={() => toggleRow(idx)}
                      className="hover:bg-canvas/80 cursor-pointer transition-colors"
                    >
                      <td className="py-3 px-4 text-quiet">
                        {isExpanded ? (
                          <ChevronDown className="h-4 w-4 text-cyan-400" />
                        ) : (
                          <ChevronRight className="h-4 w-4" />
                        )}
                      </td>
                      <td className="py-3 px-4 font-bold text-foreground">
                        <div className="flex items-center gap-2">
                          <span className={isCrit ? "text-rose-400" : isHigh ? "text-amber-400" : "text-emerald-400"}>
                            {f.algorithm}
                          </span>
                          {f.key_size && (
                            <span className="text-[10px] text-quiet px-1.5 py-0.5 rounded bg-surface border border-subtle">
                              {f.key_size}-bit
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-cyan-400 underline decoration-cyan-500/30 underline-offset-4">
                        {f.location}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${badgeBg}`}>
                          {sev}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-quiet text-[11px] font-sans">
                        {f.quantum_attack_vector}
                      </td>
                      <td className="py-3 px-4 text-emerald-400 text-[11px] font-mono font-semibold">
                        {f.recommended_replacement}
                      </td>
                      <td className="py-3 px-4 text-right">
                        {onPatchAsset && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onPatchAsset(scanId, f.algorithm);
                            }}
                            className="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-[11px] font-sans font-semibold transition-colors"
                          >
                            Patch This
                          </button>
                        )}
                      </td>
                    </tr>

                    {/* Section C: Code Evidence Drawer */}
                    {isExpanded && (
                      <tr className="bg-canvas/90 border-b border-subtle">
                        <td colSpan={7} className="p-4 space-y-3 font-sans">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-semibold text-foreground flex items-center gap-2">
                              <Code2 className="h-4 w-4 text-cyan-400" />
                              AST Code Evidence · {f.location}
                            </span>
                            <div className="flex items-center gap-2 font-mono text-[10px]">
                              <span className="px-2 py-0.5 rounded bg-surface border border-subtle text-cyan-300">
                                Rule: {f.rule_id}
                              </span>
                              <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                Evidence Level: {f.evidence_level}
                              </span>
                            </div>
                          </div>

                          {/* Code snippet with highlight */}
                          <div className="p-3 rounded-lg bg-[#0b0f17] border border-subtle font-mono text-xs text-foreground overflow-x-auto">
                            <div className="flex items-center gap-3">
                              <span className="select-none text-quiet/40 w-6 text-right">
                                {f.line}
                              </span>
                              <span className="bg-rose-500/20 text-rose-300 px-1 py-0.5 rounded font-bold">
                                {f.code || "Cryptographic primitive call"}
                              </span>
                            </div>
                          </div>

                          <div className="text-xs text-quiet flex items-center justify-between pt-1">
                            <p>
                              <strong>Issue:</strong> {f.issue}
                            </p>
                            <span className="text-emerald-400 text-[11px]">
                              Engine: {f.engine}
                            </span>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Section D — Visual Risk Map (Quantum Break Urgency) */}
      <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-foreground flex items-center gap-2">
            <Clock className="h-4 w-4 text-amber-400" />
            Visual Quantum Threat Timeline (Mosca Z-Horizon)
          </h3>
          <span className="text-xs text-quiet">Projected breakdown trajectory under Shor's &amp; Grover's cryptanalysis</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="p-4 rounded-lg bg-rose-950/20 border border-rose-500/30 space-y-2">
            <div className="flex items-center justify-between text-xs font-bold text-rose-400">
              <span>IMMEDIATE (0 - 3 YRS)</span>
              <span>CRITICAL</span>
            </div>
            <p className="text-xs text-quiet">
              Harvest Now, Decrypt Later (HNDL) exposure for long-lifetime data encrypted with RSA-2048 / ECC.
            </p>
            <div className="font-mono text-xs text-rose-300 font-bold">
              Targets: RSA-2048, MD5, SHA-1
            </div>
          </div>

          <div className="p-4 rounded-lg bg-amber-950/20 border border-amber-500/30 space-y-2">
            <div className="flex items-center justify-between text-xs font-bold text-amber-400">
              <span>MIGRATION (3 - 7 YRS)</span>
              <span>HIGH</span>
            </div>
            <p className="text-xs text-quiet">
              Rollout hybrid PQC standards (ML-KEM-768 / ML-DSA-65) across network gateways and core protocols.
            </p>
            <div className="font-mono text-xs text-amber-300 font-bold">
              Targets: TLS 1.3 Hybrid, AES-256
            </div>
          </div>

          <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-500/30 space-y-2">
            <div className="flex items-center justify-between text-xs font-bold text-emerald-400">
              <span>QUANTUM RESILIENT (&gt; 7 YRS)</span>
              <span>SAFE</span>
            </div>
            <p className="text-xs text-quiet">
              Full post-quantum compliance. All asymmetric sinks migrated to NIST FIPS 203/204 standards.
            </p>
            <div className="font-mono text-xs text-emerald-300 font-bold">
              Targets: ML-KEM, ML-DSA, SHA-3
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
