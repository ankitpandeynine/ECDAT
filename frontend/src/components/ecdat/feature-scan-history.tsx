"use client";

import { useState, useMemo } from "react";
import {
  Globe,
  Code2,
  Binary,
  CheckCircle2,
  AlertTriangle,
  CircleHelp,
  Download,
  RotateCcw,
  Search,
  ShieldCheck,
  ShieldAlert,
  Key,
  FileCode2,
  Clock,
  FileText,
  Copy,
  Check,
  Radio,
} from "lucide-react";
import { Scan, Finding } from "@/lib/api";

const panelClass = "min-w-0 rounded-lg border border-subtle bg-surface";

interface FeatureScanHistoryProps {
  mode: "network" | "code" | "binary" | "pcap";
  scans: Scan[];
  selectedId: string | null;
  onSelectScan: (id: string) => void;
  exportIds: string[];
  onToggleExport: (id: string) => void;
  onRescanTarget?: (target: string, language?: string, code?: string) => void;
  onDownloadSingleCbom: (scan: Scan) => void;
  onRefresh: () => void;
}

const kindMeta = {
  network: {
    label: "Network Scan",
    plural: "Network scans",
    icon: Globe,
    title: "Network Scan History & Post-Quantum TLS Observations",
    subtitle:
      "Historical record of observed TLS cipher suites, hybrid post-quantum key exchanges, certificates, and HNDL risk for servers scanned in this project.",
    emptyHelp:
      "Enter a hostname or HTTPS server address above and click 'Start scan' to observe real TLS handshakes and hybrid PQC key exchange.",
  },
  code: {
    label: "Source Code Scan",
    plural: "Source code scans",
    icon: Code2,
    title: "Source Code Scan History & Cryptographic Findings",
    subtitle:
      "Historical record of discovered cryptographic algorithm calls, deprecated hash functions, weak key lengths, and line references in your codebase.",
    emptyHelp:
      "Upload source files or paste code snippets above to find cryptographic primitives and identify post-quantum migration targets.",
  },
  binary: {
    label: "Binary & Firmware Scan",
    plural: "Binary & firmware scans",
    icon: Binary,
    title: "Binary & Firmware Scan History & Signatures",
    subtitle:
      "Historical record of cryptographic constants, S-boxes, unstripped private key sequences, and section entropy from compiled executables and archives.",
    emptyHelp:
      "Upload an ELF, PE, raw firmware binary, or ZIP archive above to inspect embedded cryptographic signatures.",
  },
  pcap: {
    label: "Passive PCAP Scan",
    plural: "Passive PCAP scans",
    icon: Radio,
    title: "Passive PCAP History & Dissected TLS Handshakes",
    subtitle:
      "Historical record of passively dissected TLS handshakes, ML-KEM post-quantum hybrid sessions, and JA3/JA4 fingerprints from network traffic captures.",
    emptyHelp:
      "Upload a .pcap file or trigger synthetic traffic above to passively inspect TLS sessions without active probing.",
  },
} as const;


function StatusBadge({ status }: { status: Scan["status"] }) {
  const color =
    status === "completed"
      ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
      : status === "failed"
        ? "border-red-500/20 bg-red-500/10 text-red-400"
        : status === "cancelled"
          ? "border-slate-500/20 bg-slate-500/10 text-quiet"
          : "border-cyan-500/20 bg-cyan-500/10 text-cyan-400";
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 rounded border px-2 py-0.5 text-[10px] font-medium capitalize ${color}`}
    >
      {status === "running" && (
        <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" />
      )}
      {status}
    </span>
  );
}

function getScanTargetLabel(scan: Scan): string {
  const matches = scan.result?.findings || scan.result?.detections || [];
  return (
    scan.result?.target ||
    matches[0]?.file ||
    `${scan.kind.toUpperCase()} · ${scan.id.slice(0, 8)}`
  );
}

export function FeatureScanHistory({
  mode,
  scans,
  selectedId,
  onSelectScan,
  exportIds,
  onToggleExport,
  onRescanTarget,
  onDownloadSingleCbom,
  onRefresh,
}: FeatureScanHistoryProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [copiedId, setCopiedId] = useState(false);

  // STRICT FILTERING: Only scans belonging to THIS specific feature
  const featureScans = useMemo(() => {
    return scans.filter((s) => s.kind === mode);
  }, [scans, mode]);

  const filteredScans = useMemo(() => {
    if (!searchQuery.trim()) return featureScans;
    const q = searchQuery.toLowerCase();
    return featureScans.filter((s) => {
      const target = getScanTargetLabel(s).toLowerCase();
      const id = s.id.toLowerCase();
      const findings = s.result?.findings || s.result?.detections || [];
      const hasPrimitive = findings.some((f) =>
        f.primitive?.toLowerCase().includes(q),
      );
      const cipher = s.result?.cipher_name?.toLowerCase() || "";
      const protocol = s.result?.protocol?.toLowerCase() || "";
      return (
        target.includes(q) ||
        id.includes(q) ||
        hasPrimitive ||
        cipher.includes(q) ||
        protocol.includes(q)
      );
    });
  }, [featureScans, searchQuery]);

  // Determine active selected scan for this feature
  const activeScan = useMemo(() => {
    if (selectedId) {
      const match = featureScans.find((s) => s.id === selectedId);
      if (match) return match;
    }
    return featureScans[0] || null;
  }, [featureScans, selectedId]);

  const meta = kindMeta[mode];
  const Icon = meta.icon;

  const handleCopyId = (id: string) => {
    navigator.clipboard.writeText(id);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  return (
    <section
      className="mt-8 space-y-4 border-t border-subtle pt-6"
      aria-labelledby="feature-history-heading"
    >
      {/* Header bar */}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-7 items-center justify-center rounded border border-cyan-500/25 bg-cyan-500/10 text-cyan-400">
              <Icon size={16} />
            </div>
            <h3
              id="feature-history-heading"
              className="text-base font-semibold tracking-tight text-foreground"
            >
              {meta.title}
            </h3>
          </div>
          <p className="mt-1 text-xs text-quiet max-w-3xl">
            {meta.subtitle}
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <div className="relative">
            <Search
              size={13}
              className="absolute left-2.5 top-1/2 -translate-y-1/2 text-quiet"
            />
            <input
              type="text"
              placeholder={`Filter ${meta.label.toLowerCase()}s...`}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="rounded-md border border-subtle bg-canvas pl-8 pr-3 py-1.5 text-xs text-foreground placeholder:text-quiet outline-none focus:border-cyan-500 w-48 sm:w-60"
            />
          </div>

          <button
            onClick={onRefresh}
            className="flex items-center gap-1.5 rounded-md border border-subtle bg-surface px-3 py-1.5 text-xs text-quiet hover:bg-surface-raised hover:text-cyan-400 transition-colors"
            title="Refresh records"
          >
            <RotateCcw size={12} />
            Refresh
          </button>
        </div>
      </div>

      {/* Empty State */}
      {!featureScans.length ? (
        <div className={`${panelClass} p-12 text-center`}>
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full border border-subtle bg-canvas text-quiet mb-3">
            <Icon size={22} />
          </div>
          <h4 className="text-sm font-semibold text-foreground">
            No {meta.label.toLowerCase()} records yet
          </h4>
          <p className="mt-1.5 text-xs text-quiet max-w-md mx-auto leading-relaxed">
            {meta.emptyHelp}
          </p>
        </div>
      ) : (
        <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
          {/* Left Column: Feature Scans List */}
          <div className={`${panelClass} overflow-hidden`}>
            <div className="flex items-center justify-between border-b border-subtle px-4 py-3 bg-canvas/40">
              <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                <FileText size={13} className="text-cyan-400" />
                {meta.label} Records ({filteredScans.length})
              </span>
              <span className="text-[11px] text-quiet">
                Click a record to inspect evidence
              </span>
            </div>

            <div className="max-h-[580px] divide-y divide-[var(--ecdat-border-subtle)] overflow-y-auto">
              {filteredScans.map((scan) => {
                const isSelected = activeScan?.id === scan.id;
                const findingsCount = (
                  scan.result?.findings ||
                  scan.result?.detections ||
                  []
                ).length;
                const isExported = exportIds.includes(scan.id);

                return (
                  <div
                    key={scan.id}
                    onClick={() => onSelectScan(scan.id)}
                    className={`border-l-2 p-3.5 cursor-pointer transition-colors ${
                      isSelected
                        ? "border-l-cyan-500 bg-cyan-500/5"
                        : "border-l-transparent hover:bg-surface-raised/40"
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <input
                        type="checkbox"
                        checked={isExported}
                        disabled={scan.status !== "completed"}
                        onChange={(e) => {
                          e.stopPropagation();
                          onToggleExport(scan.id);
                        }}
                        aria-label={`Select ${scan.id} for report`}
                        className="mt-1 h-3.5 w-3.5 shrink-0 accent-cyan-500 rounded cursor-pointer"
                      />

                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-xs font-semibold truncate text-foreground">
                            {getScanTargetLabel(scan)}
                          </span>
                          <StatusBadge status={scan.status} />
                        </div>

                        {/* Feature-specific summary line */}
                        <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[11px] text-quiet">
                          <span className="flex items-center gap-1">
                            <Clock size={11} />
                            {new Date(scan.created_at).toLocaleTimeString([], {
                              hour: "2-digit",
                              minute: "2-digit",
                            })}{" "}
                            · {new Date(scan.created_at).toLocaleDateString()}
                          </span>

                          {/* Network metadata */}
                          {mode === "network" && scan.result && (
                            <>
                              <span className="text-foreground/80 font-mono text-[10px] px-1.5 py-0.2 rounded bg-surface border border-subtle">
                                {scan.result.protocol || "TLS"}
                              </span>
                              {scan.result.quantum_vulnerable === true && (
                                <span className="text-red-400 font-medium text-[10px] px-1.5 py-0.2 rounded bg-red-500/10 border border-red-500/20">
                                  PQ Vulnerable
                                </span>
                              )}
                              {scan.result.quantum_vulnerable === false && (
                                <span className="text-emerald-400 font-medium text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/10 border border-emerald-500/20">
                                  PQ Ready
                                </span>
                              )}
                            </>
                          )}

                          {/* Code metadata */}
                          {mode === "code" && (
                            <span className="text-foreground/80 font-medium">
                              {findingsCount} finding{findingsCount === 1 ? "" : "s"}
                            </span>
                          )}

                          {/* Binary metadata */}
                          {mode === "binary" && (
                            <span className="text-foreground/80 font-medium">
                              {findingsCount} signature{findingsCount === 1 ? "" : "s"}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Column: Active Scan Details & Findings */}
          <div className={`${panelClass} p-5 space-y-5`}>
            {!activeScan ? (
              <div className="p-12 text-center text-quiet">
                <Search size={28} className="mx-auto mb-2 opacity-50" />
                <p className="text-sm">Select a scan from the list to review its findings</p>
              </div>
            ) : (
              <>
                {/* Active scan header */}
                <div className="flex flex-wrap items-start justify-between gap-3 border-b border-subtle pb-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-bold text-foreground break-all">
                        {getScanTargetLabel(activeScan)}
                      </span>
                      <StatusBadge status={activeScan.status} />
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-quiet">
                      <span>
                        Scan ID:{" "}
                        <button
                          onClick={() => handleCopyId(activeScan.id)}
                          className="font-mono hover:text-cyan-400 inline-flex items-center gap-1"
                          title="Click to copy full ID"
                        >
                          {activeScan.id.slice(0, 12)}...
                          {copiedId ? <Check size={11} /> : <Copy size={11} />}
                        </button>
                      </span>
                      <span>•</span>
                      <span>
                        Engine: {activeScan.engine_version || "ECDAT v3.0"}
                      </span>
                      <span>•</span>
                      <span>
                        {new Date(activeScan.created_at).toLocaleString()}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {/* Re-scan action */}
                    {onRescanTarget && activeScan.result?.target && (
                      <button
                        onClick={() =>
                          onRescanTarget(activeScan.result?.target || "")
                        }
                        className="rounded border border-subtle bg-surface px-2.5 py-1 text-xs text-quiet hover:bg-surface-raised hover:text-foreground flex items-center gap-1"
                        title="Load target into scan box above"
                      >
                        <RotateCcw size={12} />
                        Re-scan
                      </button>
                    )}

                    {/* Single scan CBOM download */}
                    <button
                      onClick={() => onDownloadSingleCbom(activeScan)}
                      disabled={activeScan.status !== "completed"}
                      className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-1 text-xs text-cyan-400 hover:bg-cyan-500/20 flex items-center gap-1 disabled:opacity-50"
                      title="Download CycloneDX 1.6 CBOM for this scan"
                    >
                      <Download size={12} />
                      CBOM
                    </button>
                  </div>
                </div>

                {/* Scan failure message */}
                {activeScan.error && (
                  <div
                    role="alert"
                    className="rounded-md border border-red-500/25 bg-red-500/10 p-3.5 text-xs text-red-400 space-y-1"
                  >
                    <div className="flex items-center gap-1.5 font-bold">
                      <AlertTriangle size={14} />
                      Scan Error
                    </div>
                    <p className="leading-relaxed">{activeScan.error}</p>
                  </div>
                )}

                {/* Scan in progress message */}
                {["queued", "running"].includes(activeScan.status) && (
                  <div className="rounded-md border border-cyan-500/20 bg-cyan-500/5 p-4 text-center space-y-2">
                    <div className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
                    <p className="text-xs text-foreground font-medium">
                      Scan is actively executing in the background...
                    </p>
                    <p className="text-[11px] text-quiet">
                      Evidence and findings will populate automatically once the probe completes.
                    </p>
                  </div>
                )}

                {/* COMPLETED FINDINGS */}
                {activeScan.status === "completed" && activeScan.result && (
                  <div className="space-y-5">
                    {/* 1. NETWORK SPECIFIC EVIDENCE */}
                    {mode === "network" && (
                      <div className="space-y-4">
                        {/* TLS Observation Grid */}
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                          <div className="rounded border border-subtle bg-canvas/50 p-2.5 text-center">
                            <span className="text-[10px] uppercase tracking-wider text-quiet">
                              TLS Version
                            </span>
                            <div className="mt-1 font-mono text-sm font-bold text-foreground">
                              {activeScan.result.protocol || "Not measured"}
                            </div>
                          </div>

                          <div className="rounded border border-subtle bg-canvas/50 p-2.5 text-center">
                            <span className="text-[10px] uppercase tracking-wider text-quiet">
                              Cipher Suite
                            </span>
                            <div
                              className="mt-1 font-mono text-xs font-bold text-foreground truncate px-1"
                              title={activeScan.result.cipher_name}
                            >
                              {activeScan.result.cipher_name || "Not measured"}
                            </div>
                          </div>

                          <div className="rounded border border-subtle bg-canvas/50 p-2.5 text-center">
                            <span className="text-[10px] uppercase tracking-wider text-quiet">
                              Key Exchange
                            </span>
                            <div className="mt-1 font-mono text-xs font-bold text-foreground truncate px-1">
                              {activeScan.result.pqc_status || "Classical"}
                            </div>
                          </div>

                          <div className="rounded border border-subtle bg-canvas/50 p-2.5 text-center">
                            <span className="text-[10px] uppercase tracking-wider text-quiet">
                              Port & IP
                            </span>
                            <div className="mt-1 font-mono text-xs text-quiet">
                              {activeScan.result.target?.includes(":")
                                ? activeScan.result.target.split(":")[1]
                                : "443"}
                            </div>
                          </div>
                        </div>

                        {/* Post-Quantum Threat Assessment Card */}
                        <div
                          className={`rounded-lg border p-4 text-xs space-y-2.5 ${
                            activeScan.result.quantum_vulnerable === true
                              ? "border-red-500/25 bg-red-500/5 text-foreground"
                              : activeScan.result.quantum_vulnerable === false
                                ? "border-emerald-500/25 bg-emerald-500/5 text-foreground"
                                : "border-amber-500/25 bg-amber-500/5 text-foreground"
                          }`}
                        >
                          <div className="flex items-center gap-2 font-semibold">
                            {activeScan.result.quantum_vulnerable === true ? (
                              <>
                                <ShieldAlert size={16} className="text-red-400" />
                                <span className="text-red-400">
                                  Post-Quantum Threat: Vulnerable to Harvest-Now-Decrypt-Later
                                </span>
                              </>
                            ) : activeScan.result.quantum_vulnerable === false ? (
                              <>
                                <ShieldCheck size={16} className="text-emerald-400" />
                                <span className="text-emerald-400">
                                  Post-Quantum Ready: Hybrid Key Exchange Active
                                </span>
                              </>
                            ) : (
                              <>
                                <CircleHelp size={16} className="text-amber-400" />
                                <span className="text-amber-400">
                                  Post-Quantum Assessment Inconclusive
                                </span>
                              </>
                            )}
                          </div>

                          <p className="leading-relaxed text-quiet">
                            {activeScan.result.quantum_vulnerable === true
                              ? "The observed TLS session relies entirely on classical asymmetric key exchange (such as RSA or classical ECDH). Recorded ciphertext can be decrypted in the future by a Cryptanalytically Relevant Quantum Computer (CRQC)."
                              : activeScan.result.quantum_vulnerable === false
                                ? "This server successfully negotiated hybrid post-quantum key exchange groups conforming to NIST FIPS 203 (ML-KEM). The session resists retroactive decryption."
                                : "The scanner could not conclusively verify hybrid key exchange support on this target."}
                          </p>

                          {activeScan.result.hndl_risk && (
                            <div className="pt-2 border-t border-subtle flex items-center justify-between text-[11px]">
                              <span className="text-quiet">
                                HNDL Risk Rating:{" "}
                                <strong className="text-foreground">
                                  {activeScan.result.hndl_risk}
                                </strong>
                              </span>
                              <span className="text-quiet font-mono">
                                NIST Standard: FIPS 203 (ML-KEM)
                              </span>
                            </div>
                          )}

                          {activeScan.result.hndl_rationale && (
                            <p className="text-[11px] text-quiet italic">
                              {activeScan.result.hndl_rationale}
                            </p>
                          )}
                        </div>

                        {/* Certificate Evidence Card */}
                        {activeScan.result.certificate && (
                          <div className="rounded-lg border border-subtle bg-canvas/30 p-3.5 space-y-2 text-xs">
                            <span className="font-semibold text-foreground flex items-center gap-1.5">
                              <Key size={13} className="text-cyan-400" />
                              X.509 Certificate Evidence
                            </span>
                            <div className="space-y-1 font-mono text-[11px] text-quiet">
                              <div>
                                Subject:{" "}
                                <span className="text-foreground">
                                  {String(
                                    (activeScan.result.certificate as any)?.subject ||
                                      activeScan.result.target,
                                  )}
                                </span>
                              </div>
                              <div>
                                Issuer:{" "}
                                <span className="text-foreground">
                                  {String(
                                    (activeScan.result.certificate as any)?.issuer ||
                                      "Public CA",
                                  )}
                                </span>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* 2. SOURCE CODE SPECIFIC FINDINGS */}
                    {mode === "code" && (
                      <div className="space-y-4">
                        {/* Summary Pill Bar */}
                        <div className="flex items-center justify-between border-b border-subtle pb-2">
                          <span className="text-xs font-semibold text-foreground">
                            Identified Cryptographic Invocations (
                            {(activeScan.result.findings || []).length})
                          </span>
                          <span className="text-[11px] text-quiet">
                            Deterministic AST & pattern evidence
                          </span>
                        </div>

                        {!(activeScan.result.findings || []).length ? (
                          <div className="rounded border border-subtle p-6 text-center text-quiet text-xs">
                            <CheckCircle2 size={20} className="mx-auto mb-1 text-emerald-400" />
                            No deprecated or vulnerable cryptographic calls detected in this code snippet.
                          </div>
                        ) : (
                          <div className="space-y-2.5 max-h-[420px] overflow-y-auto pr-1">
                            {(activeScan.result.findings || []).map(
                              (finding: Finding, idx: number) => {
                                const sev = (
                                  finding.severity || "medium"
                                ).toLowerCase();
                                const badgeColor =
                                  sev === "critical"
                                    ? "border-red-500/30 bg-red-500/10 text-red-400"
                                    : sev === "high"
                                      ? "border-amber-500/30 bg-amber-500/10 text-amber-400"
                                      : "border-cyan-500/30 bg-cyan-500/10 text-cyan-400";

                                return (
                                  <div
                                    key={idx}
                                    className="rounded-md border border-subtle bg-canvas/50 p-3.5 space-y-2 text-xs"
                                  >
                                    <div className="flex items-center justify-between">
                                      <span className="font-mono text-sm font-bold text-foreground flex items-center gap-2">
                                        <FileCode2 size={14} className="text-cyan-400" />
                                        {finding.primitive || "Cryptographic Call"}
                                      </span>
                                      <span
                                        className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase ${badgeColor}`}
                                      >
                                        {finding.severity || "FINDING"}
                                      </span>
                                    </div>

                                    {/* Location reference */}
                                    <div className="flex items-center gap-2 text-[11px] font-mono text-quiet">
                                      <span>
                                        {finding.file || "snippet"}
                                        {finding.line ? `:${finding.line}` : ""}
                                      </span>
                                    </div>

                                    {/* Description */}
                                    {finding.description && (
                                      <p className="text-quiet leading-relaxed">
                                        {finding.description}
                                      </p>
                                    )}

                                    {/* Remediation guidance */}
                                    <div className="pt-2 border-t border-subtle/50 text-[11px] text-cyan-400 flex items-center justify-between">
                                      <span>
                                        PQC Migration Recommendation:{" "}
                                        {finding.primitive?.toUpperCase().includes("MD5")
                                          ? "Migrate to SHA-256 (NIST FIPS 180-4) or SHA-3"
                                          : finding.primitive?.toUpperCase().includes("RSA")
                                            ? "Migrate to ML-KEM-768 (NIST FIPS 203) / RSA-3072"
                                            : finding.primitive?.toUpperCase().includes("DES")
                                              ? "Migrate to AES-256-GCM (NIST FIPS 197)"
                                              : "Migrate to Post-Quantum Standard Algorithm"}
                                      </span>
                                    </div>
                                  </div>
                                );
                              },
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* 3. BINARY SPECIFIC DETECTIONS */}
                    {mode === "binary" && (
                      <div className="space-y-4">
                        <div className="flex items-center justify-between border-b border-subtle pb-2">
                          <span className="text-xs font-semibold text-foreground">
                            Embedded Cryptographic Constants & Keys (
                            {(activeScan.result.detections || []).length})
                          </span>
                          <span className="text-[11px] text-quiet">
                            Binary signature & S-box analysis
                          </span>
                        </div>

                        {!(activeScan.result.detections || []).length ? (
                          <div className="rounded border border-subtle p-6 text-center text-quiet text-xs">
                            <CheckCircle2 size={20} className="mx-auto mb-1 text-emerald-400" />
                            No embedded cryptographic constants or private key markers identified in this binary.
                          </div>
                        ) : (
                          <div className="space-y-2.5 max-h-[420px] overflow-y-auto pr-1">
                            {(activeScan.result.detections || []).map(
                              (det: Finding, idx: number) => (
                                <div
                                  key={idx}
                                  className="rounded-md border border-subtle bg-canvas/50 p-3.5 space-y-2 text-xs"
                                >
                                  <div className="flex items-center justify-between">
                                    <span className="font-mono text-sm font-bold text-foreground flex items-center gap-2">
                                      <Binary size={14} className="text-cyan-400" />
                                      {det.primitive || "Crypto Signature"}
                                    </span>
                                    <span className="rounded border border-cyan-500/20 bg-cyan-500/10 px-2 py-0.5 text-[10px] font-mono text-cyan-400">
                                      {det.confidence || "High Confidence"}
                                    </span>
                                  </div>

                                  <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-quiet">
                                    <div>
                                      Section:{" "}
                                      <span className="text-foreground">
                                        {det.file || ".text / .rodata"}
                                      </span>
                                    </div>
                                    {det.offset && (
                                      <div>
                                        Offset:{" "}
                                        <span className="text-foreground">
                                          {det.offset}
                                        </span>
                                      </div>
                                    )}
                                  </div>

                                  {det.description && (
                                    <p className="text-quiet leading-relaxed text-[11px]">
                                      {det.description}
                                    </p>
                                  )}
                                </div>
                              ),
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* 4. PCAP SPECIFIC SESSIONS */}
                    {mode === "pcap" && (
                      <div className="space-y-4">
                        <div className="flex items-center justify-between border-b border-subtle pb-2">
                          <span className="text-xs font-semibold text-foreground">
                            Dissected TLS Handshake Sessions (
                            {(activeScan.result.sessions || []).length})
                          </span>
                          <span className="text-[11px] text-quiet">
                            Passive capture analysis & JA4
                          </span>
                        </div>

                        {!(activeScan.result.sessions || []).length ? (
                          <div className="rounded border border-subtle p-6 text-center text-quiet text-xs">
                            <CheckCircle2 size={20} className="mx-auto mb-1 text-emerald-400" />
                            No TLS handshakes detected in this packet capture.
                          </div>
                        ) : (
                          <div className="space-y-3 max-h-[420px] overflow-y-auto pr-1">
                            {(activeScan.result.sessions || []).map(
                              (sess: any, idx: number) => (
                                <div
                                  key={idx}
                                  className="rounded-md border border-subtle bg-canvas/50 p-3.5 space-y-2 text-xs"
                                >
                                  <div className="flex items-center justify-between">
                                    <span className="font-mono text-xs font-bold text-foreground flex items-center gap-2">
                                      <Radio size={14} className="text-cyan-400" />
                                      {sess.client_ip}:{sess.client_port} ➔ {sess.server_ip}:{sess.server_port}
                                    </span>
                                    {sess.has_pqc_hybrid ? (
                                      <span className="rounded border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-mono text-emerald-400">
                                        PQC Hybrid
                                      </span>
                                    ) : (
                                      <span className="rounded border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-[10px] font-mono text-amber-400">
                                        Classical Only
                                      </span>
                                    )}
                                  </div>

                                  <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-quiet">
                                    <div>
                                      Cipher: <span className="text-foreground">{sess.selected_cipher || "N/A"}</span>
                                    </div>
                                    <div>
                                      SNI: <span className="text-foreground">{sess.sni || "N/A"}</span>
                                    </div>
                                  </div>

                                  {sess.ja4_fingerprint && (
                                    <div className="text-[11px] font-mono text-quiet flex items-center gap-2">
                                      <span>JA4:</span>
                                      <span className="text-emerald-400">{sess.ja4_fingerprint}</span>
                                    </div>
                                  )}
                                </div>
                              ),
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Complete JSON evidence accordion */}
                    <details className="rounded-md border border-subtle">

                      <summary className="cursor-pointer px-3 py-2.5 text-xs font-medium text-quiet hover:text-foreground">
                        Raw Evidence Record & CycloneDX CBOM Mapping
                      </summary>
                      <pre className="max-h-[320px] overflow-auto border-t border-subtle bg-canvas/50 p-3 text-[10px] font-mono leading-relaxed whitespace-pre-wrap break-all text-quiet">
                        {JSON.stringify(
                          {
                            scan_id: activeScan.id,
                            kind: activeScan.kind,
                            status: activeScan.status,
                            engine_version: activeScan.engine_version,
                            input_hash: activeScan.input_hash,
                            result: activeScan.result,
                          },
                          null,
                          2,
                        )}
                      </pre>
                    </details>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
