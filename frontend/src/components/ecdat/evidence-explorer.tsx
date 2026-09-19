"use client";

import React, { useEffect, useState } from "react";
import {
  FileCheck2,
  Filter,
  RefreshCw,
  X,
  Code2,
  Terminal,
  MapPin,
  Clock,
  Fingerprint,
} from "lucide-react";

export interface EvidenceRecord {
  id: string;
  asset_id?: string | null;
  scan_id: string;
  project: string;
  evidence_type: string;
  level: string; // "E0" | "E1" | "E2" | "E3" | "E4" | "E5"
  algorithm: string;
  location: string;
  snippet?: string;
  confidence: number;
  rule_id: string;
  timestamp: string;
  description?: string;
  source_engine?: string;
}

interface EvidenceExplorerProps {
  projectId: string;
  initialAssetIdFilter?: string | null;
  initialScanIdFilter?: string | null;
  onClearAssetFilter?: () => void;
  onNavigateToStudio?: () => void;
  onNavigateToAsset?: (assetId: string) => void;
  onNavigateToAutoPatch?: (scanId: string) => void;
}

export function EvidenceExplorer({
  projectId,
  initialAssetIdFilter,
  initialScanIdFilter,
  onClearAssetFilter,
  onNavigateToStudio,
  onNavigateToAsset,
  onNavigateToAutoPatch,
}: EvidenceExplorerProps) {
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [levelFilter, setLevelFilter] = useState<string>("All");
  const [assetIdFilter, setAssetIdFilter] = useState<string>(initialAssetIdFilter || "");
  const [scanIdFilter, setScanIdFilter] = useState<string>(initialScanIdFilter || "");

  // Synchronize when initialAssetIdFilter changes from props
  useEffect(() => {
    if (initialAssetIdFilter !== undefined) {
      setAssetIdFilter(initialAssetIdFilter || "");
    }
  }, [initialAssetIdFilter]);

  useEffect(() => {
    if (initialScanIdFilter !== undefined) {
      setScanIdFilter(initialScanIdFilter || "");
    }
  }, [initialScanIdFilter]);

  const fetchEvidence = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        project: projectId,
      });
      if (levelFilter !== "All") params.set("level", levelFilter);
      if (assetIdFilter.trim()) params.set("asset_id", assetIdFilter.trim());
      if (scanIdFilter.trim()) params.set("scan_id", scanIdFilter.trim());

      const res = await fetch(`/api/evidence?${params.toString()}`);
      if (!res.ok) {
        throw new Error(`Failed to fetch evidence: ${res.statusText}`);
      }
      const data: EvidenceRecord[] = await res.json();
      setEvidence(data);
    } catch (err: any) {
      setError(err?.message || "Failed to load evidence records");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvidence();
  }, [projectId, levelFilter, assetIdFilter, scanIdFilter]);

  // Evidence level badge helper (E0-E5 colored)
  const renderEvidenceLevelBadge = (level: string) => {
    const lvl = (level || "E2").toUpperCase();
    let colorClass = "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
    if (lvl === "E1") colorClass = "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
    else if (lvl === "E2") colorClass = "bg-cyan-500/10 text-cyan-400 border-cyan-500/20";
    else if (lvl === "E3") colorClass = "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
    else if (lvl === "E4") colorClass = "bg-blue-500/10 text-blue-400 border-blue-500/20";
    else if (lvl === "E5") colorClass = "bg-purple-500/10 text-purple-400 border-purple-500/20";

    return (
      <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold border ${colorClass}`}>
        {lvl}
      </span>
    );
  };

  // Evidence type pill helper
  const renderEvidenceTypePill = (type: string) => {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-subtle text-foreground border border-subtle">
        {type || "OBSERVATION"}
      </span>
    );
  };

  const clearAssetFilter = () => {
    setAssetIdFilter("");
    if (onClearAssetFilter) {
      onClearAssetFilter();
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Record Count */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-subtle pb-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <FileCheck2 className="h-5 w-5 text-cyan-400" />
            Canonical Evidence Explorer
          </h2>
          <p className="text-xs text-quiet mt-1">
            Normalized evidence observations with confidence levels (E0–E5), syntax snippets, and rule IDs.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchEvidence()}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-subtle bg-canvas/60 hover:bg-subtle text-xs text-quiet hover:text-foreground transition-colors disabled:opacity-50"
            title="Refresh evidence records"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <div className="font-mono text-xs text-cyan-400 bg-cyan-500/10 px-3 py-1.5 rounded-lg border border-cyan-500/20">
            {evidence.length} Records Ingested
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-3.5 rounded-xl border border-subtle bg-surface/70 backdrop-blur-sm space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          {/* Level Filter Dropdown */}
          <div className="flex items-center gap-2">
            <Filter className="h-3.5 w-3.5 text-quiet" />
            <span className="text-[11px] font-medium text-quiet uppercase tracking-wider">Level:</span>
            <select
              value={levelFilter}
              onChange={(e) => setLevelFilter(e.target.value)}
              className="text-xs font-mono bg-canvas border border-subtle rounded-lg px-2.5 py-1.5 text-foreground focus:outline-none focus:border-cyan-500 transition-colors"
            >
              <option value="All">All Levels (E0-E5)</option>
              <option value="E0">E0 - Pure Inferred</option>
              <option value="E1">E1 - Surface Clue</option>
              <option value="E2">E2 - Syntactic Pattern</option>
              <option value="E3">E3 - Actual API Use</option>
              <option value="E4">E4 - Verified Execution</option>
              <option value="E5">E5 - Live Traffic</option>
            </select>
          </div>

          {/* Asset ID Active Filter Tag */}
          {assetIdFilter && (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-mono text-xs">
              <span>Asset:</span>
              <span className="font-semibold">{assetIdFilter.slice(0, 12)}...</span>
              <button
                onClick={clearAssetFilter}
                className="hover:text-white p-0.5 rounded hover:bg-cyan-500/20 transition-colors ml-1"
                title="Clear Asset ID filter"
              >
                <X className="h-3 w-3" />
              </button>
            </div>
          )}

          {/* Scan ID Active Filter Tag */}
          {scanIdFilter && (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-300 font-mono text-xs">
              <span>Scan:</span>
              <span className="font-semibold">{scanIdFilter.slice(0, 12)}...</span>
              <button
                onClick={() => setScanIdFilter("")}
                className="hover:text-white p-0.5 rounded hover:bg-purple-500/20 transition-colors ml-1"
                title="Clear Scan ID filter"
              >
                <X className="h-3 w-3" />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Loading & Error States */}
      {loading && evidence.length === 0 ? (
        <div className="rounded-xl border border-subtle bg-surface p-12 text-center text-quiet font-mono text-xs space-y-2">
          <RefreshCw className="h-6 w-6 animate-spin mx-auto text-cyan-400" />
          <p>Loading canonical evidence records from database...</p>
        </div>
      ) : error ? (
        <div className="rounded-xl border border-rose-500/20 bg-rose-500/5 p-8 text-center text-rose-400 text-xs font-mono">
          {error}
        </div>
      ) : evidence.length === 0 ? (
        <div className="rounded-xl border border-subtle bg-surface p-12 text-center space-y-3">
          <FileCheck2 className="h-8 w-8 text-quiet mx-auto" />
          <h3 className="font-semibold text-sm text-foreground">No Canonical Evidence Captured Yet</h3>
          <p className="text-xs text-quiet max-w-sm mx-auto">
            {assetIdFilter || scanIdFilter || levelFilter !== "All"
              ? "No evidence records match your active filters. Try clearing your filters."
              : "Execute a scan via Scan Studio (Source, Binary, Network, or Archive) to populate canonical evidence."}
          </p>
          <div className="flex justify-center gap-3 pt-2">
            {(assetIdFilter || scanIdFilter || levelFilter !== "All") && (
              <button
                onClick={() => {
                  setLevelFilter("All");
                  clearAssetFilter();
                  setScanIdFilter("");
                }}
                className="px-3 py-1.5 rounded-lg border border-subtle bg-canvas hover:bg-subtle text-xs text-foreground font-semibold transition-colors"
              >
                Clear All Filters
              </button>
            )}
            {onNavigateToStudio && (
              <button
                onClick={onNavigateToStudio}
                className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-colors"
              >
                Open Scan Studio
              </button>
            )}
          </div>
        </div>
      ) : (
        /* Evidence Rows */
        <div className="space-y-3">
          {evidence.map((rec) => {
            const hasSnippet = !!rec.snippet && rec.snippet.trim().length > 0;

            return (
              <div
                key={rec.id}
                className="rounded-xl border border-subtle bg-surface p-4 hover:border-cyan-500/30 transition-all space-y-3 font-mono text-xs"
              >
                {/* Top Row: Type Pill, Level Badge, Algorithm, Confidence, Timestamp */}
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-subtle pb-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    {renderEvidenceLevelBadge(rec.level)}
                    {renderEvidenceTypePill(rec.evidence_type)}
                    <span className="font-bold text-foreground text-sm">
                      {rec.algorithm || "UNKNOWN"}
                    </span>
                  </div>

                  <div className="flex items-center gap-4 text-quiet text-[11px]">
                    {/* Confidence value: just the number like "0.94" */}
                    <div className="flex items-center gap-1">
                      <Fingerprint className="h-3.5 w-3.5 text-cyan-400" />
                      <span>Conf:</span>
                      <span className="font-bold text-foreground font-mono">
                        {rec.confidence.toFixed(2)}
                      </span>
                    </div>

                    {/* Timestamp */}
                    <div className="flex items-center gap-1">
                      <Clock className="h-3.5 w-3.5 text-quiet" />
                      <span>{rec.timestamp ? new Date(rec.timestamp).toLocaleTimeString() : "N/A"}</span>
                    </div>
                  </div>
                </div>

                {/* Metadata Details: Location, Rule ID, Engine */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-quiet">
                  {/* Location (file:line for source, hex offset for binary, hostname for network) */}
                  <div className="flex items-center gap-1.5 truncate">
                    <MapPin className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                    <span className="text-quiet shrink-0">Location:</span>
                    <span className="font-semibold text-foreground truncate select-all">
                      {rec.location || "N/A"}
                    </span>
                  </div>

                  {/* Rule ID that triggered it */}
                  <div className="flex items-center gap-1.5 truncate">
                    <Terminal className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                    <span className="text-quiet shrink-0">Rule ID:</span>
                    <span className="font-semibold text-foreground truncate select-all">
                      {rec.rule_id || "RULE_UNASSIGNED"}
                    </span>
                  </div>
                </div>

                {/* Description if present */}
                {rec.description && (
                  <p className="text-[11px] text-quiet font-sans leading-relaxed">
                    {rec.description}
                  </p>
                )}

                {/* Quick Navigation Links */}
                <div className="flex flex-wrap items-center gap-4 pt-1 text-[11px] font-mono">
                  {rec.asset_id && onNavigateToAsset && (
                    <button
                      onClick={() => onNavigateToAsset(rec.asset_id!)}
                      className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 hover:underline cursor-pointer"
                    >
                      <span>→ View Asset</span>
                    </button>
                  )}
                  {rec.scan_id && onNavigateToAutoPatch && (
                    <button
                      onClick={() => onNavigateToAutoPatch(rec.scan_id)}
                      className="text-rose-400 hover:text-rose-300 flex items-center gap-1 hover:underline cursor-pointer"
                    >
                      <span>→ Patch This</span>
                    </button>
                  )}
                </div>

                {/* Source code snippet (if AST or regex or snippet present — monospace, syntax highlighted style) */}
                {hasSnippet && (
                  <div className="rounded-lg border border-subtle bg-canvas/80 overflow-hidden">
                    <div className="flex items-center justify-between px-3 py-1.5 border-b border-subtle bg-canvas/50 text-[10px] text-quiet">
                      <span className="flex items-center gap-1">
                        <Code2 className="h-3 w-3 text-cyan-400" />
                        Code Match Snippet
                      </span>
                      <span className="text-[9px] uppercase tracking-wider">{rec.source_engine || "AST/Regex"}</span>
                    </div>
                    <pre className="p-3 overflow-x-auto text-[11px] font-mono text-cyan-300 leading-relaxed">
                      <code>{rec.snippet}</code>
                    </pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
