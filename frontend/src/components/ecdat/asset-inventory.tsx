"use client";

import React, { useEffect, useState } from "react";
import {
  Code,
  Binary,
  Globe,
  FileCheck2,
  Archive,
  Layers,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  GitGraph,
  ShieldAlert,
  Zap,
  Info,
  RefreshCw,
} from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";

export interface AssetRecord {
  id: string;
  project: string;
  asset_type?: string;
  name: string;
  scan_id?: string;
  algorithm?: string;
  variant?: string | null;
  key_size?: number | null;
  library?: string | null;
  version?: string | null;
  status?: string;
  fused_status?: string;
  highest_evidence_level?: string;
  confidence?: number;
  explanation?: string;
  created_at?: string;
  updated_at?: string;
  risk_level: "CRITICAL" | "AT_RISK" | "SAFE" | "UNKNOWN";
  surface: "source" | "binary" | "network" | "certificate" | "archive";
  algorithm_family: "RSA" | "ECC" | "AES" | "SHA" | "Other";
  mosca_score: number;
  mosca_analysis?: {
    algorithm: string;
    key_size?: number | null;
    x_sensitivity_years: number;
    y_migration_years: number;
    z_threat_horizon_years: number;
    quantum_deficit_years: number;
    harvest_now_risk: boolean;
    risk_level: string;
    risk_score: number;
    explanation: string;
    recommendation: string;
    literature_reference: string;
  };
  pqc_recommendation?: {
    standard: string;
    recommended_primitive: string;
    migration_action: string;
    urgency: string;
  };
}

interface AssetInventoryProps {
  projectId: string;
  onNavigateToEvidence?: (assetId: string) => void;
  onNavigateToGraph?: (assetId: string) => void;
  onNavigateToStudio?: () => void;
  onPatchAsset?: (asset: AssetRecord) => void;
}

export function AssetInventory({
  projectId,
  onNavigateToEvidence,
  onNavigateToGraph,
  onNavigateToStudio,
  onPatchAsset,
}: AssetInventoryProps) {
  const [assets, setAssets] = useState<AssetRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filter state (Dropdowns, not search)
  const [riskFilter, setRiskFilter] = useState<string>("All");
  const [surfaceFilter, setSurfaceFilter] = useState<string>("All");
  const [familyFilter, setFamilyFilter] = useState<string>("All");

  // Pagination state
  const [page, setPage] = useState<number>(1);
  const perPage = 50;
  const [totalCount, setTotalCount] = useState<number>(0);

  // Selected asset for detail drawer
  const [selectedAsset, setSelectedAsset] = useState<AssetRecord | null>(null);
  const [isDrawerOpen, setIsDrawerOpen] = useState(false);

  const fetchAssets = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        project: projectId,
        sort: "mosca_score",
        page: page.toString(),
        per_page: perPage.toString(),
      });
      if (riskFilter !== "All") params.set("risk_level", riskFilter);
      if (surfaceFilter !== "All") params.set("surface", surfaceFilter);
      if (familyFilter !== "All") params.set("algorithm_family", familyFilter);

      const res = await fetch(`/api/assets?${params.toString()}`);
      if (!res.ok) {
        throw new Error(`Failed to fetch assets: ${res.statusText}`);
      }
      const data: AssetRecord[] = await res.json();
      setAssets(data);

      const countHeader = res.headers.get("X-Total-Count");
      if (countHeader) {
        setTotalCount(parseInt(countHeader, 10));
      } else {
        setTotalCount(data.length);
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load cryptographic assets");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, [projectId, page, riskFilter, surfaceFilter, familyFilter]);

  // Surface icon helper
  const renderSurfaceIcon = (surface: string) => {
    switch (surface?.toLowerCase()) {
      case "source":
        return <span title="Source Code"><Code className="h-4 w-4 text-sky-400" /></span>;
      case "binary":
        return <span title="Compiled Binary"><Binary className="h-4 w-4 text-purple-400" /></span>;
      case "network":
        return <span title="Network Endpoint / TLS"><Globe className="h-4 w-4 text-emerald-400" /></span>;
      case "certificate":
        return <span title="X.509 Certificate"><FileCheck2 className="h-4 w-4 text-amber-400" /></span>;
      case "archive":
        return <span title="Cryptographic Archive"><Archive className="h-4 w-4 text-orange-400" /></span>;
      default:
        return <Code className="h-4 w-4 text-quiet" />;
    }
  };

  // Risk badge helper
  const renderRiskBadge = (level: string) => {
    switch (level) {
      case "CRITICAL":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <span className="h-1.5 w-1.5 rounded-full bg-rose-500 animate-pulse" />
            CRITICAL
          </span>
        );
      case "AT_RISK":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
            AT RISK
          </span>
        );
      case "SAFE":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
            SAFE
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
            UNKNOWN
          </span>
        );
    }
  };

  // Evidence level pill helper
  const renderEvidenceLevelBadge = (level?: string) => {
    const lvl = (level || "E2").toUpperCase();
    let colorClass = "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
    if (lvl === "E1") colorClass = "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
    else if (lvl === "E2") colorClass = "bg-cyan-500/10 text-cyan-400 border-cyan-500/20";
    else if (lvl === "E3") colorClass = "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
    else if (lvl === "E4") colorClass = "bg-blue-500/10 text-blue-400 border-blue-500/20";
    else if (lvl === "E5") colorClass = "bg-purple-500/10 text-purple-400 border-purple-500/20";

    return (
      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${colorClass}`}>
        {lvl}
      </span>
    );
  };

  // Mosca score color
  const getMoscaScoreColor = (score: number) => {
    if (score >= 65) return "text-rose-400 font-bold";
    if (score >= 35) return "text-amber-400 font-bold";
    if (score > 0) return "text-cyan-400 font-semibold";
    return "text-emerald-400 font-semibold";
  };

  const handleRowClick = (asset: AssetRecord) => {
    setSelectedAsset(asset);
    setIsDrawerOpen(true);
  };

  const totalPages = Math.max(1, Math.ceil(totalCount / perPage));

  return (
    <div className="space-y-6">
      {/* Header & Stats */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-subtle pb-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
            <Layers className="h-5 w-5 text-cyan-400" />
            Cryptographic Asset Inventory
          </h2>
          <p className="text-xs text-quiet mt-1">
            Live catalog of cryptographic primitives, certificates, and algorithms with Mosca theorem risk scoring.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchAssets()}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-subtle bg-canvas/60 hover:bg-subtle text-xs text-quiet hover:text-foreground transition-colors disabled:opacity-50"
            title="Refresh asset inventory"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <div className="font-mono text-xs text-cyan-400 bg-cyan-500/10 px-3 py-1.5 rounded-lg border border-cyan-500/20">
            {totalCount} Total Assets
          </div>
        </div>
      </div>

      {/* Filter Bar (Dropdowns, not search) */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3.5 rounded-xl border border-subtle bg-surface/70 backdrop-blur-sm">
        {/* Risk Level Filter */}
        <div className="space-y-1">
          <label className="text-[11px] font-medium text-quiet uppercase tracking-wider">
            Risk Level
          </label>
          <select
            value={riskFilter}
            onChange={(e) => {
              setRiskFilter(e.target.value);
              setPage(1);
            }}
            className="w-full text-xs font-mono bg-canvas border border-subtle rounded-lg px-3 py-2 text-foreground focus:outline-none focus:border-cyan-500 transition-colors"
          >
            <option value="All">All Risk Levels</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="AT_RISK">AT_RISK</option>
            <option value="SAFE">SAFE</option>
            <option value="UNKNOWN">UNKNOWN</option>
          </select>
        </div>

        {/* Surface Filter */}
        <div className="space-y-1">
          <label className="text-[11px] font-medium text-quiet uppercase tracking-wider">
            Discovery Surface
          </label>
          <select
            value={surfaceFilter}
            onChange={(e) => {
              setSurfaceFilter(e.target.value);
              setPage(1);
            }}
            className="w-full text-xs font-mono bg-canvas border border-subtle rounded-lg px-3 py-2 text-foreground focus:outline-none focus:border-cyan-500 transition-colors"
          >
            <option value="All">All Surfaces</option>
            <option value="source">source (Code)</option>
            <option value="binary">binary (Compiled)</option>
            <option value="network">network (TLS/Protocol)</option>
            <option value="certificate">certificate (X.509)</option>
            <option value="archive">archive (Storage)</option>
          </select>
        </div>

        {/* Algorithm Family Filter */}
        <div className="space-y-1">
          <label className="text-[11px] font-medium text-quiet uppercase tracking-wider">
            Algorithm Family
          </label>
          <select
            value={familyFilter}
            onChange={(e) => {
              setFamilyFilter(e.target.value);
              setPage(1);
            }}
            className="w-full text-xs font-mono bg-canvas border border-subtle rounded-lg px-3 py-2 text-foreground focus:outline-none focus:border-cyan-500 transition-colors"
          >
            <option value="All">All Algorithm Families</option>
            <option value="RSA">RSA (Asymmetric)</option>
            <option value="ECC">ECC (Elliptic Curve)</option>
            <option value="AES">AES (Symmetric)</option>
            <option value="SHA">SHA (Hash)</option>
            <option value="Other">Other / Post-Quantum</option>
          </select>
        </div>
      </div>

      {/* Asset Table */}
      {loading && assets.length === 0 ? (
        <div className="rounded-xl border border-subtle bg-surface p-12 text-center text-quiet font-mono text-xs space-y-2">
          <RefreshCw className="h-6 w-6 animate-spin mx-auto text-cyan-400" />
          <p>Querying real cryptographic assets from database...</p>
        </div>
      ) : error ? (
        <div className="rounded-xl border border-rose-500/20 bg-rose-500/5 p-8 text-center text-rose-400 text-xs font-mono">
          {error}
        </div>
      ) : assets.length === 0 ? (
        <div className="rounded-xl border border-subtle bg-surface p-12 text-center space-y-3">
          <Layers className="h-8 w-8 text-quiet mx-auto" />
          <h3 className="font-semibold text-sm text-foreground">No Matching Cryptographic Assets</h3>
          <p className="text-xs text-quiet max-w-sm mx-auto">
            {riskFilter !== "All" || surfaceFilter !== "All" || familyFilter !== "All"
              ? "No assets match your active filter parameters. Try clearing your filters."
              : "Launch a discovery scan in Scan Studio to detect algorithms, keys, and certificates."}
          </p>
          {onNavigateToStudio && (
            <button
              onClick={onNavigateToStudio}
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-colors"
            >
              Open Scan Studio
            </button>
          )}
        </div>
      ) : (
        <div className="rounded-xl border border-subtle bg-surface overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-canvas/60 border-b border-subtle text-quiet uppercase text-[10px] font-bold font-mono tracking-wider">
                <tr>
                  <th className="p-3 w-10 text-center">Surface</th>
                  <th className="p-3">Algorithm & Key Size</th>
                  <th className="p-3">Risk Level</th>
                  <th className="p-3">Evidence</th>
                  <th className="p-3">Confidence</th>
                  <th className="p-3">Mosca Score</th>
                  <th className="p-3 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-subtle font-mono text-[11px]">
                {assets.map((a) => {
                  const algoLabel = a.algorithm || a.name || "UNKNOWN";
                  const keySizeLabel = a.key_size ? `-${a.key_size}` : "";
                  const pillText = `${algoLabel}${!algoLabel.includes(String(a.key_size || "")) ? keySizeLabel : ""}`;
                  const confidencePct = Math.round((a.confidence ?? 0.9) * 100);

                  return (
                    <tr
                      key={a.id}
                      onClick={() => handleRowClick(a)}
                      className="hover:bg-cyan-500/5 cursor-pointer transition-colors group"
                    >
                      {/* Surface Icon */}
                      <td className="p-3 text-center">
                        <div className="flex items-center justify-center p-1.5 rounded-lg bg-canvas/80 border border-subtle">
                          {renderSurfaceIcon(a.surface)}
                        </div>
                      </td>

                      {/* Algorithm + Key size pill */}
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <span className="px-2.5 py-1 rounded-md bg-canvas border border-subtle font-bold text-foreground group-hover:border-cyan-500/40 transition-colors">
                            {pillText}
                          </span>
                          <span className="text-[10px] text-quiet">
                            {a.asset_type || "PRIMITIVE"}
                          </span>
                        </div>
                      </td>

                      {/* Risk badge */}
                      <td className="p-3">{renderRiskBadge(a.risk_level)}</td>

                      {/* Evidence Level Badge */}
                      <td className="p-3">{renderEvidenceLevelBadge(a.highest_evidence_level)}</td>

                      {/* Confidence bar: thin <progress> element 0-100% */}
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <progress
                            value={confidencePct}
                            max={100}
                            className="w-16 h-1.5 rounded-full overflow-hidden bg-canvas border border-subtle [&::-webkit-progress-bar]:bg-canvas [&::-webkit-progress-value]:bg-cyan-400 [&::-moz-progress-bar]:bg-cyan-400"
                          />
                          <span className="text-quiet text-[10px]">{confidencePct}%</span>
                        </div>
                      </td>

                      {/* Mosca score: number colored by verdict */}
                      <td className="p-3">
                        <span className={`text-xs ${getMoscaScoreColor(a.mosca_score)}`}>
                          {a.mosca_score.toFixed(1)}
                        </span>
                      </td>

                      {/* Action */}
                      <td className="p-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleRowClick(a);
                          }}
                          className="px-2 py-1 rounded text-[10px] bg-subtle hover:bg-cyan-500/20 text-quiet hover:text-cyan-300 transition-colors"
                        >
                          View Drawer →
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          <div className="flex items-center justify-between px-4 py-3 border-t border-subtle bg-canvas/40 text-xs font-mono">
            <div className="text-quiet text-[11px]">
              Showing {assets.length > 0 ? (page - 1) * perPage + 1 : 0} to{" "}
              {Math.min(page * perPage, totalCount)} of {totalCount} assets
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1 || loading}
                className="px-2.5 py-1 rounded border border-subtle bg-canvas hover:bg-subtle text-quiet hover:text-foreground disabled:opacity-40 transition-colors"
              >
                <ChevronLeft className="h-3.5 w-3.5 inline mr-1" />
                Previous
              </button>
              <span className="text-quiet px-2">
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages || loading}
                className="px-2.5 py-1 rounded border border-subtle bg-canvas hover:bg-subtle text-quiet hover:text-foreground disabled:opacity-40 transition-colors"
              >
                Next
                <ChevronRight className="h-3.5 w-3.5 inline ml-1" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Asset Detail Drawer (Sheet Component) */}
      <Sheet open={isDrawerOpen} onOpenChange={setIsDrawerOpen}>
        <SheetContent side="right" className="w-full sm:max-w-lg overflow-y-auto bg-surface border-l border-subtle p-6 space-y-6">
          {selectedAsset && (
            <>
              <SheetHeader className="p-0 border-b border-subtle pb-4">
                <div className="flex items-center justify-between gap-2">
                  {renderRiskBadge(selectedAsset.risk_level)}
                  <span className="text-[10px] font-mono text-quiet">{selectedAsset.id.slice(0, 16)}...</span>
                </div>
                <SheetTitle className="text-lg font-bold text-foreground mt-2 flex items-center gap-2">
                  {selectedAsset.algorithm || selectedAsset.name}
                  {selectedAsset.key_size ? ` (${selectedAsset.key_size} bit)` : ""}
                </SheetTitle>
                <SheetDescription className="text-xs text-quiet mt-1 font-mono">
                  Asset Type: {selectedAsset.asset_type || "ALGORITHM"} | Surface: {selectedAsset.surface}
                </SheetDescription>
              </SheetHeader>

              {/* Action Buttons */}
              <div className="grid grid-cols-2 gap-2 pt-1">
                {onPatchAsset && (
                  <button
                    onClick={() => {
                      setIsDrawerOpen(false);
                      onPatchAsset(selectedAsset);
                    }}
                    className="col-span-2 flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 text-xs font-semibold border border-rose-500/40 shadow-sm transition-colors cursor-pointer"
                  >
                    <Zap className="h-3.5 w-3.5 text-rose-400" />
                    Patch This Asset (Auto Patch Engine)
                  </button>
                )}
                <button
                  onClick={() => {
                    setIsDrawerOpen(false);
                    if (onNavigateToEvidence) {
                      onNavigateToEvidence(selectedAsset.id);
                    }
                  }}
                  className="flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-sm transition-colors"
                >
                  <ExternalLink className="h-3.5 w-3.5" />
                  View Evidence Records
                </button>
                <button
                  onClick={() => {
                    setIsDrawerOpen(false);
                    if (onNavigateToGraph) {
                      onNavigateToGraph(selectedAsset.id);
                    }
                  }}
                  className="flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-subtle hover:bg-canvas text-foreground text-xs font-semibold border border-subtle transition-colors"
                >
                  <GitGraph className="h-3.5 w-3.5 text-cyan-400" />
                  View in Graph
                </button>
              </div>

              {/* Mosca Analysis Panel */}
              <div className="rounded-xl border border-subtle bg-canvas/70 p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-subtle pb-2">
                  <span className="text-xs font-bold text-foreground flex items-center gap-1.5">
                    <ShieldAlert className="h-4 w-4 text-amber-400" />
                    Mosca Theorem Assessment (X + Y &gt; Z)
                  </span>
                  <span className={`text-xs font-mono ${getMoscaScoreColor(selectedAsset.mosca_score)}`}>
                    Score: {selectedAsset.mosca_score.toFixed(1)} / 100
                  </span>
                </div>

                {selectedAsset.mosca_analysis && (
                  <div className="space-y-2 text-xs font-mono">
                    <div className="grid grid-cols-3 gap-2 text-center py-2 bg-surface rounded-lg border border-subtle">
                      <div>
                        <div className="text-[10px] text-quiet">X (Sensitivity)</div>
                        <div className="font-bold text-foreground">
                          {selectedAsset.mosca_analysis.x_sensitivity_years} yrs
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] text-quiet">Y (Migration)</div>
                        <div className="font-bold text-foreground">
                          {selectedAsset.mosca_analysis.y_migration_years} yrs
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] text-quiet">Z (CRQC Arrival)</div>
                        <div className="font-bold text-foreground">
                          {selectedAsset.mosca_analysis.z_threat_horizon_years} yrs
                        </div>
                      </div>
                    </div>

                    <div className="flex justify-between items-center py-1 border-b border-subtle/50 text-[11px]">
                      <span className="text-quiet">Quantum Deficit:</span>
                      <span
                        className={
                          selectedAsset.mosca_analysis.quantum_deficit_years > 0
                            ? "text-rose-400 font-bold"
                            : "text-emerald-400 font-bold"
                        }
                      >
                        {selectedAsset.mosca_analysis.quantum_deficit_years > 0 ? "+" : ""}
                        {selectedAsset.mosca_analysis.quantum_deficit_years} years
                      </span>
                    </div>

                    <div className="flex justify-between items-center py-1 border-b border-subtle/50 text-[11px]">
                      <span className="text-quiet">Harvest Now, Decrypt Later:</span>
                      <span
                        className={
                          selectedAsset.mosca_analysis.harvest_now_risk
                            ? "text-rose-400 font-bold"
                            : "text-emerald-400 font-bold"
                        }
                      >
                        {selectedAsset.mosca_analysis.harvest_now_risk ? "CRITICAL EXPOSURE" : "SAFE"}
                      </span>
                    </div>

                    <p className="text-[11px] text-quiet leading-relaxed pt-1">
                      {selectedAsset.mosca_analysis.explanation}
                    </p>

                    <div className="text-[10px] text-quiet/70 italic">
                      Ref: {selectedAsset.mosca_analysis.literature_reference}
                    </div>
                  </div>
                )}
              </div>

              {/* PQC Replacement Recommendation */}
              <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4 space-y-2.5">
                <div className="flex items-center gap-1.5 text-xs font-bold text-cyan-300">
                  <Zap className="h-4 w-4 text-cyan-400" />
                  Canonical PQC Recommendation (Knowledge Base)
                </div>

                {selectedAsset.pqc_recommendation ? (
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between items-center font-mono text-[11px]">
                      <span className="text-quiet">Standard:</span>
                      <span className="text-foreground font-semibold">
                        {selectedAsset.pqc_recommendation.standard}
                      </span>
                    </div>
                    <div className="flex justify-between items-center font-mono text-[11px]">
                      <span className="text-quiet">Target Primitive:</span>
                      <span className="text-cyan-400 font-bold">
                        {selectedAsset.pqc_recommendation.recommended_primitive}
                      </span>
                    </div>
                    <div className="flex justify-between items-center font-mono text-[11px]">
                      <span className="text-quiet">Migration Urgency:</span>
                      <span className="text-amber-400 font-semibold">
                        {selectedAsset.pqc_recommendation.urgency}
                      </span>
                    </div>
                    <p className="text-[11px] text-quiet bg-canvas/50 p-2.5 rounded-lg border border-subtle leading-relaxed">
                      {selectedAsset.pqc_recommendation.migration_action}
                    </p>
                  </div>
                ) : (
                  <p className="text-xs text-quiet">
                    Standard Post-Quantum migration recommendations available under NIST SP 800-227.
                  </p>
                )}
              </div>

              {/* All Asset Fields Table */}
              <div className="rounded-xl border border-subtle bg-canvas/40 p-4 space-y-2">
                <div className="text-xs font-bold text-foreground flex items-center gap-1.5 mb-2">
                  <Info className="h-4 w-4 text-quiet" />
                  Raw Asset Metadata
                </div>
                <div className="divide-y divide-subtle font-mono text-[11px]">
                  <div className="flex justify-between py-1.5">
                    <span className="text-quiet">Asset ID:</span>
                    <span className="text-foreground select-all">{selectedAsset.id}</span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="text-quiet">Algorithm:</span>
                    <span className="text-foreground">{selectedAsset.algorithm || selectedAsset.name}</span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="text-quiet">Key Size:</span>
                    <span className="text-foreground">{selectedAsset.key_size ? `${selectedAsset.key_size} bits` : "N/A"}</span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="text-quiet">Surface:</span>
                    <span className="text-foreground uppercase">{selectedAsset.surface}</span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="text-quiet">Evidence Level:</span>
                    <span className="text-foreground font-bold">{selectedAsset.highest_evidence_level || "E2"}</span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="text-quiet">Status:</span>
                    <span className="text-cyan-400">{selectedAsset.status || "ACTIVE"}</span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="text-quiet">Fused Status:</span>
                    <span className="text-foreground">{selectedAsset.fused_status || "SINGLE_SOURCE"}</span>
                  </div>
                  <div className="flex justify-between py-1.5">
                    <span className="text-quiet">Confidence:</span>
                    <span className="text-foreground">{((selectedAsset.confidence || 0.9) * 100).toFixed(0)}%</span>
                  </div>
                  {selectedAsset.scan_id && (
                    <div className="flex justify-between py-1.5">
                      <span className="text-quiet">Scan ID:</span>
                      <span className="text-foreground truncate max-w-[200px]">{selectedAsset.scan_id}</span>
                    </div>
                  )}
                  {selectedAsset.created_at && (
                    <div className="flex justify-between py-1.5">
                      <span className="text-quiet">Ingested At:</span>
                      <span className="text-foreground">{new Date(selectedAsset.created_at).toLocaleString()}</span>
                    </div>
                  )}
                </div>

                {selectedAsset.explanation && (
                  <div className="pt-2 text-[11px] text-quiet border-t border-subtle">
                    <div className="font-semibold text-foreground mb-1">Observation Details:</div>
                    <div className="bg-canvas p-2.5 rounded border border-subtle whitespace-pre-wrap leading-relaxed">
                      {selectedAsset.explanation}
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
