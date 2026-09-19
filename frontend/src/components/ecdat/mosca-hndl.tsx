"use client";

import React, { useEffect, useRef, useState } from "react";
import {
  Hourglass,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  BookOpen,
  Zap,
  Sliders,
  CheckCircle2,
  Clock,
} from "lucide-react";
import { Slider } from "@/components/ui/slider";
import { EmptyState } from "@/components/ui/empty-state";

export interface MoscaResult {
  algorithm: string;
  key_size: number | null;
  x_sensitivity_years: number;
  y_migration_years: number;
  z_threat_horizon_years: number;
  quantum_deficit_years: number;
  harvest_now_risk: boolean;
  risk_level: "CRITICAL" | "HIGH" | "AT_RISK" | "MEDIUM" | "LOW" | "SAFE" | string;
  risk_score: number;
  explanation: string;
  recommendation: string;
  literature_reference: string;
  asset_count: number;
}

interface MoscaHndlProps {
  projectId: string;
  onNavigateToStudio?: () => void;
  onNavigateToMigration?: (algorithm?: string) => void;
  onNavigateToPatch?: (algorithm?: string) => void;
}

export function MoscaHndl({
  projectId,
  onNavigateToStudio,
  onNavigateToMigration,
  onNavigateToPatch,
}: MoscaHndlProps) {
  // Slider 1: Data Sensitivity (X years) range 1-50, default 10
  const [xYears, setXYears] = useState<number>(10);

  // Slider 2: Quantum Threat Horizon (Z override) range 5-20, default null
  const [overrideZ, setOverrideZ] = useState<boolean>(false);
  const [zOverrideYears, setZOverrideYears] = useState<number>(10);

  const [results, setResults] = useState<MoscaResult[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [message, setMessage] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  // Debounced API fetch
  const isFirstMount = useRef(true);

  async function fetchMoscaScan(x: number, override: boolean, z: number) {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/quantum/mosca-project-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project_id: projectId,
          data_sensitivity_years: x,
          migration_time_years: 3.0,
          crqc_horizon_override: override ? z : null,
        }),
      });

      if (!res.ok) {
        throw new Error(`Failed to calculate Mosca risk: ${res.status} ${res.statusText}`);
      }

      const data = await res.json();
      setResults(data.results || []);
      setMessage(data.message || "");
    } catch (err: any) {
      console.error("Mosca assessment error:", err);
      setError(err?.message || "Failed to contact quantum assessment engine.");
    } finally {
      setLoading(false);
    }
  }

  // Initial fetch on mount
  useEffect(() => {
    fetchMoscaScan(xYears, overrideZ, zOverrideYears);
    isFirstMount.current = false;
  }, [projectId]);

  // Debounced fetch on slider change (500ms)
  useEffect(() => {
    if (isFirstMount.current) return;
    const timer = setTimeout(() => {
      fetchMoscaScan(xYears, overrideZ, zOverrideYears);
    }, 500);

    return () => clearTimeout(timer);
  }, [xYears, overrideZ, zOverrideYears]);

  const hndlExposed = results.filter((r) => r.harvest_now_risk);
  const maxZ = Math.max(30, ...results.map((r) => Math.max(r.z_threat_horizon_years, r.x_sensitivity_years + r.y_migration_years)));

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="border-b border-subtle pb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold tracking-tight text-foreground">
              Mosca&apos;s Theorem &amp; HNDL Exposure
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-semibold">
              X + Y &gt; Z
            </span>
          </div>
          <p className="text-xs text-quiet mt-1 max-w-3xl">
            Mathematical evaluation of post-quantum vulnerability horizons. When data confidentiality lifetime ($X$)
            plus migration lead time ($Y$) exceeds the Cryptanalytically Relevant Quantum Computer arrival ($Z$),
            adversaries intercepting ciphertext today can decrypt retroactively upon CRQC realization (Harvest Now, Decrypt Later).
          </p>
        </div>

        <button
          onClick={() => fetchMoscaScan(xYears, overrideZ, zOverrideYears)}
          disabled={loading}
          className="self-start sm:self-auto px-3 py-1.5 text-xs rounded-lg border border-subtle bg-surface hover:bg-canvas text-foreground flex items-center gap-1.5 transition-colors disabled:opacity-50"
        >
          <RefreshCw size={13} className={loading ? "animate-spin text-cyan-400" : "text-quiet"} />
          <span>Recalculate</span>
        </button>
      </div>

      {/* Sliders Control Deck */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Slider 1: Data Sensitivity (X years) */}
        <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                <Sliders size={14} className="text-cyan-400" />
                Data Sensitivity (X years)
              </span>
              <p className="text-[11px] text-quiet">Required shelf-life confidentiality duration</p>
            </div>
            <span className="font-mono text-base font-bold text-cyan-400 bg-cyan-500/10 px-2.5 py-0.5 rounded border border-cyan-500/20">
              {xYears}y
            </span>
          </div>

          <div className="pt-2">
            <Slider
              value={[xYears]}
              onValueChange={(val) => {
                const num = Array.isArray(val) ? val[0] : val;
                if (typeof num === "number") setXYears(num);
              }}
              min={1}
              max={50}
              step={1}
            />
          </div>

          <div className="flex justify-between text-[10px] font-mono text-quiet">
            <span>1 Year (Ephemeral)</span>
            <span>10y (Default / Financial)</span>
            <span>25y (Healthcare)</span>
            <span>50y (Classified)</span>
          </div>
        </div>

        {/* Slider 2: Quantum Threat Horizon (Z override) */}
        <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                  <Clock size={14} className="text-cyan-400" />
                  Quantum Threat Horizon (Z override)
                </span>
                <label className="flex items-center gap-1.5 cursor-pointer text-[11px] text-quiet select-none">
                  <input
                    type="checkbox"
                    checked={overrideZ}
                    onChange={(e) => setOverrideZ(e.target.checked)}
                    className="rounded border-subtle bg-canvas accent-cyan-500 h-3.5 w-3.5"
                  />
                  <span>Override literature Z</span>
                </label>
              </div>
              <p className="text-[11px] text-quiet">
                {overrideZ
                  ? "Manual fixed CRQC threat horizon applied to all primitives"
                  : "Per-algorithm published literature standards (Gidney & Ekerå 2021; NIST IR 8547)"}
              </p>
            </div>

            <span
              className={`font-mono text-base font-bold px-2.5 py-0.5 rounded border ${
                overrideZ
                  ? "text-amber-400 bg-amber-500/10 border-amber-500/20"
                  : "text-quiet bg-subtle/30 border-subtle text-xs py-1"
              }`}
            >
              {overrideZ ? `${zOverrideYears}y (~${2026 + zOverrideYears})` : "Per-Algo (Auto)"}
            </span>
          </div>

          <div className={`pt-2 transition-opacity ${overrideZ ? "opacity-100" : "opacity-40 pointer-events-none"}`}>
            <Slider
              value={[zOverrideYears]}
              onValueChange={(val) => {
                const num = Array.isArray(val) ? val[0] : val;
                if (typeof num === "number") setZOverrideYears(num);
              }}
              min={5}
              max={20}
              step={1}
              disabled={!overrideZ}
            />
          </div>

          <div className="flex justify-between text-[10px] font-mono text-quiet">
            <span>5 Years (Aggressive)</span>
            <span>10y (NIST Horizon ~2035)</span>
            <span>20 Years (Conservative)</span>
          </div>
        </div>
      </div>

      {/* Loading state indicator */}
      {loading && (
        <div className="flex items-center justify-center gap-2 p-6 text-xs text-quiet border border-subtle rounded-xl bg-surface/30 animate-pulse">
          <RefreshCw size={14} className="animate-spin text-cyan-400" />
          <span>Evaluating cryptographic primitives across quantum cryptanalysis horizons...</span>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-300 text-xs flex items-center gap-3">
          <AlertTriangle size={16} className="text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Empty State */}
      {!loading && !error && results.length === 0 && (
        <EmptyState
          icon={<Hourglass className="h-6 w-6 text-cyan-400" />}
          title="No Cryptographic Assets Found"
          description="No cryptographic assets found. Run a discovery scan first."
          actionLabel="Launch Discovery Scan"
          onAction={onNavigateToStudio}
        />
      )}

      {/* Active Results */}
      {!loading && !error && results.length > 0 && (
        <div className="space-y-8">
          {/* Section 1: Per-Algorithm Timeline Rows */}
          <div className="space-y-4">
            <div className="flex items-center justify-between border-b border-subtle pb-2">
              <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
                <Hourglass size={15} className="text-cyan-400" />
                Per-Algorithm Quantum Timeline Breakdown
              </h3>
              <span className="text-xs text-quiet font-mono">
                {results.length} algorithm family{results.length === 1 ? "" : "ies"} assessed
              </span>
            </div>

            <div className="space-y-3">
              {results.map((r, idx) => {
                const totalReq = r.x_sensitivity_years + r.y_migration_years;
                const hasDeficit = r.quantum_deficit_years > 0;
                const deficitYears = r.quantum_deficit_years;

                const getRiskBadge = (level: string) => {
                  switch (level) {
                    case "CRITICAL":
                      return "bg-rose-500/15 border-rose-500/30 text-rose-400";
                    case "HIGH":
                    case "AT_RISK":
                      return "bg-amber-500/15 border-amber-500/30 text-amber-400";
                    case "MEDIUM":
                      return "bg-cyan-500/15 border-cyan-500/30 text-cyan-300";
                    default:
                      return "bg-emerald-500/15 border-emerald-500/30 text-emerald-400";
                  }
                };

                // Percentage bar calculations
                const totalReqPct = Math.min(100, Math.max(5, (totalReq / maxZ) * 100));
                const threatHorizonPct = Math.min(100, Math.max(5, (r.z_threat_horizon_years / maxZ) * 100));

                return (
                  <div
                    key={`${r.algorithm}-${r.key_size}-${idx}`}
                    className="rounded-xl border border-subtle bg-surface p-4 sm:p-5 space-y-4 hover:border-subtle/80 transition-colors"
                  >
                    {/* Row Header */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <span className="font-mono font-bold text-sm text-foreground">
                          {r.algorithm}
                        </span>
                        {r.key_size && (
                          <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-canvas border border-subtle text-quiet">
                            {r.key_size}-bit
                          </span>
                        )}
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                          {r.asset_count} asset{r.asset_count === 1 ? "" : "s"}
                        </span>
                      </div>

                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`text-[10px] font-mono font-bold px-2.5 py-1 rounded border uppercase ${getRiskBadge(
                            r.risk_level
                          )}`}
                        >
                          {r.risk_level === "CRITICAL"
                            ? "CRITICAL DEFICIT"
                            : r.risk_level === "AT_RISK"
                            ? "AT RISK"
                            : r.risk_level}
                        </span>

                        <span
                          className={`text-xs font-mono font-bold px-2.5 py-1 rounded border ${
                            hasDeficit
                              ? "bg-rose-500/10 border-rose-500/30 text-rose-300"
                              : "bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
                          }`}
                        >
                          {hasDeficit ? `+${deficitYears}y Deficit` : `${Math.abs(deficitYears)}y Safe Margin`}
                        </span>
                      </div>
                    </div>

                    {/* Mosca Timeline Visual Bar */}
                    <div className="space-y-1.5 pt-1">
                      <div className="flex justify-between text-[11px] font-mono text-quiet">
                        <span>
                          Protection Required: <strong className="text-foreground">{totalReq}y</strong> (X:{r.x_sensitivity_years}y + Y:{r.y_migration_years}y)
                        </span>
                        <span>
                          CRQC Horizon (Z): <strong className="text-foreground">{r.z_threat_horizon_years}y</strong> (~{2026 + Math.round(r.z_threat_horizon_years)})
                        </span>
                      </div>

                      {/* Bar Visualization */}
                      <div className="relative h-6 rounded-lg bg-canvas border border-subtle overflow-hidden flex items-center px-2">
                        {/* Threat Horizon Marker / Fill */}
                        <div
                          className="absolute left-0 top-0 bottom-0 bg-cyan-500/15 border-r-2 border-cyan-400"
                          style={{ width: `${threatHorizonPct}%` }}
                        />

                        {/* Required Protection Fill */}
                        <div
                          className={`absolute left-0 top-1 bottom-1 rounded opacity-75 ${
                            hasDeficit ? "bg-rose-500/40" : "bg-emerald-500/30"
                          }`}
                          style={{ width: `${totalReqPct}%` }}
                        />

                        {/* Deficit Segment Indicator */}
                        {hasDeficit && (
                          <div
                            className="absolute top-0 bottom-0 bg-rose-500/30 border-l border-rose-400"
                            style={{
                              left: `${threatHorizonPct}%`,
                              width: `${Math.max(4, totalReqPct - threatHorizonPct)}%`,
                            }}
                          />
                        )}

                        <span className="relative z-10 text-[10px] font-mono font-semibold text-foreground/90 select-none">
                          {hasDeficit
                            ? `Deficit: Interception vulnerability begins ${r.z_threat_horizon_years}y from now`
                            : `Secure: ${Math.abs(deficitYears)}y buffer available before CRQC exposure`}
                        </span>
                      </div>
                    </div>

                    {/* Explanation & Literature */}
                    <div className="space-y-2 text-xs">
                      <p className="text-foreground/90 leading-relaxed">{r.explanation}</p>
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-1 text-[11px] text-quiet border-t border-subtle/50">
                        <div className="flex items-center gap-1.5 text-cyan-400 font-medium">
                          <Zap size={12} className="shrink-0" />
                          <span>Recommendation: {r.recommendation}</span>
                        </div>
                        <div className="flex items-center gap-1 font-mono text-[10px] text-quiet/80 shrink-0">
                          <BookOpen size={11} />
                          <span>{r.literature_reference}</span>
                        </div>
                      </div>
                      {onNavigateToMigration && (
                        <div className="pt-2 flex justify-end">
                          <button
                            onClick={() => onNavigateToMigration(r.algorithm)}
                            className="text-[11px] px-3 py-1 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center gap-1.5 font-medium transition-colors cursor-pointer"
                          >
                            <span>→ Start Migration</span>
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Section 2: Harvest Now, Decrypt Later (HNDL) Threat Cards */}
          <div className="space-y-4 pt-4 border-t border-subtle">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
                  <ShieldAlert size={16} className="text-rose-400" />
                  Harvest Now, Decrypt Later (HNDL) Vulnerability Queue
                </h3>
                <p className="text-xs text-quiet mt-0.5">
                  Adversaries actively intercepting ciphertext streams today will store and retroactively decrypt them
                  prior to your required confidentiality shelf-life expiration.
                </p>
              </div>

              <span
                className={`text-xs font-mono font-bold px-2.5 py-1 rounded border ${
                  hndlExposed.length > 0
                    ? "bg-rose-500/10 border-rose-500/20 text-rose-400"
                    : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                }`}
              >
                {hndlExposed.length} Exposed Primitive{hndlExposed.length === 1 ? "" : "s"}
              </span>
            </div>

            {hndlExposed.length === 0 ? (
              <div className="rounded-xl border border-subtle bg-surface p-6 text-center space-y-2">
                <div className="h-10 w-10 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center mx-auto">
                  <ShieldCheck size={20} />
                </div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-foreground">
                  No Active HNDL Exposure Detected
                </h4>
                <p className="text-xs text-quiet max-w-md mx-auto">
                  All active confidentiality primitives in this project maintain sufficient quantum security margins under
                  the specified {xYears}-year data sensitivity horizon.
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {hndlExposed.map((h, i) => (
                  <div
                    key={`hndl-${h.algorithm}-${i}`}
                    className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-4 space-y-3 flex flex-col justify-between"
                  >
                    <div className="space-y-2">
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="font-mono font-bold text-sm text-foreground">{h.algorithm}</div>
                          <div className="text-[11px] text-quiet">
                            {h.asset_count} asset{h.asset_count === 1 ? "" : "s"} in project
                          </div>
                        </div>
                        <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                          +{h.quantum_deficit_years}y EXPOSED
                        </span>
                      </div>

                      <div className="p-2 rounded-lg bg-canvas/60 border border-rose-500/20 space-y-1 text-xs">
                        <div className="flex justify-between text-[11px]">
                          <span className="text-quiet">Threat Horizon (Z):</span>
                          <span className="font-mono font-bold text-rose-300">{h.z_threat_horizon_years}y (~{2026 + Math.round(h.z_threat_horizon_years)})</span>
                        </div>
                        <div className="flex justify-between text-[11px]">
                          <span className="text-quiet">Confidentiality Shelf-Life (X):</span>
                          <span className="font-mono text-cyan-400">{h.x_sensitivity_years}y</span>
                        </div>
                        <div className="flex justify-between text-[11px]">
                          <span className="text-quiet">Migration Lead Time (Y):</span>
                          <span className="font-mono text-foreground">{h.y_migration_years}y</span>
                        </div>
                      </div>

                      <p className="text-[11px] text-foreground/80 leading-relaxed">
                        Interception today guarantees decryption before shelf-life expires in {2026 + Math.round(h.x_sensitivity_years)}.
                      </p>
                    </div>

                    <div className="pt-2 border-t border-rose-500/20 space-y-2">
                      <div className="text-[11px] text-rose-300 flex items-start gap-1.5 font-medium">
                        <ArrowRight size={13} className="shrink-0 mt-0.5 text-rose-400" />
                        <span>{h.recommendation}</span>
                      </div>
                      {onNavigateToPatch && (
                        <button
                          onClick={() => onNavigateToPatch(h.algorithm)}
                          className="w-full text-xs py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 flex items-center justify-center gap-1.5 font-semibold transition-colors cursor-pointer"
                        >
                          <Zap size={13} />
                          <span>Patch Now</span>
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
