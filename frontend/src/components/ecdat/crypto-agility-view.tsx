"use client";

import React, { useState, useEffect } from "react";
import {
  Gauge,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Layers,
  FileCode,
  Globe,
  Lock,
  Cpu,
  CheckCircle2,
} from "lucide-react";

interface CryptoAgilityViewProps {
  projectId: string;
  onNavigateToScan?: () => void;
}

interface AgilityDimension {
  name: string;
  state: "SUPPORTED" | "OBSERVED" | "PARTIALLY_OBSERVED" | "CONSTRAINED" | "UNKNOWN";
  desc: string;
  evidence_basis: string;
}

export function CryptoAgilityView({ projectId, onNavigateToScan }: CryptoAgilityViewProps) {
  const [dimensions, setDimensions] = useState<AgilityDimension[]>([]);
  const [overallScore, setOverallScore] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [totalAssets, setTotalAssets] = useState(0);
  const [totalScans, setTotalScans] = useState(0);

  const loadAgility = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/agility/assessment?project=${encodeURIComponent(projectId)}`);
      if (res.ok) {
        const data = await res.json();
        setDimensions(data.dimensions || []);
        setOverallScore(data.overall_score || 0);
        setTotalAssets(data.total_assets_evaluated || 0);
        setTotalScans(data.total_scans_evaluated || 0);
      }
    } catch (err) {
      console.error("Failed to load agility assessment:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAgility();
  }, [projectId]);

  const getStateBadge = (state: string) => {
    switch (state) {
      case "SUPPORTED":
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
      case "OBSERVED":
        return "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";
      case "PARTIALLY_OBSERVED":
        return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
      case "CONSTRAINED":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      default:
        return "bg-gray-500/10 text-gray-400 border-gray-500/30";
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="rounded-xl border border-cyan-500/30 bg-gradient-to-r from-cyan-950/30 via-surface to-canvas p-6 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-cyan-400 font-bold text-base">
            <Gauge className="h-5 w-5" />
            <span>7-Dimensional Evidence-Based Crypto Agility Assessment</span>
          </div>

          <button
            onClick={loadAgility}
            disabled={loading}
            className="px-3 py-1.5 rounded-lg bg-surface border border-subtle text-xs font-semibold flex items-center gap-1.5 text-foreground hover:bg-canvas transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>Refresh Assessment</span>
          </button>
        </div>

        <p className="text-xs text-quiet max-w-3xl leading-relaxed">
          Evaluates polymorphic agility across 7 operational vectors. All classifications are
          derived directly from cryptographic evidence discovered in project scans, not static rules.
        </p>

        {/* Score Meter */}
        <div className="pt-2 flex items-center gap-4">
          <div className="flex items-baseline gap-1.5">
            <span className="text-3xl font-black font-mono text-cyan-400">{overallScore}</span>
            <span className="text-xs text-quiet font-mono">/ 10.0</span>
          </div>
          <div className="text-xs text-quiet">
            Overall Crypto-Agility Index · Evaluated across {totalAssets} assets and {totalScans} discovery scans
          </div>
        </div>
      </div>

      {/* 7 Dimension Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {dimensions.map((dim) => (
          <div
            key={dim.name}
            className="rounded-xl border border-subtle bg-surface p-5 space-y-3 flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="font-bold text-xs text-foreground">{dim.name}</span>
                <span
                  className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${getStateBadge(
                    dim.state
                  )}`}
                >
                  {dim.state}
                </span>
              </div>
              <p className="text-xs text-quiet leading-relaxed">{dim.desc}</p>
            </div>

            {/* Evidence Basis Box */}
            <div className="p-3 rounded-lg bg-canvas border border-subtle space-y-1">
              <span className="text-[10px] font-bold text-quiet uppercase tracking-wider block">
                Evidence Basis:
              </span>
              <p className="text-xs font-mono text-cyan-300/90 leading-relaxed">
                {dim.evidence_basis}
              </p>
            </div>
          </div>
        ))}
      </div>

      {/* Empty State Callout if zero evidence */}
      {dimensions.every((d) => d.state === "UNKNOWN") && onNavigateToScan && (
        <div className="p-6 rounded-xl border border-dashed border-subtle bg-surface text-center space-y-3">
          <AlertTriangle className="h-6 w-6 text-amber-400 mx-auto" />
          <h4 className="text-sm font-bold text-foreground">Insufficient Cryptographic Evidence</h4>
          <p className="text-xs text-quiet max-w-md mx-auto">
            No active discovery scans or cryptographic assets found in this project. Run source AST,
            TLS network, or binary scans to populate evidence-based agility metrics.
          </p>
          <button
            onClick={onNavigateToScan}
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-bold text-xs inline-flex items-center gap-1.5"
          >
            Go to Scan Studio
          </button>
        </div>
      )}
    </div>
  );
}
