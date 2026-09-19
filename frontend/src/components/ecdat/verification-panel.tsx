"use client";

import { useState, useEffect } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  ArrowRight,
  RefreshCw,
  Clock,
  Layers,
  FileDiff,
  Loader2,
} from "lucide-react";
import { requestApi, Scan, VerificationReport } from "@/lib/api";

interface VerificationPanelProps {
  project: string;
  token: string;
}

export function VerificationPanel({ project, token }: VerificationPanelProps) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [baselineScanId, setBaselineScanId] = useState<string>("");
  const [postScanId, setPostScanId] = useState<string>("");
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingScans, setLoadingScans] = useState(false);

  useEffect(() => {
    loadScans();
  }, [project, token]);

  async function loadScans() {
    setLoadingScans(true);
    try {
      const res = await requestApi<Scan[]>("/scans", project, token);
      const completed = res.filter((s) => s.status === "completed");
      setScans(completed);
      if (completed.length >= 2) {
        setPostScanId(completed[0].id);
        setBaselineScanId(completed[1].id);
      } else if (completed.length === 1) {
        setBaselineScanId(completed[0].id);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingScans(false);
    }
  }

  async function handleVerify() {
    if (!baselineScanId || !postScanId) {
      alert("Select both a baseline scan and a post-migration scan.");
      return;
    }
    setLoading(true);
    try {
      const res = await requestApi<VerificationReport>(
        "/verify",
        project,
        token,
        {
          baseline_scan_ids: [baselineScanId],
          post_migration_scan_ids: [postScanId],
        }
      );
      setReport(res);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setLoading(false);
    }
  }

  function getVerdictBadge(verdict: string) {
    if (verdict === "VERIFIED") {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
          <CheckCircle2 size={14} /> Verified Complete
        </span>
      );
    }
    if (verdict === "NOT_VERIFIED") {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-rose-500/15 text-rose-400 border border-rose-500/30">
          <ShieldAlert size={14} /> Not Verified
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-amber-500/15 text-amber-400 border border-amber-500/30">
        <AlertTriangle size={14} /> Inconclusive
      </span>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-subtle pb-4">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <FileDiff className="text-cyan-400" size={22} />
            Closed-Loop Re-Scan Verification
          </h2>
          <p className="text-sm text-quiet">
            Section 10 Core Differentiator: ECDAT compares post-migration evidence directly against
            the baseline to prove that the deployed cryptographic posture actually changed.
          </p>
        </div>
      </div>

      {/* Selectors */}
      <div className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-xs font-semibold uppercase tracking-wider text-quiet mb-1 block">
              1. Baseline Scan (Before Migration)
            </label>
            <select
              value={baselineScanId}
              onChange={(e) => setBaselineScanId(e.target.value)}
              className="w-full rounded-md border border-subtle bg-canvas px-3 py-2 text-sm text-foreground"
            >
              <option value="">Select baseline scan...</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  [{s.kind.toUpperCase()}] {s.id.slice(0, 8)} - {s.created_at.slice(0, 16)}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-xs font-semibold uppercase tracking-wider text-quiet mb-1 block">
              2. Post-Migration Scan (After Remediating)
            </label>
            <select
              value={postScanId}
              onChange={(e) => setPostScanId(e.target.value)}
              className="w-full rounded-md border border-subtle bg-canvas px-3 py-2 text-sm text-foreground"
            >
              <option value="">Select post-migration scan...</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  [{s.kind.toUpperCase()}] {s.id.slice(0, 8)} - {s.created_at.slice(0, 16)}
                </option>
              ))}
            </select>
          </div>
        </div>

        <button
          onClick={handleVerify}
          disabled={loading || !baselineScanId || !postScanId}
          className="ec-button flex items-center gap-2"
        >
          {loading ? <Loader2 className="animate-spin" size={16} /> : <FileDiff size={16} />}
          Compare Evidence & Verify Migration
        </button>
      </div>

      {/* Verification Report */}
      {report && (
        <div className="space-y-6">
          {/* Verdict Banner */}
          <div className="rounded-lg border border-subtle bg-surface p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {getVerdictBadge(report.verdict)}
                <span className="text-xs text-quiet">Confidence: {report.confidence}</span>
              </div>
              <span className="text-xs text-quiet font-mono">
                Verified at {report.timestamp.slice(0, 19)}
              </span>
            </div>

            <p className="text-sm font-medium text-foreground">{report.rationale}</p>

            {/* Metric counters */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2">
              <div className="p-3 rounded bg-canvas border border-subtle">
                <div className="text-xs text-quiet">Retired Weaknesses</div>
                <div className="text-xl font-bold text-emerald-400">
                  {report.summary.retired_weaknesses_count}
                </div>
              </div>
              <div className="p-3 rounded bg-canvas border border-subtle">
                <div className="text-xs text-quiet">Introduced Protections</div>
                <div className="text-xl font-bold text-cyan-400">
                  {report.summary.introduced_protections_count}
                </div>
              </div>
              <div className="p-3 rounded bg-canvas border border-subtle">
                <div className="text-xs text-quiet">Persisting Risks</div>
                <div className="text-xl font-bold text-amber-400">
                  {report.summary.persisting_risks_count}
                </div>
              </div>
              <div className="p-3 rounded bg-canvas border border-subtle">
                <div className="text-xs text-quiet">Risk Reduction</div>
                <div className="text-xl font-bold text-emerald-400">
                  {report.summary.risk_reduction_percentage}%
                </div>
              </div>
            </div>
          </div>

          {/* Retired Weaknesses List */}
          {report.retired_weaknesses.length > 0 && (
            <div className="rounded-lg border border-subtle bg-surface p-5 space-y-3">
              <h3 className="text-sm font-bold text-emerald-400 flex items-center gap-2">
                <CheckCircle2 size={16} />
                Retired Weak Cryptographic Assets ({report.retired_weaknesses.length})
              </h3>
              <div className="space-y-2">
                {report.retired_weaknesses.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded bg-canvas border border-subtle flex items-center justify-between text-xs"
                  >
                    <div>
                      <span className="font-bold text-foreground mr-2">{item.primitive}</span>
                      <span className="text-quiet">{item.location}</span>
                    </div>
                    <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400">
                      Eliminated
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Introduced Protections */}
          {report.introduced_protections.length > 0 && (
            <div className="rounded-lg border border-subtle bg-surface p-5 space-y-3">
              <h3 className="text-sm font-bold text-cyan-400 flex items-center gap-2">
                <ShieldCheck size={16} />
                Introduced Cryptographic Protections ({report.introduced_protections.length})
              </h3>
              <div className="space-y-2">
                {report.introduced_protections.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded bg-canvas border border-subtle flex items-center justify-between text-xs"
                  >
                    <div>
                      <span className="font-bold text-foreground mr-2">{item.primitive}</span>
                      <span className="text-quiet">{item.description}</span>
                    </div>
                    <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400">
                      Active Protection
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Persisting Risks / Regressions */}
          {report.persisting_risks.length > 0 && (
            <div className="rounded-lg border border-subtle bg-surface p-5 space-y-3">
              <h3 className="text-sm font-bold text-amber-400 flex items-center gap-2">
                <AlertTriangle size={16} />
                Persisting Risks Still Detected ({report.persisting_risks.length})
              </h3>
              <div className="space-y-2">
                {report.persisting_risks.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded bg-canvas border border-subtle flex items-center justify-between text-xs"
                  >
                    <div>
                      <span className="font-bold text-foreground mr-2">{item.primitive}</span>
                      <span className="text-quiet">{item.location}</span>
                    </div>
                    <span className="text-xs px-2 py-0.5 rounded bg-amber-500/10 text-amber-400">
                      Requires Action
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
