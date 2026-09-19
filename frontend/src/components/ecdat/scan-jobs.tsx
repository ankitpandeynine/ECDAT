"use client";

import React, { useEffect, useRef, useState } from "react";
import {
  RefreshCw,
  Radio,
  FileCheck2,
  Clock,
  CheckCircle2,
  XCircle,
  AlertCircle,
  ChevronRight,
  ExternalLink,
  Hash,
  Layers,
  FileCode,
  Globe2,
  Binary,
  Shield,
  Activity,
} from "lucide-react";
import { Scan } from "@/lib/api";
import { EmptyState } from "@/components/ui/empty-state";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetFooter,
} from "@/components/ui/sheet";

interface ScanJobsProps {
  projectId: string;
  onNavigateToStudio?: () => void;
  onNavigateToEvidence?: (scanId: string) => void;
  onInspectScan?: (scanId: string) => void;
  onScanCompleted?: () => void;
}

export function ScanJobs({
  projectId,
  onNavigateToStudio,
  onNavigateToEvidence,
  onInspectScan,
  onScanCompleted,
}: ScanJobsProps) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Keep track of active pollers for running jobs
  const pollingRef = useRef<{ [scanId: string]: NodeJS.Timeout }>({});

  async function loadScans() {
    try {
      setLoading(true);
      const res = await fetch(`/api/scans?project=${encodeURIComponent(projectId)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: Scan[] = await res.json();
      setScans(data);
      setError(null);
    } catch (err: any) {
      console.error("Failed to load scans:", err);
      setError("Failed to fetch scan jobs for this project.");
    } finally {
      setLoading(false);
    }
  }

  // Initial load
  useEffect(() => {
    loadScans();
  }, [projectId]);

  // Running jobs polling (every 2 seconds per running job)
  useEffect(() => {
    const runningScans = scans.filter((s) => s.status === "running" || s.status === "queued");

    // Clean up any pollers for scans that are no longer running
    const runningIds = new Set(runningScans.map((s) => s.id));
    Object.keys(pollingRef.current).forEach((id) => {
      if (!runningIds.has(id)) {
        clearInterval(pollingRef.current[id]);
        delete pollingRef.current[id];
      }
    });

    // Start pollers for newly running scans
    runningScans.forEach((scan) => {
      if (!pollingRef.current[scan.id]) {
        pollingRef.current[scan.id] = setInterval(async () => {
          try {
            const res = await fetch(
              `/api/scans/${encodeURIComponent(scan.id)}?project=${encodeURIComponent(projectId)}`
            );
            if (!res.ok) return;
            const updated: Scan = await res.json();

            setScans((prev) =>
              prev.map((s) => (s.id === updated.id ? updated : s))
            );

            // Update selected scan if it's currently open in the drawer
            setSelectedScan((current) => (current?.id === updated.id ? updated : current));

            // Stop polling if status changed to completed/failed/cancelled
            if (["completed", "failed", "cancelled"].includes(updated.status)) {
              clearInterval(pollingRef.current[updated.id]);
              delete pollingRef.current[updated.id];
              if (onScanCompleted) onScanCompleted();
            }
          } catch (e) {
            console.error(`Error polling scan ${scan.id}:`, e);
          }
        }, 2000);
      }
    });

    return () => {
      // Clear on unmount
      Object.values(pollingRef.current).forEach(clearInterval);
      pollingRef.current = {};
    };
  }, [scans, projectId, onScanCompleted]);

  // Compute duration
  function formatDuration(scan: Scan): string {
    if (!scan.created_at) return "—";
    const start = new Date(scan.created_at).getTime();
    const end = scan.finished_at ? new Date(scan.finished_at).getTime() : Date.now();
    const diff = Math.max(0, end - start);
    if (diff < 1000) return `${diff}ms`;
    if (diff < 60000) return `${(diff / 1000).toFixed(1)}s`;
    const mins = Math.floor(diff / 60000);
    const secs = Math.floor((diff % 60000) / 1000);
    return `${mins}m ${secs}s`;
  }

  function getSurfaceIcon(kind: string) {
    switch (kind?.toLowerCase()) {
      case "code":
        return <FileCode size={14} className="text-cyan-400" />;
      case "binary":
        return <Binary size={14} className="text-purple-400" />;
      case "network":
        return <Globe2 size={14} className="text-emerald-400" />;
      case "pcap":
        return <Activity size={14} className="text-amber-400" />;
      default:
        return <Radio size={14} className="text-cyan-400" />;
    }
  }

  function getStatusBadge(status: string) {
    switch (status) {
      case "completed":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 inline-flex items-center gap-1">
            <CheckCircle2 size={11} /> Completed
          </span>
        );
      case "failed":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-rose-500/10 text-rose-400 border border-rose-500/20 inline-flex items-center gap-1">
            <XCircle size={11} /> Failed
          </span>
        );
      case "cancelled":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-subtle text-quiet border border-subtle inline-flex items-center gap-1">
            <AlertCircle size={11} /> Cancelled
          </span>
        );
      case "running":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 inline-flex items-center gap-1 animate-pulse">
            <RefreshCw size={11} className="animate-spin" /> Running
          </span>
        );
      case "queued":
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-amber-500/10 text-amber-400 border border-amber-500/20 inline-flex items-center gap-1">
            <Clock size={11} /> Queued
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-subtle text-quiet">
            {status}
          </span>
        );
    }
  }

  function getAssetsFoundCount(scan: Scan): number {
    if (!scan.result) return 0;
    const assets = scan.result.assets || [];
    const findings = scan.result.findings || scan.result.detections || [];
    return Math.max(assets.length, findings.length);
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-subtle pb-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-bold tracking-tight text-foreground">Scan Jobs</h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-semibold">
              {scans.length} Total
            </span>
          </div>
          <p className="text-xs text-quiet mt-1">
            Asynchronous scan telemetry, real-time job execution status, and audit manifests.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={loadScans}
            disabled={loading}
            className="px-3 py-1.5 rounded-lg border border-subtle bg-surface hover:bg-canvas text-foreground text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50 shadow-sm"
          >
            <RefreshCw size={13} className={loading ? "animate-spin text-cyan-400" : "text-quiet"} />
            <span>Refresh</span>
          </button>
          {onNavigateToStudio && (
            <button
              onClick={onNavigateToStudio}
              className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-colors"
            >
              <Radio size={13} />
              <span>Launch New Scan</span>
            </button>
          )}
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-300 text-xs flex items-center gap-3">
          <AlertCircle size={16} className="text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Empty State */}
      {!loading && scans.length === 0 && (
        <EmptyState
          icon={<Radio className="h-6 w-6 text-cyan-400" />}
          title="No Scans Yet"
          description="No scans yet. Start your first discovery scan in Scan Studio."
          actionLabel="Open Scan Studio"
          onAction={onNavigateToStudio}
        />
      )}

      {/* Jobs Table */}
      {scans.length > 0 && (
        <div className="rounded-xl border border-subtle bg-surface overflow-hidden shadow-xs">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-canvas/60 border-b border-subtle text-quiet uppercase text-[10px] font-mono font-bold tracking-wider">
                <tr>
                  <th className="p-3.5 pl-4">Job ID</th>
                  <th className="p-3.5">Surface</th>
                  <th className="p-3.5">Status</th>
                  <th className="p-3.5">Assets Found</th>
                  <th className="p-3.5">Duration</th>
                  <th className="p-3.5">Started</th>
                  <th className="p-3.5 text-right pr-4">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-subtle font-mono text-[11px]">
                {scans.map((s) => {
                  const assetsCount = getAssetsFoundCount(s);
                  return (
                    <tr
                      key={s.id}
                      onClick={() => {
                        if (onInspectScan) {
                          onInspectScan(s.id);
                        } else {
                          setSelectedScan(s);
                        }
                      }}
                      className="hover:bg-cyan-500/5 cursor-pointer transition-colors group"
                    >
                      <td className="p-3.5 pl-4 font-bold text-cyan-400 flex items-center gap-1.5">
                        <Hash size={12} className="text-quiet group-hover:text-cyan-400" />
                        <span>{s.id.slice(0, 8)}...</span>
                      </td>
                      <td className="p-3.5">
                        <span className="inline-flex items-center gap-1.5 font-semibold text-foreground uppercase">
                          {getSurfaceIcon(s.kind)}
                          {s.kind}
                        </span>
                      </td>
                      <td className="p-3.5">{getStatusBadge(s.status)}</td>
                      <td className="p-3.5">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              assetsCount > 0
                                ? "bg-cyan-500/10 text-cyan-300 border border-cyan-500/20"
                                : "text-quiet bg-canvas border border-subtle"
                            }`}
                          >
                            {assetsCount} asset{assetsCount === 1 ? "" : "s"}
                          </span>
                          {/* Visual Risk Indicator Dots */}
                          {s.result?.findings && s.result.findings.length > 0 && (
                            <div className="flex items-center gap-1">
                              {s.result.findings.some((f: any) => f.severity === "CRITICAL") && (
                                <span className="h-2 w-2 rounded-full bg-rose-500 inline-block" title="Critical Findings" />
                              )}
                              {s.result.findings.some((f: any) => f.severity === "HIGH") && (
                                <span className="h-2 w-2 rounded-full bg-amber-500 inline-block" title="High Risk Findings" />
                              )}
                              {s.result.findings.some((f: any) => f.severity !== "CRITICAL" && f.severity !== "HIGH") && (
                                <span className="h-2 w-2 rounded-full bg-emerald-500 inline-block" title="Safe / Low Risk" />
                              )}
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="p-3.5 text-quiet">{formatDuration(s)}</td>
                      <td className="p-3.5 text-quiet">
                        {s.created_at ? new Date(s.created_at).toLocaleTimeString() : "—"}
                      </td>
                      <td className="p-3.5 text-right pr-4">
                        <span className="inline-flex items-center gap-1 text-quiet group-hover:text-cyan-400 text-xs font-medium">
                          <span>Inspect</span>
                          <ChevronRight size={13} />
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Detail Drawer (shadcn/ui Sheet) */}
      <Sheet open={!!selectedScan} onOpenChange={(open) => !open && setSelectedScan(null)}>
        <SheetContent
          side="right"
          className="bg-surface border-l border-subtle sm:max-w-md p-0 overflow-y-auto flex flex-col justify-between"
        >
          {selectedScan && (
            <>
              <div>
                <SheetHeader className="p-6 border-b border-subtle bg-canvas/40 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400 flex items-center gap-1">
                      <Hash size={13} /> {selectedScan.id}
                    </span>
                    {getStatusBadge(selectedScan.status)}
                  </div>
                  <SheetTitle className="text-base font-bold text-foreground flex items-center gap-2">
                    {getSurfaceIcon(selectedScan.kind)}
                    <span className="uppercase">{selectedScan.kind} Discovery Scan</span>
                  </SheetTitle>
                  <SheetDescription className="text-xs text-quiet">
                    Full execution parameters, cryptographic inventory yield, and diagnostic telemetry.
                  </SheetDescription>
                </SheetHeader>

                <div className="p-6 space-y-5 text-xs">
                  {/* Key Telemetry Metrics */}
                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-3 rounded-lg bg-canvas border border-subtle space-y-1">
                      <span className="text-[10px] uppercase font-mono text-quiet">Assets Discovered</span>
                      <div className="text-lg font-mono font-bold text-foreground">
                        {getAssetsFoundCount(selectedScan)}
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-canvas border border-subtle space-y-1">
                      <span className="text-[10px] uppercase font-mono text-quiet">Duration</span>
                      <div className="text-lg font-mono font-bold text-foreground">
                        {formatDuration(selectedScan)}
                      </div>
                    </div>
                  </div>

                  {/* Surface & Metadata */}
                  <div className="space-y-2">
                    <h4 className="text-[11px] font-mono font-bold uppercase text-quiet">Job Metadata</h4>
                    <div className="rounded-lg border border-subtle bg-canvas divide-y divide-subtle font-mono text-[11px]">
                      <div className="p-2.5 flex justify-between">
                        <span className="text-quiet">Surface:</span>
                        <span className="text-foreground uppercase font-semibold">{selectedScan.kind}</span>
                      </div>
                      <div className="p-2.5 flex justify-between">
                        <span className="text-quiet">Status:</span>
                        <span className="text-foreground uppercase font-semibold">{selectedScan.status}</span>
                      </div>
                      <div className="p-2.5 flex justify-between">
                        <span className="text-quiet">Started At:</span>
                        <span className="text-foreground">
                          {selectedScan.created_at
                            ? new Date(selectedScan.created_at).toLocaleString()
                            : "—"}
                        </span>
                      </div>
                      <div className="p-2.5 flex justify-between">
                        <span className="text-quiet">Finished At:</span>
                        <span className="text-foreground">
                          {selectedScan.finished_at
                            ? new Date(selectedScan.finished_at).toLocaleString()
                            : "In progress"}
                        </span>
                      </div>
                      {selectedScan.input_hash && (
                        <div className="p-2.5 flex justify-between">
                          <span className="text-quiet">Input Hash:</span>
                          <span className="text-cyan-400 font-mono text-[10px]" title={selectedScan.input_hash}>
                            {selectedScan.input_hash.slice(0, 16)}...
                          </span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Input Summary */}
                  <div className="space-y-2">
                    <h4 className="text-[11px] font-mono font-bold uppercase text-quiet">Input Summary</h4>
                    <div className="p-3 rounded-lg border border-subtle bg-canvas font-mono text-[11px] text-foreground/90 break-all space-y-1">
                      {selectedScan.payload ? (
                        <>
                          {selectedScan.payload.target && (
                            <div>
                              <span className="text-quiet">Target:</span> {selectedScan.payload.target}
                            </div>
                          )}
                          {selectedScan.payload.repo_url && (
                            <div>
                              <span className="text-quiet">Repo:</span> {selectedScan.payload.repo_url}
                            </div>
                          )}
                          {selectedScan.payload.filename && (
                            <div>
                              <span className="text-quiet">File:</span> {selectedScan.payload.filename}
                            </div>
                          )}
                          {selectedScan.payload.path && (
                            <div>
                              <span className="text-quiet">Path:</span> {selectedScan.payload.path}
                            </div>
                          )}
                          {!selectedScan.payload.target &&
                            !selectedScan.payload.repo_url &&
                            !selectedScan.payload.filename &&
                            !selectedScan.payload.path && (
                              <pre className="text-[10px] text-quiet whitespace-pre-wrap">
                                {JSON.stringify(selectedScan.payload, null, 2)}
                              </pre>
                            )}
                        </>
                      ) : (
                        <span className="text-quiet">Standard scan payload</span>
                      )}
                    </div>
                  </div>

                  {/* Error Detail (if any) */}
                  {selectedScan.error && (
                    <div className="space-y-2">
                      <h4 className="text-[11px] font-mono font-bold uppercase text-rose-400">Error Details</h4>
                      <div className="p-3 rounded-lg border border-rose-500/30 bg-rose-500/10 font-mono text-[11px] text-rose-300 whitespace-pre-wrap">
                        {selectedScan.error}
                      </div>
                    </div>
                  )}

                  {/* Discovered Items Snippet */}
                  {selectedScan.result && getAssetsFoundCount(selectedScan) > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-[11px] font-mono font-bold uppercase text-quiet">
                        Discovered Primitives Sample
                      </h4>
                      <div className="max-h-40 overflow-y-auto rounded-lg border border-subtle bg-canvas divide-y divide-subtle">
                        {(selectedScan.result.findings || selectedScan.result.assets || [])
                          .slice(0, 5)
                          .map((item: any, i: number) => (
                            <div key={i} className="p-2.5 flex items-center justify-between text-[11px]">
                              <span className="font-mono text-foreground font-semibold">
                                {item.primitive || item.algorithm || item.name || "Crypto Primitive"}
                              </span>
                              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-subtle text-quiet">
                                {item.asset_type || item.severity || "E1"}
                              </span>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Drawer Footer */}
              <SheetFooter className="p-6 border-t border-subtle bg-canvas/40 flex flex-col gap-2 sm:flex-row">
                {onNavigateToEvidence && (
                  <button
                    onClick={() => {
                      onNavigateToEvidence(selectedScan.id);
                      setSelectedScan(null);
                    }}
                    className="w-full px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center justify-center gap-2 shadow-sm transition-colors"
                  >
                    <FileCheck2 size={14} />
                    <span>View Evidence Explorer</span>
                  </button>
                )}
              </SheetFooter>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
