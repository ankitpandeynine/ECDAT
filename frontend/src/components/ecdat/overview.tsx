"use client";
import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  CartesianGrid,
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";
import {
  ArrowRight,
  Activity,
  CheckCircle2,
  Globe2,
  Code2,
  Binary,
  Route,
  X,
  ShieldAlert,
  Gauge,
  Radar,
  FileCheck2,
  Scale,
  FlaskConical,
  PlayCircle,
  Radio,
  Layers,
  Lock,
  Archive,
  Cpu,
  Hourglass,
} from "lucide-react";
import { Scan } from "@/lib/api";
import { EmptyState } from "@/components/ui/empty-state";

interface OverviewProps {
  projectId?: string;
  scans?: Scan[];
  connected?: boolean;
  onStart: (kind: "network" | "code" | "binary") => void;
  onInspect: (id: string) => void;
  onMigration: () => void;
  onVerification?: () => void;
  onStandards?: () => void;
  onExperimental?: () => void;
  onSihDemo?: () => void;
}

export function Overview({
  projectId = "default",
  scans = [],
  connected = true,
  onStart,
  onInspect,
  onMigration,
  onVerification,
  onStandards,
  onExperimental,
  onSihDemo,
}: OverviewProps) {
  const [tipsDismissed, setTipsDismissed] = useState(false);
  const tipsSeen = useSyncExternalStore(
    () => () => undefined,
    () => window.localStorage.getItem("ecdat-starting-tips-seen") === "true",
    () => true,
  );
  const tips = !tipsSeen && !tipsDismissed;

  function dismissTips() {
    window.localStorage.setItem("ecdat-starting-tips-seen", "true");
    setTipsDismissed(true);
  }

  const [days, setDays] = useState(7);
  const [overviewData, setOverviewData] = useState<{
    kpis: {
      total_findings: number;
      critical: number;
      quantum_vulnerable_certs: number;
      est_migration_effort: string;
    };
    graph: { nodes: any[]; links: any[] };
    scan_count: number;
    asset_count: number;
    action_queue: Array<{
      priority: string;
      title: string;
      description: string;
      asset_ids: string[];
    }>;
    algo_distribution?: Array<[string, number]>;
    risk_distribution?: { critical: number; safe: number; legacy: number };
    coverage?: Array<{ name: string; status: string }>;
  } | null>(null);

  const [timelineSummary, setTimelineSummary] = useState<Array<{
    algorithm: string;
    z_years: number;
    risk_level: string;
    asset_count: number;
  }> | null>(null);

  useEffect(() => {
    let isMounted = true;
    async function loadOverview() {
      try {
        const res = await fetch(`/api/overview?project=${encodeURIComponent(projectId)}`);
        if (res.ok) {
          const data = await res.json();
          if (isMounted) setOverviewData(data);
        }
      } catch (err) {
        console.error("Failed to fetch overview data:", err);
      }
    }

    async function loadTimeline() {
      try {
        const res = await fetch(`/api/quantum/timeline-summary?project=${encodeURIComponent(projectId)}`);
        if (res.ok) {
          const tdata = await res.json();
          if (isMounted && Array.isArray(tdata)) {
            setTimelineSummary(tdata);
          }
        }
      } catch (err) {
        console.error("Failed to fetch quantum timeline summary:", err);
      }
    }

    loadOverview();
    loadTimeline();
    return () => {
      isMounted = false;
    };
  }, [projectId]);

  const complete = scans.filter((s) => s.status === "completed");
  const active = scans.filter((s) => ["queued", "running"].includes(s.status));
  const findings = complete.flatMap(
    (s) => s.result?.findings || s.result?.detections || [],
  );

  const totalAssets = overviewData ? overviewData.asset_count : 0;
  const criticalFindings = overviewData ? overviewData.kpis.critical : 0;
  const algoDistribution = overviewData?.algo_distribution || [];
  const riskDistribution = overviewData?.risk_distribution || {
    critical: 0,
    safe: 0,
    legacy: 0,
  };

  const riskScore = Math.min(
    100,
    criticalFindings * 28 + (overviewData ? Math.max(0, overviewData.kpis.total_findings - criticalFindings) * 6 : 0),
  );

  const posture = totalAssets === 0 && findings.length === 0
    ? "Awaiting evidence"
    : riskScore >= 55
      ? "Action required"
      : riskScore >= 20
        ? "Review recommended"
        : "Controlled";

  const quantumReadiness = totalAssets > 0 || complete.length > 0 ? Math.max(18, 100 - riskScore) : 0;
  const migrationReadiness = totalAssets > 0 || complete.length > 0 ? Math.max(12, 86 - riskScore) : 0;

  const data = useMemo(
    () =>
      Array.from({ length: days }, (_, i) => {
        const d = new Date();
        d.setHours(0, 0, 0, 0);
        d.setDate(d.getDate() - days + 1 + i);
        const end = new Date(d);
        end.setDate(end.getDate() + 1);
        return {
          date: d.toLocaleDateString(undefined, {
            month: "short",
            day: "numeric",
          }),
          scans: scans.filter(
            (s) => new Date(s.created_at) >= d && new Date(s.created_at) < end,
          ).length,
        };
      }),
    [scans, days],
  );

  return (
    <div className="overview">
      <div className="workspace-heading">
        <div>
          <p className="eyebrow">WORKSPACE / OVERVIEW</p>
          <h1>Discovery command center</h1>
          <p>Understand what you have. Decide what changes next.</p>
        </div>
        <button className="ec-button" onClick={() => onStart("network")}>
          New scan <ArrowRight size={16} />
        </button>
      </div>

      {tips && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/45 p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="tips-heading"
        >
          <section className="w-full max-w-2xl rounded-xl border border-subtle bg-surface p-6 shadow-2xl">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="eyebrow">WELCOME TO ECDAT</p>
                <h2 id="tips-heading" className="mt-2 text-xl font-semibold">
                  Your first scan, in three steps
                </h2>
                <p className="mt-2 text-sm text-quiet">
                  This quick guide is shown once. You can start with any scan
                  type when you are ready.
                </p>
              </div>
              <button
                onClick={dismissTips}
                aria-label="Close starting tips"
                className="rounded p-1 text-quiet hover:bg-surface-raised"
              >
                <X size={18} />
              </button>
            </div>
            <div className="mt-5 grid gap-3 sm:grid-cols-3">
              {[
                [
                  "01",
                  "Choose a target",
                  "Start with a website, code, or firmware you are authorized to inspect.",
                ],
                [
                  "02",
                  "Review the evidence",
                  "Use scan results to understand findings and coverage.",
                ],
                [
                  "03",
                  "Plan your next move",
                  "Create a report and prioritize remediation.",
                ],
              ].map(([n, title, text]) => (
                <div
                  key={n}
                  className="rounded-lg border border-subtle bg-canvas/50 p-4"
                >
                  <span className="font-mono text-xs text-teal">{n}</span>
                  <h3 className="mt-2 text-sm font-semibold">{title}</h3>
                  <p className="mt-1 text-xs leading-relaxed text-quiet">
                    {text}
                  </p>
                </div>
              ))}
            </div>
            <div className="mt-6 flex justify-end">
              <button className="ec-button" onClick={dismissTips}>
                Get started <ArrowRight size={15} />
              </button>
            </div>
          </section>
        </div>
      )}

      {/* Posture Banner */}
      <section className="command-posture">
        <div className="posture-overview">
          <div className="posture-kicker">
            <ShieldAlert size={17} /> SECURITY POSTURE
          </div>
          <div className="posture-score-row">
            <strong>
              {totalAssets > 0 || complete.length > 0 ? String(100 - riskScore).padStart(2, "0") : "—"}
            </strong>
            <div>
              <h2>{posture}</h2>
              <p>
                {totalAssets > 0 || complete.length > 0
                  ? `${overviewData?.kpis.total_findings ?? findings.length} recorded findings across ${overviewData?.scan_count ?? complete.length} completed scans.`
                  : "Run a scan to establish your cryptographic risk baseline."}
              </p>
            </div>
          </div>
          <div className="posture-actions">
            <button
              className="ec-button compact"
              onClick={() => onStart("network")}
            >
              Run network scan <ArrowRight size={14} />
            </button>
            <button className="text-action" onClick={onMigration}>
              Open migration plan <Route size={14} />
            </button>
          </div>
        </div>

        <div className="severity-strip" aria-label="Finding severity summary">
          {[
            ["Critical (Shor)", riskDistribution.critical, "critical"],
            ["Grover / PQC Safe", riskDistribution.safe, "low"],
            ["Legacy Insecure", riskDistribution.legacy, "high"],
          ].map(([label, value, severity]) => (
            <div className={`severity-item ${severity}`} key={String(label)}>
              <span>{String(label)}</span>
              <strong>{String(value)}</strong>
            </div>
          ))}
          <p>
            <span className="status-dot" />{" "}
            {connected
              ? "Evidence service connected"
              : "Connect a project to load evidence"}
          </p>
        </div>
      </section>

      {/* Readiness Grid */}
      <section className="readiness-grid" aria-label="Readiness summary">
        {[
          [
            Gauge,
            "Quantum readiness",
            quantumReadiness,
            "Exposure measured against the current inventory.",
          ],
          [
            Radar,
            "Migration readiness",
            migrationReadiness,
            "Planning confidence based on available evidence.",
          ],
        ].map(([Icon, label, value, detail]) => {
          const ReadinessIcon = Icon as typeof Gauge;
          return (
            <article className="readiness-card" key={String(label)}>
              <div
                className="readiness-ring"
                style={
                  { "--readiness": `${String(value)}%` } as React.CSSProperties
                }
              >
                <span>{value ? `${String(value)}%` : "—"}</span>
              </div>
              <div>
                <ReadinessIcon size={17} />
                <h2>{String(label)}</h2>
                <p>{String(detail)}</p>
              </div>
            </article>
          );
        })}
      </section>

      {/* Metric Grid */}
      <div className="metric-grid">
        {[
          [
            CheckCircle2,
            "Crypto assets",
            overviewData ? overviewData.asset_count : totalAssets,
            "Discovered in project",
          ],
          [
            ShieldAlert,
            "Quantum-relevant",
            criticalFindings,
            "Shor algorithm vulnerable",
          ],
          [
            Activity,
            "Completed scans",
            overviewData ? overviewData.scan_count : complete.length,
            "Saved in this project",
          ],
          [
            Route,
            "Migration effort",
            overviewData?.kpis.est_migration_effort || "0 weeks",
            "Heuristic estimate",
          ],
        ].map(([Icon, title, value, note]) => {
          const I = Icon as typeof Activity;
          return (
            <article className="metric" key={String(title)}>
              <div>
                <span>{String(title)}</span>
                <I size={16} />
              </div>
              <strong>{String(value)}</strong>
              <small>{String(note)}</small>
            </article>
          );
        })}
      </div>

      {/* Overview Charts: Wrapped with EmptyState conditionals */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 my-6">
        {/* Chart 1: Risk Distribution Donut */}
        <section className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-subtle pb-3">
            <div>
              <h2 className="text-sm font-semibold">Risk distribution</h2>
              <p className="text-xs text-quiet">Critical Shor-vulnerable vs Grover-safe vs Legacy primitives</p>
            </div>
            <span className="text-[10px] text-quiet font-mono">Total Assets: {totalAssets}</span>
          </div>

          {totalAssets === 0 ? (
            <EmptyState
              icon={<ShieldAlert className="h-6 w-6 text-rose-400" />}
              title="No Risk Distribution Data"
              description="No cryptographic assets cataloged in this project yet. Run a discovery scan to calculate vulnerability distribution."
              actionLabel="Run First Scan"
              onAction={() => onStart("network")}
            />
          ) : (
            <div className="flex items-center justify-around py-2">
              <div className="relative flex items-center justify-center">
                <svg className="w-36 h-36 -rotate-90" viewBox="0 0 36 36">
                  <circle cx="18" cy="18" r="14" fill="none" stroke="currentColor" className="text-subtle/40" strokeWidth="4" />
                  {riskDistribution.critical > 0 && (
                    <circle
                      cx="18"
                      cy="18"
                      r="14"
                      fill="none"
                      stroke="#f43f5e"
                      strokeWidth="4"
                      strokeDasharray={`${Math.max((riskDistribution.critical / totalAssets) * 88, 5)} 100`}
                      strokeDashoffset="0"
                    />
                  )}
                  {riskDistribution.safe > 0 && (
                    <circle
                      cx="18"
                      cy="18"
                      r="14"
                      fill="none"
                      stroke="#10b981"
                      strokeWidth="4"
                      strokeDasharray={`${Math.max((riskDistribution.safe / totalAssets) * 88, 5)} 100`}
                      strokeDashoffset={`-${(riskDistribution.critical / totalAssets) * 88}`}
                    />
                  )}
                </svg>
                <div className="absolute flex flex-col items-center">
                  <span className="text-xl font-bold font-mono">{totalAssets}</span>
                  <span className="text-[9px] text-quiet uppercase">Assets</span>
                </div>
              </div>

              <div className="space-y-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-rose-500 shrink-0" />
                  <span className="text-quiet">Critical (Shor Vuln):</span>
                  <span className="font-bold text-foreground font-mono">{riskDistribution.critical}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-emerald-500 shrink-0" />
                  <span className="text-quiet">Safe (Grover / PQC):</span>
                  <span className="font-bold text-foreground font-mono">{riskDistribution.safe}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-amber-500 shrink-0" />
                  <span className="text-quiet">Legacy Insecure:</span>
                  <span className="font-bold text-foreground font-mono">{riskDistribution.legacy}</span>
                </div>
              </div>
            </div>
          )}
        </section>

        {/* Chart 2: Algorithm Family Distribution Bar Chart */}
        <section className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-subtle pb-3">
            <div>
              <h2 className="text-sm font-semibold">Algorithm frequency</h2>
              <p className="text-xs text-quiet">Empirical distribution across detected assets</p>
            </div>
            <span className="text-[10px] text-cyan-400 font-mono">Empirical Frequency</span>
          </div>

          {algoDistribution.length === 0 ? (
            <EmptyState
              icon={<Code2 className="h-6 w-6 text-cyan-400" />}
              title="No Algorithm Frequency Data"
              description="No algorithm primitives cataloged. Ingest source code, lockfiles, or binaries to compute empirical frequency."
              actionLabel="Scan Source Code"
              onAction={() => onStart("code")}
            />
          ) : (
            <div className="space-y-2.5 py-1">
              {algoDistribution.slice(0, 5).map(([algo, count]) => {
                const pct = Math.max(Math.round((count / totalAssets) * 100), 8);
                const isVuln = algo.toUpperCase().includes("RSA") || algo.toUpperCase().includes("ECDSA") || algo.toUpperCase().includes("SHA-1");
                return (
                  <div key={algo} className="space-y-1">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="font-semibold text-foreground truncate max-w-[200px]">{algo}</span>
                      <span className="text-quiet">{count} ({pct}%)</span>
                    </div>
                    <div className="h-2 rounded-full bg-canvas overflow-hidden border border-subtle/50">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          isVuln ? "bg-rose-500" : "bg-cyan-500"
                        }`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {/* Chart 3: Scan activity chart */}
        <section className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-subtle pb-3">
            <div>
              <h2 className="text-sm font-semibold">Scan activity</h2>
              <p className="text-xs text-quiet">Submissions per day · latest 200 records · local time</p>
            </div>
            <select
              aria-label="Chart period"
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              className="px-2 py-1 rounded border border-subtle bg-canvas text-xs"
            >
              <option value={7}>7 days</option>
              <option value={30}>30 days</option>
            </select>
          </div>

          {scans.length === 0 ? (
            <EmptyState
              icon={<Activity className="h-6 w-6 text-cyan-400" />}
              title="No Activity History"
              description="Run a scan to establish your project's cryptographic discovery and activity history."
              actionLabel="Launch Scan"
              onAction={() => onStart("network")}
            />
          ) : (
            <div className="activity-chart">
              <ResponsiveContainer width="100%" height={210}>
                <AreaChart
                  data={data}
                  margin={{ top: 15, right: 16, left: -20, bottom: 0 }}
                >
                  <CartesianGrid
                    vertical={false}
                    stroke="var(--border)"
                    strokeDasharray="3 5"
                  />
                  <XAxis
                    dataKey="date"
                    tick={{ fill: "var(--muted-text)", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                    minTickGap={20}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: "var(--muted-text)", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "var(--surface)",
                      border: "1px solid var(--border)",
                      color: "var(--text)",
                      borderRadius: 8,
                    }}
                  />
                  <Area
                    dataKey="scans"
                    name="Scans submitted"
                    type="linear"
                    stroke="var(--teal)"
                    strokeWidth={2}
                    fill="var(--teal)"
                    fillOpacity={0.12}
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        {/* Chart 4: Discovery coverage */}
        <section className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-subtle pb-3">
            <div>
              <h2 className="text-sm font-semibold">Discovery coverage</h2>
              <p className="text-xs text-quiet">Completed scans across multi-surface modalities</p>
            </div>
          </div>

          {complete.length === 0 ? (
            <EmptyState
              icon={<Globe2 className="h-6 w-6 text-cyan-400" />}
              title="No Discovery Coverage Yet"
              description="No completed scans recorded for this project. Launch a network, code, or binary scan to begin coverage analysis."
              actionLabel="Run First Scan"
              onAction={() => onStart("network")}
            />
          ) : (
            <div className="space-y-3">
              {(
                [
                  { kind: "network", label: "Network & TLS", Icon: Globe2 },
                  { kind: "code", label: "Source Code AST", Icon: Code2 },
                  { kind: "binary", label: "Binary & Firmware", Icon: Binary },
                  { kind: "pcap", label: "Passive PCAP Stream", Icon: Radio },
                ] as const
              ).map(({ kind, label, Icon }) => {
                const n = complete.filter((s) => s.kind === kind).length;
                return (
                  <div key={kind} className="space-y-1">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <div className="flex items-center gap-2">
                        <Icon size={14} className="text-cyan-400" />
                        <span>{label}</span>
                      </div>
                      <span className="text-quiet">{n} scan{n === 1 ? "" : "s"}</span>
                    </div>
                    <div className="h-2 rounded-full bg-canvas overflow-hidden border border-subtle/50">
                      <div
                        className="h-full bg-cyan-500 rounded-full transition-all duration-500"
                        style={{
                          width: `${complete.length ? (n / complete.length) * 100 : 0}%`,
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </div>

      {/* Horizontal Bar Chart: Quantum Break Threat Horizon (CRQC) */}
      {timelineSummary && timelineSummary.length > 0 && (
        <section className="rounded-xl border border-subtle bg-surface p-5 my-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-subtle pb-3 gap-2">
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-semibold flex items-center gap-2">
                  <Hourglass className="h-4 w-4 text-cyan-400" />
                  Quantum Break Threat Horizons (CRQC)
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-semibold">
                  Gidney &amp; Ekerå 2021 / NIST IR 8547
                </span>
              </div>
              <p className="text-xs text-quiet mt-0.5">
                Estimated years until a Cryptanalytically Relevant Quantum Computer compromises primitive security
              </p>
            </div>
            <div className="flex items-center gap-3 text-[11px] font-mono text-quiet flex-wrap">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm bg-rose-500 inline-block" />
                <span>&lt; 5y Critical</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm bg-amber-500 inline-block" />
                <span>5–10y At Risk</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm bg-sky-400 inline-block" />
                <span>10–20y Moderate</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500 inline-block" />
                <span>20y+ Quantum Safe</span>
              </span>
            </div>
          </div>

          <div className="pt-2">
            <ResponsiveContainer width="100%" height={Math.max(200, timelineSummary.length * 44)}>
              <BarChart
                layout="vertical"
                data={timelineSummary}
                margin={{ top: 5, right: 30, left: 10, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="var(--border)" />
                <XAxis
                  type="number"
                  unit="y"
                  domain={[0, (dataMax: number) => Math.max(20, Math.ceil(dataMax * 1.1))]}
                  tick={{ fill: "var(--muted-text)", fontSize: 11 }}
                />
                <YAxis
                  type="category"
                  dataKey="algorithm"
                  tick={{ fill: "var(--text)", fontSize: 11, fontWeight: 600 }}
                  width={110}
                />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const d = payload[0].payload;
                      return (
                        <div className="p-2.5 rounded-lg bg-surface border border-subtle shadow-lg text-xs space-y-1">
                          <div className="font-bold text-foreground flex items-center justify-between gap-4">
                            <span>{d.algorithm}</span>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-canvas border border-subtle">
                              {d.asset_count} asset{d.asset_count === 1 ? "" : "s"}
                            </span>
                          </div>
                          <div className="text-quiet flex justify-between gap-4">
                            <span>Threat Horizon:</span>
                            <span className="font-mono font-bold text-foreground">{d.z_years} Years (~{2026 + Math.round(d.z_years)})</span>
                          </div>
                          <div className="text-quiet flex justify-between gap-4">
                            <span>Classification:</span>
                            <span className="font-mono font-semibold text-cyan-400">{d.risk_level}</span>
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Bar dataKey="z_years" name="Years to CRQC Threat" radius={[0, 4, 4, 0]}>
                  {timelineSummary.map((entry, index) => {
                    const fill =
                      entry.z_years <= 4
                        ? "#f43f5e"
                        : entry.z_years <= 9
                        ? "#fb7185"
                        : entry.z_years <= 15
                        ? "#f59e0b"
                        : entry.z_years <= 30
                        ? "#38bdf8"
                        : "#10b981";
                    return <Cell key={`cell-${index}`} fill={fill} />;
                  })}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
      )}

      {/* Action Queue from Real Overview Data */}
      <section className="rounded-xl border border-subtle bg-surface p-5 my-6 space-y-3">
        <h2 className="text-sm font-semibold">Evidence-Driven Action Queue</h2>
        {!overviewData || overviewData.action_queue.length === 0 ? (
          <EmptyState
            icon={<CheckCircle2 className="h-6 w-6 text-emerald-400" />}
            title="Action Queue Clear"
            description="No urgent cryptographic migrations or deprecation actions currently queued for this project."
            actionLabel="Scan Source / Network"
            onAction={() => onStart("network")}
          />
        ) : (
          <div className="space-y-2">
            {overviewData.action_queue.map((a, i) => (
              <div key={i} className="flex items-start justify-between p-3 rounded-lg border border-subtle/60 bg-canvas/40">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                      a.priority === "NOW" ? "bg-rose-500/10 border border-rose-500/20 text-rose-400" :
                      a.priority === "NEXT" ? "bg-amber-500/10 border border-amber-500/20 text-amber-400" :
                      "bg-cyan-500/10 border border-cyan-500/20 text-cyan-300"
                    }`}>
                      {a.priority}
                    </span>
                    <span className="font-semibold text-xs text-foreground">{a.title}</span>
                  </div>
                  <p className="text-xs text-quiet leading-relaxed">{a.description}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Recent Discovery Table */}
      <section className="ec-panel">
        <div className="panel-heading">
          <div>
            <h2>Recent discovery</h2>
            <p>Open a record to inspect its evidence</p>
          </div>
          <span className="count-label">{scans.length} saved records</span>
        </div>
        {!scans.length ? (
          <EmptyState
            icon={<Radio className="h-6 w-6 text-cyan-400" />}
            title="No Scans Recorded Yet"
            description="Choose a discovery modality below to initiate your first cryptographic scan."
            actionLabel="Start Network Scan"
            onAction={() => onStart("network")}
          />
        ) : (
          <div className="table-scroll">
            <table className="recent-table">
              <thead>
                <tr>
                  <th>Target / artifact</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>
                    <span className="sr-only">Action</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 6).map((s) => (
                  <tr key={s.id}>
                    <td>
                      {s.result?.target ||
                        (s.result?.findings || s.result?.detections || [])[0]
                          ?.file ||
                        `${s.kind} scan · ${s.id.slice(0, 8)}`}
                    </td>
                    <td>{s.kind}</td>
                    <td>
                      <span className={`status-pill ${s.status}`}>
                        {s.status}
                      </span>
                    </td>
                    <td>{new Date(s.created_at).toLocaleDateString()}</td>
                    <td>
                      <button
                        className="ec-button secondary compact"
                        onClick={() => onInspect(s.id)}
                      >
                        Inspect <ArrowRight size={13} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Quick Actions */}
      <div className="quick-actions">
        {(
          [
            { kind: "network", title: "Website & TLS", Icon: Globe2 },
            { kind: "code", title: "Source code", Icon: Code2 },
            { kind: "binary", title: "Binary & firmware", Icon: Binary },
          ] as const
        ).map(({ kind, title, Icon }) => (
          <button
            key={kind}
            className="quick-action"
            onClick={() => onStart(kind)}
          >
            <Icon size={20} />
            <span>
              {title}
              <small>Start a real scan</small>
            </span>
            <ArrowRight size={16} />
          </button>
        ))}
        <button className="quick-action" onClick={onMigration}>
          <Route size={20} />
          <span>
            Migration planner<small>Security + hosting</small>
          </span>
          <ArrowRight size={16} />
        </button>
        {onVerification && (
          <button className="quick-action" onClick={onVerification}>
            <FileCheck2 size={20} />
            <span>
              Verification engine<small>Closed-loop audit</small>
            </span>
            <ArrowRight size={16} />
          </button>
        )}
        {onStandards && (
          <button className="quick-action" onClick={onStandards}>
            <Scale size={20} />
            <span>
              Standards matrix<small>FIPS 203 / CNSA 2.0</small>
            </span>
            <ArrowRight size={16} />
          </button>
        )}
        {onExperimental && (
          <button className="quick-action" onClick={onExperimental}>
            <FlaskConical size={20} />
            <span>
              Experimental hub<small>7 Next-gen tools</small>
            </span>
            <ArrowRight size={16} />
          </button>
        )}
        {onSihDemo && (
          <button className="quick-action" onClick={onSihDemo}>
            <PlayCircle size={20} />
            <span>
              SIH 10-step demo<small>Judge walkthrough</small>
            </span>
            <ArrowRight size={16} />
          </button>
        )}
      </div>
    </div>
  );
}
