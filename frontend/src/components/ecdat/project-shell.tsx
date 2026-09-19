"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import {
  ShieldCheck,
  LayoutDashboard,
  Radio,
  Layers,
  FileCheck2,
  GitFork,
  Gauge,
  Bomb,
  Route,
  CheckCircle2,
  Download,
  Archive,
  BookOpen,
  Settings,
  Globe,
  Code2,
  Binary,
  Menu,
  X,
  ChevronLeft,
  Zap,
  FileText,
  Bot,
  Cpu,
  Hourglass,
  ArrowRight,
  AlertTriangle,
} from "lucide-react";
import { ThemeToggle } from "@/components/ecdat/theme-toggle";
import { Scan } from "@/lib/api";

export type TabKey =
  | "overview"
  | "studio"
  | "jobs"
  | "assets"
  | "evidence"
  | "graph"
  | "quantum"
  | "mosca"
  | "agility"
  | "blast"
  | "migration"
  | "verify"
  | "cbom"
  | "reports"
  | "archive"
  | "knowledge"
  | "settings";

interface NavGroup {
  title: string;
  items: Array<{ key: TabKey; label: string; icon: React.ElementType; badge?: string }>;
}

export function ProjectShell({
  projectId,
  projectName,
  activeTab,
  onTabChange,
  children,
  assetCount: propAssetCount,
  scanCount: propScanCount,
}: {
  projectId: string;
  projectName: string;
  activeTab: TabKey;
  onTabChange: (tab: TabKey) => void;
  children: React.ReactNode;
  assetCount?: number;
  scanCount?: number;
}) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  // Dynamic badge counts from real backend endpoints
  const [counts, setCounts] = useState<{
    completedScans: number;
    totalAssets: number;
    graphNodes: number;
  }>({
    completedScans: propScanCount ?? 0,
    totalAssets: propAssetCount ?? 0,
    graphNodes: 0,
  });

  // Active running/queued scan for top banner
  const [runningScan, setRunningScan] = useState<Scan | null>(null);
  const [elapsedTime, setElapsedTime] = useState<string>("0s");
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Track previously running IDs to detect completion
  const prevRunningIdsRef = useRef<Set<string>>(new Set());

  // Function to refresh overview and graph counts
  async function refreshCounts() {
    if (!projectId) return;
    try {
      const [overviewRes, graphRes] = await Promise.all([
        fetch(`/api/overview?project=${encodeURIComponent(projectId)}`),
        fetch(`/api/graph?project=${encodeURIComponent(projectId)}`),
      ]);

      let completedScans = 0;
      let totalAssets = 0;
      let graphNodes = 0;

      if (overviewRes.ok) {
        const odata = await overviewRes.json();
        completedScans = odata.summary?.completed_scans ?? odata.scan_count ?? 0;
        totalAssets = odata.summary?.total_crypto_assets ?? odata.asset_count ?? 0;
        if (odata.graph?.nodes?.length) {
          graphNodes = odata.graph.nodes.length;
        }
      }

      if (graphRes.ok) {
        const gdata = await graphRes.json();
        if (Array.isArray(gdata.nodes)) {
          graphNodes = gdata.nodes.length;
        }
      }

      setCounts({ completedScans, totalAssets, graphNodes });
    } catch (e) {
      console.error("Failed to load project counts in shell:", e);
    }
  }

  // Load counts on project load
  useEffect(() => {
    refreshCounts();
  }, [projectId]);

  // Poll for running scan status every 5 seconds
  useEffect(() => {
    if (!projectId) return;

    async function checkRunningScans() {
      try {
        const res = await fetch(`/api/scans?project=${encodeURIComponent(projectId)}&status=running`);
        if (!res.ok) return;
        const runningList: Scan[] = await res.json();

        const currentRunningIds = new Set(runningList.map((s) => s.id));

        // Check if any previously running scans have completed
        for (const prevId of prevRunningIdsRef.current) {
          if (!currentRunningIds.has(prevId)) {
            // Scan completed! Fetch its asset yield
            try {
              const scanRes = await fetch(
                `/api/scans/${encodeURIComponent(prevId)}?project=${encodeURIComponent(projectId)}`
              );
              if (scanRes.ok) {
                const finishedScan: Scan = await scanRes.json();
                const foundCount =
                  finishedScan.result?.assets?.length ??
                  finishedScan.result?.findings?.length ??
                  finishedScan.result?.detections?.length ??
                  0;
                setToastMessage(`Scan complete — ${foundCount} asset${foundCount === 1 ? "" : "s"} found`);
                setTimeout(() => setToastMessage(null), 4500);
              }
            } catch (err) {
              console.error("Error inspecting completed scan:", err);
            }
            // Refresh counts immediately
            refreshCounts();
          }
        }

        prevRunningIdsRef.current = currentRunningIds;

        if (runningList.length > 0) {
          setRunningScan(runningList[0]);
        } else {
          setRunningScan(null);
        }
      } catch (err) {
        console.error("Error polling running scans:", err);
      }
    }

    checkRunningScans();
    const interval = setInterval(checkRunningScans, 5000);
    return () => clearInterval(interval);
  }, [projectId]);

  // Live elapsed time ticker for active running scan
  useEffect(() => {
    if (!runningScan?.created_at) return;

    function updateTicker() {
      if (!runningScan?.created_at) return;
      const start = new Date(runningScan.created_at).getTime();
      const diff = Math.max(0, Date.now() - start);
      if (diff < 60000) {
        setElapsedTime(`${Math.floor(diff / 1000)}s`);
      } else {
        const mins = Math.floor(diff / 60000);
        const secs = Math.floor((diff % 60000) / 1000);
        setElapsedTime(`${mins}m ${secs}s`);
      }
    }

    updateTicker();
    const timer = setInterval(updateTicker, 1000);
    return () => clearInterval(timer);
  }, [runningScan]);

  // Construct navigation groups with real dynamic badge counts
  const navGroups: NavGroup[] = [
    {
      title: "COMMAND CENTER",
      items: [
        { key: "overview", label: "Overview", icon: LayoutDashboard },
        { key: "studio", label: "Scan Studio", icon: Radio },
        {
          key: "jobs",
          label: "Scan Jobs",
          icon: Zap,
          badge: counts.completedScans > 0 ? String(counts.completedScans) : undefined,
        },
      ],
    },
    {
      title: "DISCOVERY",
      items: [
        {
          key: "assets",
          label: "Asset Inventory",
          icon: Layers,
          badge: counts.totalAssets > 0 ? String(counts.totalAssets) : undefined,
        },
        { key: "evidence", label: "Evidence Records", icon: FileCheck2 },
        {
          key: "graph",
          label: "Crypto Graph",
          icon: GitFork,
          badge: counts.graphNodes > 0 ? String(counts.graphNodes) : undefined,
        },
      ],
    },
    {
      title: "RISK & READINESS",
      items: [
        { key: "quantum", label: "Quantum Risk", icon: Cpu },
        { key: "mosca", label: "Mosca Timeline", icon: Hourglass },
        { key: "agility", label: "Crypto Agility", icon: Gauge },
        { key: "blast", label: "Blast Radius", icon: Bomb },
      ],
    },
    {
      title: "MIGRATION",
      items: [
        { key: "migration", label: "Migration Planner", icon: Route },
        { key: "verify", label: "Verification", icon: CheckCircle2 },
      ],
    },
    {
      title: "EXPORT & TOOLS",
      items: [
        { key: "cbom", label: "CBOM Export", icon: Download },
        { key: "reports", label: "Reports", icon: FileText },
        { key: "archive", label: "Archive Lab", icon: Archive },
        { key: "knowledge", label: "Knowledge Base", icon: BookOpen },
        { key: "settings", label: "Settings", icon: Settings },
      ],
    },
  ];

  return (
    <div className="ecdat-shell">
      {/* ─── Top Banner (Active Scan Alert) ─── */}
      {runningScan && (
        <div className="bg-cyan-500/10 border-b border-cyan-500/30 px-4 py-2 text-xs text-cyan-300 flex items-center justify-between font-mono animate-pulse z-40">
          <div className="flex items-center gap-2">
            <span className="animate-spin text-cyan-400 font-bold">⟳</span>
            <span>
              Scan running — <strong className="uppercase text-cyan-200">{runningScan.kind}</strong> — Job{" "}
              {runningScan.id.slice(0, 8)} — {elapsedTime}
            </span>
          </div>
          <button
            onClick={() => onTabChange("jobs")}
            className="text-cyan-400 hover:text-cyan-200 underline font-semibold flex items-center gap-1 cursor-pointer transition-colors"
          >
            <span>View Job →</span>
          </button>
        </div>
      )}

      {/* ─── Toast Notification for Scan Completion ─── */}
      {toastMessage && (
        <div className="fixed top-4 right-4 z-50 p-3.5 rounded-xl bg-surface border border-emerald-500/40 text-emerald-300 shadow-xl flex items-center gap-2.5 font-mono text-xs animate-in slide-in-from-top-4 duration-300">
          <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
          <span className="font-semibold">{toastMessage}</span>
          <button
            onClick={() => setToastMessage(null)}
            className="ml-2 text-quiet hover:text-foreground"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* ─── Top Bar ─── */}
      <header className="ecdat-topbar">
        <div className="ecdat-topbar-left">
          <button
            className="ecdat-mobile-toggle"
            onClick={() => setMobileOpen(!mobileOpen)}
            aria-label="Toggle navigation"
          >
            {mobileOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
          <Link href="/projects" className="ecdat-brand">
            <ShieldCheck size={22} />
            <span className="ecdat-brand-text">ECDAT</span>
          </Link>
          <span className="ecdat-breadcrumb">
            <ChevronLeft size={14} />
            <Link href="/projects" className="ecdat-breadcrumb-link">Projects</Link>
            <span className="ecdat-breadcrumb-sep">/</span>
            <span className="ecdat-breadcrumb-current">{projectName || projectId}</span>
          </span>
        </div>
        <div className="ecdat-topbar-right">
          <div className="ecdat-topbar-stats">
            <span className="ecdat-stat-badge">
              <Zap size={13} /> {counts.completedScans} scans
            </span>
            <span className="ecdat-stat-badge">
              <Layers size={13} /> {counts.totalAssets} assets
            </span>
          </div>
          <ThemeToggle />
        </div>
      </header>

      <div className="ecdat-body">
        {/* ─── Sidebar ─── */}
        <nav
          className={`ecdat-sidebar ${collapsed ? "ecdat-sidebar-collapsed" : ""} ${mobileOpen ? "ecdat-sidebar-open" : ""}`}
          aria-label="Project navigation"
        >
          <div className="ecdat-sidebar-inner">
            {navGroups.map((group) => (
              <div key={group.title} className="ecdat-nav-group">
                {!collapsed && (
                  <div className="ecdat-nav-group-title">{group.title}</div>
                )}
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.key;
                  return (
                    <button
                      key={item.key}
                      className={`ecdat-nav-item ${isActive ? "ecdat-nav-active" : ""}`}
                      onClick={() => {
                        onTabChange(item.key);
                        setMobileOpen(false);
                      }}
                      title={collapsed ? item.label : undefined}
                    >
                      <Icon size={18} />
                      {!collapsed && <span>{item.label}</span>}
                      {!collapsed && item.badge && (
                        <span className="ecdat-nav-badge">{item.badge}</span>
                      )}
                    </button>
                  );
                })}
              </div>
            ))}
          </div>

          <button
            className="ecdat-sidebar-collapse-btn"
            onClick={() => setCollapsed(!collapsed)}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            <ChevronLeft
              size={16}
              style={{ transform: collapsed ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}
            />
          </button>
        </nav>

        {/* ─── Mobile Overlay ─── */}
        {mobileOpen && (
          <div
            className="ecdat-mobile-overlay"
            onClick={() => setMobileOpen(false)}
          />
        )}

        {/* ─── Main Content ─── */}
        <main className="ecdat-main">
          {children}
        </main>
      </div>
    </div>
  );
}
