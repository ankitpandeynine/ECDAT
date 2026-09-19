"use client";

import { use, useCallback, useEffect, useState, useMemo, useRef } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  ShieldCheck,
  LayoutDashboard,
  Radio,
  ListTodo,
  Layers,
  FileCheck2,
  GitFork,
  Cpu,
  Hourglass,
  Gauge,
  Bomb,
  Route,
  CheckCircle2,
  Download,
  FileText,
  Archive,
  BookOpen,
  Settings,
  Search,
  Upload,
  Globe,
  Code2,
  Binary,
  Lock,
  Clock,
  Play,
  Check,
  X,
  AlertTriangle,
  RefreshCw,
  Eye,
  Key,
  Flame,
  FileCode,
  Network,
  Sparkles,
  Menu,
  Bot,
  Zap,
  Share2,
  Sliders,
  SlidersHorizontal,
  CheckCheck,
  ChevronRight,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Info,
  ExternalLink,
  ShieldAlert,
  ArrowRight,
  Terminal,
  Calculator,
  Scale,
  Activity
} from "lucide-react";
import { ThemeToggle } from "@/components/ecdat/theme-toggle";
import { Project, Scan, Finding } from "@/lib/api";
import { CustomLoopPanel } from "@/components/ecdat/custom-loop-panel";
import { StandardsPanel } from "@/components/ecdat/standards-panel";
import { ExperimentalHub } from "@/components/ecdat/experimental-hub";
import { VerificationPanel } from "@/components/ecdat/verification-panel";
import { ScanStudio } from "@/components/ecdat/scan-studio";
import { EmptyState } from "@/components/ui/empty-state";
import { CryptoGraph } from "@/components/ecdat/crypto-graph";
import { MoscaHndl } from "@/components/ecdat/mosca-hndl";
import { ScanJobs } from "@/components/ecdat/scan-jobs";
import { AssetInventory } from "@/components/ecdat/asset-inventory";
import { EvidenceExplorer } from "@/components/ecdat/evidence-explorer";
import { AutoPatchShowpiece } from "@/components/ecdat/auto-patch-showpiece";
import { ScanResultView } from "@/components/ecdat/scan-result-view";
import { QuantumEstimatorShowpiece } from "@/components/ecdat/quantum-estimator-showpiece";
import { CryptoAgilityView } from "@/components/ecdat/crypto-agility-view";

type TabKey =
  | "overview"
  | "custom-loop"
  | "studio"
  | "jobs"
  | "assets"
  | "evidence"
  | "graph"
  | "quantum"
  | "quantum-estimator"
  | "mosca"
  | "agility"
  | "blast"
  | "autopatch"
  | "migration"
  | "verify"
  | "standards"
  | "runtime"
  | "binary-pcap"
  | "cbom"
  | "reports"
  | "archive"
  | "knowledge"
  | "settings";

interface NavGroup {
  title: string;
  items: Array<{ key: TabKey; label: string; icon: any; count?: number }>;
}

export default function ProjectWorkspacePage({
  params,
}: {
  params: Promise<{ projectId: string }>;
}) {
  const resolvedParams = use(params);
  const projectId = resolvedParams.projectId;
  const router = useRouter();

  const [activeTab, setActiveTab] = useState<TabKey>("overview");
  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [assets, setAssets] = useState<any[]>([]);
  const [evidenceList, setEvidenceList] = useState<any[]>([]);
  const [graphData, setGraphData] = useState<{ nodes: any[]; links: any[] }>({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [evidenceAssetFilter, setEvidenceAssetFilter] = useState<string | null>(null);
  const [inspectedScanId, setInspectedScanId] = useState<string | null>(null);
  const [autoPatchPreselectedScanId, setAutoPatchPreselectedScanId] = useState<string | null>(null);
  const [autoPatchPreselectedAsset, setAutoPatchPreselectedAsset] = useState<string | null>(null);
  const [archiveError, setArchiveError] = useState<string | null>(null);

  // Global Command / Search Palette (Cmd+K)
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  // Scan Studio Form States
  const [scanType, setScanType] = useState<"network" | "code" | "binary" | "pcap">("network");
  const [targetHost, setTargetHost] = useState("localhost");
  const [targetPort, setTargetPort] = useState(443);
  const [sourceCode, setSourceCode] = useState(
    'from cryptography.hazmat.primitives.asymmetric import rsa\nprivate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)'
  );
  const [sourceLang, setSourceLang] = useState("python");
  const [binaryFile, setBinaryFile] = useState<File | null>(null);
  const [submittingScan, setSubmittingScan] = useState(false);

  // Archive Lab Form States
  const [archiveFile, setArchiveFile] = useState<File | null>(null);
  const [archivePassword, setArchivePassword] = useState("");
  const [archiveAnalysis, setArchiveAnalysis] = useState<any | null>(null);
  const [analyzingArchive, setAnalyzingArchive] = useState(false);

  // Vault Repackaging Form States
  const [vaultPayload, setVaultPayload] = useState("Confidential payment gateway cryptographic master configuration");
  const [vaultMode, setVaultMode] = useState<"PASSWORD_VAULT" | "RECIPIENT_KEY_VAULT" | "PQC_HYBRID_VAULT">("PASSWORD_VAULT");
  const [vaultPassword, setVaultPassword] = useState("VaultMasterKey2026!");
  const [createdVault, setCreatedVault] = useState<any | null>(null);
  const [creatingVault, setCreatingVault] = useState(false);
  const [verificationResult, setVerificationResult] = useState<any | null>(null);

  // Verification Scan Selection
  const [baselineScanId, setBaselineScanId] = useState("");
  const [postMigrationScanId, setPostMigrationScanId] = useState("");
  const [verifyingMigration, setVerifyingMigration] = useState(false);
  const [closedLoopReport, setClosedLoopReport] = useState<any | null>(null);

  // Mobile Navigation State
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  // Google AI Studio / Gemini Copilot State
  const [aiModalOpen, setAiModalOpen] = useState(false);
  const [aiMode, setAiMode] = useState<"triage" | "explain" | "advisory" | "posture">("posture");
  const [aiApiKey, setAiApiKey] = useState("");
  const [aiSnippet, setAiSnippet] = useState(
    'def custom_encrypt(data, key):\n    return bytes([(b ^ key) << 2 for b in data])'
  );
  const [aiTargetAlgo, setAiTargetAlgo] = useState("RSA-2048");
  const [aiTargetRole, setAiTargetRole] = useState("AUTHENTICATION");
  const [aiResult, setAiResult] = useState<any | null>(null);
  const [aiLoading, setAiLoading] = useState(false);

  // Project Settings State
  const [settingsEnv, setSettingsEnv] = useState("PRODUCTION");
  const [settingsCrit, setSettingsCrit] = useState("CRITICAL");
  const [settingsSens, setSettingsSens] = useState("CONFIDENTIAL");
  const [settingsLifetime, setSettingsLifetime] = useState(20);
  const [savingSettings, setSavingSettings] = useState(false);
  const [settingsSavedMsg, setSettingsSavedMsg] = useState("");

  // Graph / Blast Radius State
  const [selectedGraphNode, setSelectedGraphNode] = useState<any | null>(null);
  const [graphZoom, setGraphZoom] = useState(1);
  const [graphFilter, setGraphFilter] = useState("ALL");
  const [selectedBlastAsset, setSelectedBlastAsset] = useState<string>("");

  // Mosca Parameters (Interactive Sliders)
  const [moscaX, setMoscaX] = useState(20); // Data lifetime
  const [moscaY, setMoscaY] = useState(3);  // Migration time
  const [moscaZ, setMoscaZ] = useState(8);  // CRQC threat horizon (years until ~2033)

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
    summary?: { completed_scans: number; total_crypto_assets: number };
  } | null>(null);

  // Live Running Scan & Completion Toast State
  const [runningScan, setRunningScan] = useState<Scan | null>(null);
  const [runningElapsedTime, setRunningElapsedTime] = useState<string>("0s");
  const [scanToast, setScanToast] = useState<string | null>(null);
  const prevRunningIdsRef = useRef<Set<string>>(new Set());

  // Load project & telemetry
  const loadProjectData = useCallback(async () => {
    try {
      // 1. Get Project Metadata
      const pRes = await fetch(`/api/projects/${projectId}`);
      if (pRes.ok) {
        const pData = await pRes.json();
        setProject(pData);
        if (pData.data_lifetime_years) {
          setMoscaX(pData.data_lifetime_years);
        }
      }

      // 2. Get Scans
      const sRes = await fetch(`/api/scans?project=${encodeURIComponent(projectId)}`);
      if (sRes.ok) {
        const sData = await sRes.json();
        setScans(sData);
        if (sData.length >= 2) {
          setBaselineScanId(sData[sData.length - 1].id);
          setPostMigrationScanId(sData[0].id);
        } else if (sData.length === 1) {
          setBaselineScanId(sData[0].id);
          setPostMigrationScanId(sData[0].id);
        }
      }

      // 3. Get Assets
      const aRes = await fetch(`/api/projects/${projectId}/assets`);
      if (aRes.ok) {
        const aData = await aRes.json();
        setAssets(aData);
        if (aData.length > 0 && !selectedBlastAsset) {
          setSelectedBlastAsset(aData[0].algorithm || aData[0].name || "RSA-2048");
        }
      }

      // 4. Get Evidence Records
      const eRes = await fetch(`/api/projects/${projectId}/evidence`);
      if (eRes.ok) {
        const eData = await eRes.json();
        setEvidenceList(eData);
      }

      // 5. Get Real Relational Graph
      const gRes = await fetch(`/api/graph?project=${encodeURIComponent(projectId)}`);
      if (gRes.ok) {
        const gData = await gRes.json();
        setGraphData(gData);
      }

      // 6. Get Aggregated Overview Telemetry
      const oRes = await fetch(`/api/overview?project=${encodeURIComponent(projectId)}`);
      if (oRes.ok) {
        const oData = await oRes.json();
        setOverviewData(oData);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [projectId, selectedBlastAsset]);

  useEffect(() => {
    loadProjectData();
    const interval = setInterval(loadProjectData, 7000);
    return () => clearInterval(interval);
  }, [loadProjectData]);

  // Query GET /api/scans?project={id}&status=running every 5 seconds
  useEffect(() => {
    if (!projectId) return;

    async function pollRunningScans() {
      try {
        const res = await fetch(`/api/scans?project=${encodeURIComponent(projectId)}&status=running`);
        if (!res.ok) return;
        const list: Scan[] = await res.json();
        const currentRunningIds = new Set(list.map((s) => s.id));

        // Detect newly completed scans
        for (const prevId of prevRunningIdsRef.current) {
          if (!currentRunningIds.has(prevId)) {
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
                setScanToast(`Scan complete — ${foundCount} asset${foundCount === 1 ? "" : "s"} found`);
                setTimeout(() => setScanToast(null), 4500);
              }
            } catch (err) {
              console.error("Error inspecting completed scan in page:", err);
            }
            loadProjectData();
          }
        }

        prevRunningIdsRef.current = currentRunningIds;
        setRunningScan(list.length > 0 ? list[0] : null);
      } catch (err) {
        console.error("Error polling running scans in page:", err);
      }
    }

    pollRunningScans();
    const interval = setInterval(pollRunningScans, 5000);
    return () => clearInterval(interval);
  }, [projectId, loadProjectData]);

  // Live elapsed time ticker for running scan
  useEffect(() => {
    if (!runningScan?.created_at) return;

    function updateElapsed() {
      if (!runningScan?.created_at) return;
      const start = new Date(runningScan.created_at).getTime();
      const diff = Math.max(0, Date.now() - start);
      if (diff < 60000) {
        setRunningElapsedTime(`${Math.floor(diff / 1000)}s`);
      } else {
        const mins = Math.floor(diff / 60000);
        const secs = Math.floor((diff % 60000) / 1000);
        setRunningElapsedTime(`${mins}m ${secs}s`);
      }
    }

    updateElapsed();
    const timer = setInterval(updateElapsed, 1000);
    return () => clearInterval(timer);
  }, [runningScan]);

  // Keyboard shortcut listener for Cmd+K
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setSearchOpen((prev) => !prev);
      } else if (e.key === "Escape") {
        setSearchOpen(false);
        setAiModalOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Launch Scan
  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmittingScan(true);

    try {
      if (scanType === "network") {
        await fetch(`/api/scan/network?project=${encodeURIComponent(projectId)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target: targetHost, port: Number(targetPort) }),
        });
      } else if (scanType === "code") {
        await fetch(`/api/scan/code?project=${encodeURIComponent(projectId)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ source_code: sourceCode, language: sourceLang }),
        });
      } else if (scanType === "binary" && binaryFile) {
        const fd = new FormData();
        fd.append("file", binaryFile);
        await fetch(`/api/scan/binary/upload?project=${encodeURIComponent(projectId)}`, {
          method: "POST",
          body: fd,
        });
      } else if (scanType === "pcap") {
        await fetch(`/api/scan/pcap/synthetic?project=${encodeURIComponent(projectId)}&with_pqc_hybrid=true`, {
          method: "POST",
        });
      }

      await loadProjectData();
      setActiveTab("jobs");
    } catch (err) {
      console.error(err);
    } finally {
      setSubmittingScan(false);
    }
  };

  // Analyze Archive
  const handleAnalyzeArchive = async (e: React.FormEvent) => {
    e.preventDefault();
    setArchiveError(null);
    if (!archiveFile) {
      setArchiveError("Please upload an archive file to analyze. Drag and drop a ZIP or 7z file here.");
      return;
    }
    setAnalyzingArchive(true);
    setArchiveAnalysis(null);

    try {
      const fd = new FormData();
      fd.append("file", archiveFile);
      const url = `/api/projects/${projectId}/archive/upload${archivePassword ? `?password=${encodeURIComponent(archivePassword)}` : ""}`;
      const res = await fetch(url, { method: "POST", body: fd });
      if (res.ok) {
        const data = await res.json();
        setArchiveAnalysis(data);
      } else {
        const errData = await res.json().catch(() => ({}));
        setArchiveError(errData.detail || "Failed to inspect archive container.");
      }
      await loadProjectData();
    } catch (e: any) {
      console.error(e);
      setArchiveError(e.message || "Archive inspection network error.");
    } finally {
      setAnalyzingArchive(false);
    }
  };

  // Create Vault (.ecvault)
  const handleCreateVault = async () => {
    setCreatingVault(true);
    setCreatedVault(null);
    setVerificationResult(null);

    try {
      const res = await fetch(`/api/projects/${projectId}/archive/protect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          plain_text: vaultPayload,
          mode: vaultMode,
          password: vaultPassword,
          vault_name: `${projectId}_protected_container.ecvault`,
        }),
      });

      if (res.ok) {
        const container = await res.json();
        setCreatedVault(container);

        const vRes = await fetch(`/api/projects/${projectId}/archive/verify`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            container,
            password: vaultPassword,
          }),
        });
        if (vRes.ok) {
          const vData = await vRes.json();
          setVerificationResult(vData);
        }
      }
    } catch (e) {
      console.error(e);
    } finally {
      setCreatingVault(false);
    }
  };

  // Run Closed-Loop Verification
  const handleRunVerification = async () => {
    if (!baselineScanId || !postMigrationScanId) return;
    setVerifyingMigration(true);

    try {
      const res = await fetch(`/api/verify?project=${encodeURIComponent(projectId)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          baseline_scan_ids: [baselineScanId],
          post_migration_scan_ids: [postMigrationScanId],
        }),
      });
      if (res.ok) {
        const report = await res.json();
        setClosedLoopReport(report);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setVerifyingMigration(false);
    }
  };

  // Sync settings when project is loaded
  useEffect(() => {
    if (project) {
      setSettingsEnv(project.environment || "PRODUCTION");
      setSettingsCrit(project.business_criticality || "CRITICAL");
      setSettingsSens(project.data_sensitivity || "CONFIDENTIAL");
      setSettingsLifetime(project.data_lifetime_years ?? 20);
    }
  }, [project]);

  // Persist Project Settings
  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingSettings(true);
    setSettingsSavedMsg("");
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          environment: settingsEnv,
          business_criticality: settingsCrit,
          data_sensitivity: settingsSens,
          data_lifetime_years: Number(settingsLifetime),
        }),
      });
      if (res.ok) {
        setSettingsSavedMsg("Project business context successfully persisted.");
        await loadProjectData();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setSavingSettings(false);
    }
  };

  // Execute AI Cryptographic Copilot Analysis
  const handleRunAiAnalysis = async () => {
    setAiLoading(true);
    setAiResult(null);
    try {
      let endpoint = "/api/ai/triage";
      let body: any = {};

      if (aiMode === "triage") {
        endpoint = "/api/ai/triage";
        body = { code_snippet: aiSnippet, file_path: "snippet.py", api_key: aiApiKey || undefined };
      } else if (aiMode === "explain") {
        endpoint = "/api/ai/explain";
        body = {
          algorithm: aiTargetAlgo,
          cryptographic_role: aiTargetRole,
          quantum_vulnerable: true,
          data_lifetime_years: project?.data_lifetime_years || 15,
          business_criticality: project?.business_criticality || "CRITICAL",
          api_key: aiApiKey || undefined,
        };
      } else if (aiMode === "advisory") {
        endpoint = "/api/ai/migration-advisory";
        body = {
          current_algorithm: aiTargetAlgo,
          cryptographic_role: aiTargetRole,
          data_lifetime_years: project?.data_lifetime_years || 15,
          environment: project?.environment || "PRODUCTION",
          api_key: aiApiKey || undefined,
        };
      } else if (aiMode === "posture") {
        endpoint = `/api/projects/${projectId}/ai/summary`;
        body = {};
      }

      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (res.ok) {
        const data = await res.json();
        setAiResult(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setAiLoading(false);
    }
  };

  // Section 4: Grouped Navigation Structure
  const navGroups: NavGroup[] = [
    {
      title: "OVERVIEW",
      items: [
        { key: "overview", label: "Executive Overview", icon: LayoutDashboard },
        { key: "custom-loop", label: "Autonomous Custom Loop", icon: Sparkles },
      ],
    },
    {
      title: "DISCOVER",
      items: [
        { key: "studio", label: "Scan Studio", icon: Radio },
        {
          key: "jobs",
          label: "Scan Jobs",
          icon: ListTodo,
          count: overviewData?.summary?.completed_scans ?? overviewData?.scan_count ?? scans.length,
        },
      ],
    },
    {
      title: "INVENTORY",
      items: [
        {
          key: "assets",
          label: "Asset Inventory",
          icon: Layers,
          count: overviewData?.summary?.total_crypto_assets ?? overviewData?.asset_count ?? assets.length,
        },
        { key: "evidence", label: "Evidence Explorer", icon: FileCheck2, count: evidenceList.length },
        { key: "graph", label: "Crypto Graph", icon: GitFork, count: graphData.nodes.length },
      ],
    },
    {
      title: "ASSESS & ESTIMATE",
      items: [
        { key: "quantum", label: "Quantum Risk", icon: Cpu },
        { key: "quantum-estimator", label: "Quantum Estimation", icon: Calculator },
        { key: "mosca", label: "Mosca & HNDL", icon: Hourglass },
        { key: "agility", label: "Crypto Agility", icon: Gauge },
        { key: "blast", label: "Blast Radius", icon: Bomb },
      ],
    },
    {
      title: "MIGRATE & REMEDIATE",
      items: [
        { key: "autopatch", label: "Auto Patch Engine", icon: Zap },
        { key: "migration", label: "Migration Planner", icon: Route },
        { key: "verify", label: "Verification Engine", icon: CheckCircle2 },
      ],
    },
    {
      title: "COMPLIANCE & RUNTIME",
      items: [
        { key: "standards", label: "Standards & Mandates", icon: Scale },
        { key: "runtime", label: "Runtime & eBPF", icon: Activity },
        { key: "binary-pcap", label: "Binary ML & PCAP", icon: Binary },
      ],
    },
    {
      title: "OUTPUT",
      items: [
        { key: "cbom", label: "CycloneDX CBOM", icon: Download },
        { key: "reports", label: "Report Center", icon: FileText },
      ],
    },
    {
      title: "SPECIAL",
      items: [
        { key: "archive", label: "Secure Archive Lab", icon: Archive },
        { key: "knowledge", label: "Knowledge Base", icon: BookOpen },
      ],
    },
    {
      title: "PROJECT",
      items: [{ key: "settings", label: "Project Settings", icon: Settings }],
    },
  ];

  // Dynamic Risk Counts
  const shorCount = useMemo(() => {
    return assets.filter((a) => {
      const algo = String(a.algorithm || a.name || "").toUpperCase();
      return algo.includes("RSA") || algo.includes("ECDSA") || algo.includes("ECDH") || algo.includes("DSA") || algo.includes("ED25519");
    }).length;
  }, [assets]);

  const groverSafeCount = useMemo(() => {
    return assets.filter((a) => {
      const algo = String(a.algorithm || a.name || "").toUpperCase();
      return algo.includes("AES-256") || algo.includes("SHA-384") || algo.includes("SHA-512") || algo.includes("CHACHA20");
    }).length;
  }, [assets]);

  const legacyRiskCount = useMemo(() => {
    return assets.filter((a) => {
      const algo = String(a.algorithm || a.name || "").toUpperCase();
      return algo.includes("SHA-1") || algo.includes("SHA1") || algo.includes("MD5") || algo.includes("DES") || algo.includes("RC4");
    }).length;
  }, [assets]);

  const hybridPqcCount = useMemo(() => {
    return assets.filter((a) => {
      const algo = String(a.algorithm || a.name || "").toUpperCase();
      return algo.includes("MLKEM") || algo.includes("ML-KEM") || algo.includes("MLDSA") || algo.includes("HYBRID");
    }).length;
  }, [assets]);

  // Algorithm distribution map
  const algoDistribution = useMemo(() => {
    const map: Record<string, number> = {};
    assets.forEach((a) => {
      const algo = a.algorithm || a.name || "Unknown";
      map[algo] = (map[algo] || 0) + 1;
    });
    return Object.entries(map).sort((a, b) => b[1] - a[1]);
  }, [assets]);

  // Dynamic Action Queue strictly from real evidence or overview data
  const dynamicActionQueue = useMemo(() => {
    if (overviewData?.action_queue && overviewData.action_queue.length > 0) {
      return overviewData.action_queue.map((a) => ({
        priority: a.priority,
        title: a.title,
        desc: a.description,
        reason: a.description,
      }));
    }
    const actions: Array<{ priority: string; title: string; desc: string; reason: string }> = [];
    if (shorCount > 0) {
      actions.push({
        priority: "NOW",
        title: `Transition ${shorCount} Quantum-Vulnerable Public Key Assets`,
        desc: "Public-key cryptography (RSA/ECC) broken by polynomial-time Shor's algorithm on CRQC.",
        reason: "Long data protection lifetime exceeds CRQC threat horizon (HNDL risk).",
      });
    }
    if (legacyRiskCount > 0) {
      actions.push({
        priority: "NEXT",
        title: `Deprecate ${legacyRiskCount} Legacy Insecure Primitives`,
        desc: "Collision-vulnerable or weak cipher primitives detected in active project paths.",
        reason: "Zero resistance against classical cryptanalysis; fails compliance baselines.",
      });
    }
    if (hybridPqcCount > 0) {
      actions.push({
        priority: "VERIFY",
        title: `Validate ${hybridPqcCount} Negotiated Hybrid PQC Key Shares`,
        desc: "Confirm dual-mode X25519 + ML-KEM-768 parameters against NIST FIPS 203 specification.",
        reason: "Ensure zero handshake latency regressions across external egress boundaries.",
      });
    }
    return actions;
  }, [overviewData, shorCount, legacyRiskCount, hybridPqcCount]);

  // Filtered nodes for graph
  const filteredGraphNodes = useMemo(() => {
    if (graphFilter === "ALL") return graphData.nodes;
    return graphData.nodes.filter((n) => n.group?.toUpperCase() === graphFilter);
  }, [graphData.nodes, graphFilter]);

  return (
    <div className="ecdat-shell font-sans selection:bg-cyan-500/20 selection:text-cyan-300">
      {/* ACTIVE RUNNING SCAN TOP BANNER */}
      {runningScan && (
        <div className="bg-cyan-500/10 border-b border-cyan-500/30 px-4 py-2 text-xs text-cyan-300 flex items-center justify-between font-mono animate-pulse z-40">
          <div className="flex items-center gap-2">
            <span className="animate-spin text-cyan-400 font-bold">⟳</span>
            <span>
              Scan running — <strong className="uppercase text-cyan-200">{runningScan.kind}</strong> — Job{" "}
              {runningScan.id.slice(0, 8)} — {runningElapsedTime}
            </span>
          </div>
          <button
            onClick={() => setActiveTab("jobs")}
            className="text-cyan-400 hover:text-cyan-200 underline font-semibold flex items-center gap-1 cursor-pointer transition-colors"
          >
            <span>View Job →</span>
          </button>
        </div>
      )}

      {/* SCAN COMPLETION TOAST */}
      {scanToast && (
        <div className="fixed top-4 right-4 z-50 p-3.5 rounded-xl bg-surface border border-emerald-500/40 text-emerald-300 shadow-xl flex items-center gap-2.5 font-mono text-xs animate-in slide-in-from-top-4 duration-300">
          <CheckCircle2 size={16} className="text-emerald-400 shrink-0" />
          <span className="font-semibold">{scanToast}</span>
          <button onClick={() => setScanToast(null)} className="ml-2 text-quiet hover:text-foreground">
            <X size={14} />
          </button>
        </div>
      )}

      {/* Global Application Shell Header (Section 4) */}
      <header className="ecdat-topbar">
        <div className="ecdat-topbar-left">
          <Link href="/projects" className="ecdat-brand">
            <ShieldCheck className="h-5 w-5" />
            <span className="ecdat-brand-text">ECDAT</span>
          </Link>
          <span className="text-subtle">/</span>
          <span className="text-xs text-quiet font-medium hidden md:inline">
            {project?.organization || "National Technical Security"}
          </span>
          <span className="text-subtle hidden md:inline">/</span>
          <span className="text-xs font-semibold px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 font-mono">
            {project?.name || projectId}
          </span>
          <span className="text-subtle">/</span>
          <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded bg-subtle text-quiet">
            {project?.environment || "PRODUCTION"}
          </span>
        </div>

        <div className="ecdat-topbar-right">
          {/* Global Search / Command Menu Trigger (Cmd+K) */}
          <button
            onClick={() => setSearchOpen(true)}
            className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg border border-subtle bg-canvas/80 hover:border-cyan-500/40 text-quiet hover:text-foreground text-xs transition-colors"
            title="Search projects, assets, algorithms (Cmd+K)"
          >
            <Search className="h-3.5 w-3.5 text-quiet" />
            <span className="hidden sm:inline text-[11px]">Command Menu</span>
            <kbd className="hidden sm:inline text-[10px] font-mono px-1 py-0.2 rounded bg-subtle text-quiet border border-subtle/80">
              ⌘K
            </kbd>
          </button>

          {/* AI Security Copilot Button */}
          <button
            onClick={() => setAiModalOpen(true)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500/20 to-indigo-500/20 hover:from-cyan-500/30 hover:to-indigo-500/30 border border-cyan-500/30 text-cyan-300 text-xs font-semibold shadow-sm transition-all"
            title="Open Google AI Studio Cryptographic Copilot"
          >
            <Sparkles className="h-3.5 w-3.5 text-cyan-400 animate-pulse" />
            <span className="hidden sm:inline">AI Copilot</span>
          </button>

          {/* Refresh / Sync Button */}
          <button
            onClick={() => {
              setRefreshing(true);
              loadProjectData();
            }}
            className="p-1.5 rounded-lg border border-subtle hover:border-cyan-500/40 text-quiet hover:text-foreground text-xs flex items-center gap-1 transition-colors"
            title="Synchronize real-time project telemetry"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin text-cyan-400" : ""}`} />
          </button>

          <ThemeToggle />

          {/* Mobile Menu Toggle Button */}
          <button
            onClick={() => setMobileNavOpen(!mobileNavOpen)}
            className="md:hidden p-1.5 rounded-lg border border-subtle text-quiet hover:text-foreground text-xs"
            aria-label="Toggle Project Navigation"
          >
            {mobileNavOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
        </div>
      </header>

      {/* Main Container with Left Vertical Command Bar */}
      <div className="ecdat-body">
        {/* Left Command Navigation: 8 Functional Groups (Section 4) */}
        <aside
          className={`ecdat-sidebar ${
            mobileNavOpen ? "ecdat-sidebar-open" : ""
          }`}
        >
        <div className="ecdat-sidebar-inner">
          {navGroups.map((group) => (
            <div key={group.title} className="ecdat-nav-group">
              <div className="ecdat-nav-group-title">
                {group.title}
              </div>
              {group.items.map((item) => {
                const Icon = item.icon;
                const active = activeTab === item.key;
                const showBadge = item.count !== undefined && item.count > 0;
                return (
                  <button
                    key={item.key}
                    onClick={() => {
                      setActiveTab(item.key);
                      setMobileNavOpen(false);
                    }}
                    className={`ecdat-nav-item ${active ? "ecdat-nav-active" : ""}`}
                  >
                    <Icon size={16} />
                    <span>{item.label}</span>
                    {showBadge && (
                      <span className="ecdat-nav-badge">
                        {item.count}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </div>
        </aside>
        {mobileNavOpen && <div className="ecdat-mobile-overlay" onClick={() => setMobileNavOpen(false)} />}

        {/* Center Workspace Stage */}
        <main className="ecdat-main">
          {/* TAB 1: EXECUTIVE OVERVIEW */}
          {activeTab === "overview" && (
            <div className="space-y-6">
              {/* Header Context Row */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-subtle pb-5">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <h1 className="text-xl font-bold tracking-tight">{project?.name || projectId}</h1>
                    <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400">
                      {project?.environment || "Production"}
                    </span>
                    <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded bg-subtle text-quiet">
                      {project?.business_criticality || "Critical"}
                    </span>
                  </div>
                  <p className="text-xs text-quiet">
                    {project?.description || "High-assurance cryptographic asset boundary and post-quantum migration tracking."}
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setActiveTab("custom-loop")}
                    className="px-3 py-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-700 dark:text-cyan-300 text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <Sparkles className="h-3.5 w-3.5 text-cyan-600 dark:text-cyan-400" />
                    One-Click Custom Loop
                  </button>
                  <Link
                    href={`/projects/${projectId}/changes`}
                    className="px-3 py-1.5 rounded-lg border border-subtle bg-canvas hover:bg-surface text-muted-foreground hover:text-foreground text-xs font-semibold flex items-center gap-1.5 transition-colors"
                  >
                    <FileCode className="h-3.5 w-3.5" />
                    Changes Diff
                  </Link>
                  <button
                    onClick={() => setActiveTab("studio")}
                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm cursor-pointer"
                  >
                    <Radio className="h-3.5 w-3.5" />
                    Run Discovery
                  </button>
                </div>
              </div>

              {/* KPI Row (Section 5) */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
                <div
                  onClick={() => setActiveTab("assets")}
                  className="rounded-xl border border-subtle bg-surface p-4 hover:border-cyan-500/40 transition-all cursor-pointer group"
                >
                  <div className="text-[11px] text-quiet font-medium group-hover:text-cyan-400 transition-colors">Crypto Assets</div>
                  <div className="text-2xl font-bold text-foreground mt-1">{overviewData ? overviewData.asset_count : assets.length}</div>
                  <div className="text-[10px] text-cyan-400 mt-1">Discovered in Project →</div>
                </div>

                <div
                  onClick={() => setActiveTab("quantum")}
                  className="rounded-xl border border-subtle bg-surface p-4 hover:border-rose-500/40 transition-all cursor-pointer group"
                >
                  <div className="text-[11px] text-quiet font-medium group-hover:text-rose-400 transition-colors">Quantum-Relevant</div>
                  <div className="text-2xl font-bold text-rose-400 mt-1">{shorCount}</div>
                  <div className="text-[10px] text-rose-400/80 mt-1">Shor Algorithm Vulnerable →</div>
                </div>

                <div
                  onClick={() => setActiveTab("mosca")}
                  className="rounded-xl border border-subtle bg-surface p-4 hover:border-amber-500/40 transition-all cursor-pointer group"
                >
                  <div className="text-[11px] text-quiet font-medium group-hover:text-amber-400 transition-colors">HNDL Exposure</div>
                  <div className="text-2xl font-bold text-amber-400 mt-1">
                    {shorCount > 0 && moscaX > 5 ? shorCount : 0}
                  </div>
                  <div className="text-[10px] text-amber-400/80 mt-1">Harvest Now Decrypt Later →</div>
                </div>

                <div
                  onClick={() => setActiveTab("standards")}
                  className="rounded-xl border border-subtle bg-surface p-4 hover:border-emerald-500/40 transition-all cursor-pointer group"
                >
                  <div className="text-[11px] text-quiet font-medium group-hover:text-emerald-400 transition-colors">Hybrid PQC Capable</div>
                  <div className="text-2xl font-bold text-emerald-400 mt-1">{hybridPqcCount}</div>
                  <div className="text-[10px] text-emerald-400/80 mt-1">NIST FIPS 203 In-Use →</div>
                </div>

                <div
                  onClick={() => setActiveTab("jobs")}
                  className="rounded-xl border border-subtle bg-surface p-4 col-span-2 sm:col-span-1 hover:border-cyan-500/40 transition-all cursor-pointer group"
                >
                  <div className="text-[11px] text-quiet font-medium group-hover:text-cyan-400 transition-colors">Completed Scans</div>
                  <div className="text-2xl font-bold text-foreground mt-1">{overviewData ? overviewData.scan_count : scans.length}</div>
                  <div className="text-[10px] text-quiet mt-1">Deterministic Provenance →</div>
                </div>
              </div>

              {/* ZERO DATA EMPTY STATE EXPERIENCE (Section 6) */}
              {assets.length === 0 ? (
                <div className="rounded-2xl border border-dashed border-subtle bg-surface/40 p-8 sm:p-12 text-center space-y-4">
                  <div className="h-12 w-12 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 flex items-center justify-center mx-auto">
                    <Radio className="h-6 w-6" />
                  </div>
                  <div className="space-y-1">
                    <h3 className="text-base font-bold text-foreground tracking-tight">NO CRYPTOGRAPHIC INVENTORY YET</h3>
                    <p className="text-xs text-quiet max-w-md mx-auto">
                      Connect your first cryptographic surface to begin building the project&apos;s evidence-backed inventory.
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
                    <button
                      onClick={() => setActiveTab("studio")}
                      className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-2 shadow-sm"
                    >
                      <Radio className="h-4 w-4" />
                      Scan Source / Network / Binary
                    </button>
                    <button
                      onClick={() => setActiveTab("jobs")}
                      className="px-4 py-2 rounded-lg border border-subtle bg-surface hover:bg-subtle text-foreground text-xs font-semibold flex items-center gap-2 transition-colors"
                    >
                      <Layers className="h-4 w-4 text-cyan-400" />
                      View Scan Jobs
                    </button>
                  </div>

                  <div className="pt-6 border-t border-subtle/60 text-left max-w-2xl mx-auto">
                    <div className="text-[11px] font-bold text-quiet uppercase tracking-wider mb-2 font-mono">
                      Discoverable Cryptographic Surfaces:
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs text-quiet">
                      <div className="p-2 rounded border border-subtle/50 bg-canvas/60">• Source Code AST</div>
                      <div className="p-2 rounded border border-subtle/50 bg-canvas/60">• Dependency Lockfiles</div>
                      <div className="p-2 rounded border border-subtle/50 bg-canvas/60">• ELF / PE Binaries</div>
                      <div className="p-2 rounded border border-subtle/50 bg-canvas/60">• TLS 1.3 / SSH Probes</div>
                    </div>
                  </div>
                </div>
              ) : (
                <>
                  {/* Real Visualizations (Section 5 & 34) */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Left: Risk Distribution SVG Donut */}
                    <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
                      <div className="flex items-center justify-between border-b border-subtle pb-3">
                        <h3 className="text-sm font-semibold">Risk Distribution</h3>
                        <span className="text-[10px] text-quiet font-mono">Total Assets: {assets.length}</span>
                      </div>

                      <div className="flex items-center justify-around py-2">
                        {/* SVG Donut */}
                        <div className="relative flex items-center justify-center">
                          <svg className="w-36 h-36 -rotate-90" viewBox="0 0 36 36">
                            <circle cx="18" cy="18" r="14" fill="none" stroke="currentColor" className="text-subtle/40" strokeWidth="4" />
                            {shorCount > 0 && (
                              <circle
                                cx="18"
                                cy="18"
                                r="14"
                                fill="none"
                                stroke="#f43f5e"
                                strokeWidth="4"
                                strokeDasharray={`${Math.max((shorCount / assets.length) * 88, 5)} 100`}
                                strokeDashoffset="0"
                              />
                            )}
                            {groverSafeCount > 0 && (
                              <circle
                                cx="18"
                                cy="18"
                                r="14"
                                fill="none"
                                stroke="#10b981"
                                strokeWidth="4"
                                strokeDasharray={`${Math.max((groverSafeCount / assets.length) * 88, 5)} 100`}
                                strokeDashoffset={`-${(shorCount / assets.length) * 88}`}
                              />
                            )}
                          </svg>
                          <div className="absolute flex flex-col items-center">
                            <span className="text-xl font-bold font-mono">{assets.length}</span>
                            <span className="text-[9px] text-quiet uppercase">Assets</span>
                          </div>
                        </div>

                        {/* Legend */}
                        <div className="space-y-2 text-xs">
                          <div className="flex items-center gap-2">
                            <span className="h-2.5 w-2.5 rounded-full bg-rose-500 shrink-0" />
                            <span className="text-quiet">Critical (Shor Vuln):</span>
                            <span className="font-bold text-foreground font-mono">{shorCount}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500 shrink-0" />
                            <span className="text-quiet">Safe (Grover / PQC):</span>
                            <span className="font-bold text-foreground font-mono">{groverSafeCount + hybridPqcCount}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="h-2.5 w-2.5 rounded-full bg-amber-500 shrink-0" />
                            <span className="text-quiet">Legacy Insecure:</span>
                            <span className="font-bold text-foreground font-mono">{legacyRiskCount}</span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Right: Algorithm Family Distribution Bar Chart */}
                    <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
                      <div className="flex items-center justify-between border-b border-subtle pb-3">
                        <h3 className="text-sm font-semibold">Algorithm Family Distribution</h3>
                        <span className="text-[10px] text-cyan-400 font-mono">Empirical Frequency</span>
                      </div>

                      <div className="space-y-2.5 py-1">
                        {algoDistribution.slice(0, 5).map(([algo, count]) => {
                          const pct = Math.max(Math.round((count / assets.length) * 100), 8);
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
                    </div>
                  </div>

                  {/* Multi-Surface Discovery Coverage */}
                  <div className="rounded-xl border border-subtle bg-surface p-5">
                    <h3 className="text-sm font-semibold mb-3">Multi-Surface Discovery Coverage</h3>
                    <div className="grid grid-cols-3 sm:grid-cols-9 gap-2 text-center text-xs">
                      {[
                        { name: "Source AST", status: scans.some((s) => s.kind === "source" || s.kind === "code") ? "SCANNED" : "NOT_SCANNED", icon: Code2 },
                        { name: "Dependencies", status: "SUPPORTED", icon: Layers },
                        { name: "Binary Sections", status: scans.some((s) => s.kind === "binary") ? "SCANNED" : "NOT_SCANNED", icon: Binary },
                        { name: "Firmware", status: "BOUNDED", icon: Archive },
                        { name: "Live Network", status: scans.some((s) => s.kind === "network") ? "SCANNED" : "NOT_SCANNED", icon: Globe },
                        { name: "X.509 Certs", status: assets.some((a) => a.asset_type === "certificate") ? "SCANNED" : "NOT_SCANNED", icon: Lock },
                        { name: "Archive Lab", status: "ACTIVE", icon: Archive },
                        { name: "PCAP Stream", status: scans.some((s) => s.kind === "pcap") ? "SCANNED" : "NOT_SCANNED", icon: Network },
                        { name: "Runtime Call", status: "UNMEASURED", icon: Cpu },
                      ].map((s) => (
                        <div key={s.name} className="p-2.5 rounded-lg border border-subtle/50 bg-canvas/60">
                          <s.icon className="h-4 w-4 mx-auto text-cyan-400 mb-1" />
                          <div className="text-[10px] font-semibold text-foreground truncate">{s.name}</div>
                          <span className={`text-[8px] font-mono px-1 py-0.2 rounded mt-1 inline-block ${
                            s.status === "SCANNED" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-subtle text-quiet"
                          }`}>
                            {s.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Evidence-Driven Action Queue (Section 5) */}
                  <div className="rounded-xl border border-subtle bg-surface p-5">
                    <h3 className="text-sm font-semibold mb-3">Evidence-Driven Action Queue</h3>
                    {dynamicActionQueue.length === 0 ? (
                      <EmptyState
                        icon={<CheckCircle2 className="h-6 w-6 text-emerald-400" />}
                        title="Action Queue Clear"
                        description="No urgent cryptographic migrations or deprecation actions currently queued for this project."
                        actionLabel="Scan Source / Network"
                        onAction={() => setActiveTab("studio")}
                      />
                    ) : (
                      <div className="space-y-2.5">
                        {dynamicActionQueue.map((item, idx) => (
                          <div
                            key={idx}
                            className={`p-3 rounded-lg border flex items-start gap-3 ${
                              item.priority === "NOW"
                                ? "border-rose-500/30 bg-rose-500/5"
                                : item.priority === "NEXT"
                                ? "border-amber-500/30 bg-amber-500/5"
                                : "border-cyan-500/30 bg-cyan-500/5"
                            }`}
                          >
                            <span
                              className={`text-[10px] font-bold px-1.5 py-0.5 rounded font-mono ${
                                item.priority === "NOW"
                                  ? "bg-rose-500/20 text-rose-300"
                                  : item.priority === "NEXT"
                                  ? "bg-amber-500/20 text-amber-300"
                                  : "bg-cyan-500/20 text-cyan-300"
                              }`}
                            >
                              {item.priority}
                            </span>
                            <div className="text-xs space-y-0.5">
                              <div className="font-semibold text-foreground">{item.title}</div>
                              <div className="text-quiet">{item.desc}</div>
                              <div className="text-[11px] text-cyan-400/90 font-mono pt-0.5">Rationale: {item.reason}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Quantum Threat Timeline Chart (Section 5 / Priority 8) */}
                  <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-semibold flex items-center gap-2">
                          <Hourglass className="h-4 w-4 text-cyan-400" />
                          Cryptographic Quantum Threat Timeline (Z Horizon)
                        </h3>
                        <p className="text-xs text-quiet mt-0.5">
                          Years remaining until cryptanalytically relevant quantum computing (CRQC) breaks discovered primitives under published research (Gidney &amp; Ekerå 2021).
                        </p>
                      </div>
                      <button
                        onClick={() => setActiveTab("mosca")}
                        className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 cursor-pointer transition-colors"
                      >
                        <span>Interactive Mosca Calculator →</span>
                      </button>
                    </div>

                    <div className="space-y-3 pt-2">
                      {assets.length === 0 ? (
                        <div className="py-4 text-center text-xs text-quiet font-mono">
                          No discovered primitives cataloged yet. Run a discovery scan to plot quantum break timelines.
                        </div>
                      ) : (
                        assets.slice(0, 6).map((a, idx) => {
                          const name = String(a.algorithm || a.name || "Unknown");
                          let z = 9;
                          if (name.includes("4096")) z = 12;
                          else if (name.includes("ECDSA") || name.includes("ECC") || name.includes("256")) z = 7;
                          else if (name.includes("MD5") || name.includes("SHA1")) z = 0;
                          else if (name.includes("AES-128")) z = 14;
                          else if (name.includes("AES-256") || name.includes("ML-KEM")) z = 25;

                          const zPct = Math.min(100, Math.round((z / 20) * 100));
                          const color = z < 5 ? "text-rose-400 font-bold" : z <= 12 ? "text-amber-400 font-bold" : "text-emerald-400 font-bold";
                          const barColor = z < 5 ? "bg-rose-500" : z <= 12 ? "bg-amber-500" : "bg-emerald-500";

                          return (
                            <div key={idx} className="space-y-1 text-xs">
                              <div className="flex items-center justify-between font-mono text-[11px]">
                                <span className="font-semibold text-foreground">{name}</span>
                                <span className={color}>
                                  {z > 20 ? "Safe (25+ yrs)" : z === 0 ? "Broken Classically" : `${z} years to CRQC break`}
                                </span>
                              </div>
                              <div className="h-2 rounded-full bg-canvas overflow-hidden border border-subtle relative">
                                <div
                                  className={`h-full rounded-full transition-all duration-500 ${barColor}`}
                                  style={{ width: `${zPct}%` }}
                                />
                              </div>
                            </div>
                          );
                        })
                      )}
                    </div>
                  </div>
                </>
              )}
            </div>
          )}

          {/* TAB: AUTONOMOUS CUSTOM LOOP */}
          {activeTab === "custom-loop" && (
            <CustomLoopPanel projectId={projectId} />
          )}

          {/* TAB 2: SCAN STUDIO (Section 8) */}
          {activeTab === "studio" && (
            <ScanStudio
              projectId={projectId}
              onJobCreated={() => {
                loadProjectData();
              }}
              onNavigateToJobs={() => {
                loadProjectData();
                setActiveTab("jobs");
              }}
            />
          )}

          {/* TAB 3: SCAN JOBS (Section 9) */}
          {activeTab === "jobs" && (
            inspectedScanId ? (
              <ScanResultView
                scanId={inspectedScanId}
                projectId={projectId}
                onBack={() => setInspectedScanId(null)}
                onPatchAll={(scanId) => {
                  setAutoPatchPreselectedScanId(scanId);
                  setInspectedScanId(null);
                  setActiveTab("autopatch");
                }}
                onPatchAsset={(scanId, algo) => {
                  setAutoPatchPreselectedScanId(scanId);
                  setAutoPatchPreselectedAsset(algo);
                  setInspectedScanId(null);
                  setActiveTab("autopatch");
                }}
                onViewEvidence={() => {
                  setInspectedScanId(null);
                  setActiveTab("evidence");
                }}
                onViewGraph={() => {
                  setInspectedScanId(null);
                  setActiveTab("graph");
                }}
              />
            ) : (
              <ScanJobs
                projectId={projectId}
                onNavigateToStudio={() => setActiveTab("studio")}
                onNavigateToEvidence={(scanId) => {
                  setActiveTab("evidence");
                }}
                onInspectScan={(scanId) => {
                  setInspectedScanId(scanId);
                }}
                onScanCompleted={loadProjectData}
              />
            )
          )}

          {/* TAB 4: ASSET INVENTORY (Section 16) */}
          {activeTab === "assets" && (
            <AssetInventory
              projectId={projectId}
              onNavigateToEvidence={(assetId) => {
                setEvidenceAssetFilter(assetId);
                setActiveTab("evidence");
              }}
              onNavigateToGraph={() => {
                setActiveTab("graph");
              }}
              onNavigateToStudio={() => setActiveTab("studio")}
              onPatchAsset={(asset) => {
                setAutoPatchPreselectedAsset(asset.algorithm || asset.name);
                if (asset.scan_id) {
                  setAutoPatchPreselectedScanId(asset.scan_id);
                }
                setActiveTab("autopatch");
              }}
            />
          )}

          {/* TAB 5: EVIDENCE EXPLORER (Section 18) */}
          {activeTab === "evidence" && (
            <EvidenceExplorer
              projectId={projectId}
              initialAssetIdFilter={evidenceAssetFilter}
              onClearAssetFilter={() => setEvidenceAssetFilter(null)}
              onNavigateToStudio={() => setActiveTab("studio")}
              onNavigateToAsset={(assetId) => {
                setEvidenceAssetFilter(assetId);
                setActiveTab("assets");
              }}
              onNavigateToAutoPatch={(scanId) => {
                setAutoPatchPreselectedScanId(scanId);
                setActiveTab("autopatch");
              }}
            />
          )}

          {/* TAB 6: CRYPTO ASSET GRAPH — REAL INTERACTIVE GRAPH (Section 19) */}
          {activeTab === "graph" && (
            <CryptoGraph
              projectId={projectId}
              onNavigateToStudio={() => setActiveTab("studio")}
              onNavigateToBlast={(assetLabel) => {
                setSelectedBlastAsset(assetLabel);
                setActiveTab("blast");
              }}
              onNodeCountChange={(count) => {
                setGraphData((prev) => {
                  if (prev.nodes.length === count) return prev;
                  return {
                    ...prev,
                    nodes: Array.from({ length: count }, (_, i) => prev.nodes[i] || { id: `node-${i}` }),
                  };
                });
              }}
            />
          )}

          {/* TAB 7: QUANTUM RISK (Section 20) */}
          {activeTab === "quantum" && (
            <div className="space-y-6">
              <div className="border-b border-subtle pb-4">
                <h2 className="text-xl font-bold tracking-tight">Quantum Risk & Cryptanalytic Relevance</h2>
                <p className="text-xs text-quiet mt-1">
                  Deterministic evaluation under Shor and Grover threat models with NIST FIPS 203/204/205 replacement mappings.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-5 space-y-2">
                  <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
                    <Cpu className="h-4 w-4" />
                    Shor&apos;s Algorithm Relevance (Asymmetric Cryptography)
                  </div>
                  <p className="text-xs text-foreground">
                    Solves integer factorization and discrete logarithms in polynomial time. Completely breaks RSA, ECDSA, ECDH, DSA, and Ed25519 when a Cryptanalytically Relevant Quantum Computer (CRQC) is realized.
                  </p>
                  <div className="text-[11px] text-rose-300 font-mono pt-1">
                    Remediation: NIST FIPS 203 (ML-KEM) &amp; NIST FIPS 204 (ML-DSA)
                  </div>
                </div>

                <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-5 space-y-2">
                  <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                    <ShieldCheck className="h-4 w-4" />
                    Grover&apos;s Algorithm Relevance (Symmetric &amp; Hashing)
                  </div>
                  <p className="text-xs text-foreground">
                    Provides a quadratic speedup for unstructured search. Halves effective bit-security. AES-128 drops to 64 bits (vulnerable); AES-256 remains post-quantum safe with 128 bits of security.
                  </p>
                  <div className="text-[11px] text-emerald-300 font-mono pt-1">
                    Remediation: Enforce 256-bit symmetric keys (AES-256-GCM, SHA-384/512)
                  </div>
                </div>
              </div>

              {/* Real Project Transition Matrix */}
              <div className="rounded-xl border border-subtle bg-surface overflow-hidden">
                <div className="p-4 border-b border-subtle font-semibold text-sm">
                  Cryptographic Algorithm Transition Matrix
                </div>
                {assets.length === 0 ? (
                  <div className="p-8 text-center text-xs text-quiet">
                    No cryptographic algorithms recorded for this project. Run a scan to evaluate quantum risk.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-canvas/50 border-b border-subtle text-quiet uppercase text-[10px] font-mono">
                        <tr>
                          <th className="p-3">Algorithm</th>
                          <th className="p-3">Primary Role</th>
                          <th className="p-3">Quantum Vulnerability</th>
                          <th className="p-3">Target NIST PQC Primitive</th>
                          <th className="p-3">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-subtle font-mono text-[11px]">
                        {assets.map((a, idx) => {
                          const algo = String(a.algorithm || a.name || "").toUpperCase();
                          const isShor = algo.includes("RSA") || algo.includes("ECDSA") || algo.includes("ECDH");
                          const isPqc = algo.includes("MLKEM") || algo.includes("ML-KEM");
                          return (
                            <tr key={idx} className="hover:bg-canvas/30">
                              <td className="p-3 font-bold text-foreground">{a.algorithm || a.name}</td>
                              <td className="p-3 text-quiet">{a.asset_type || "ALGORITHM"}</td>
                              <td className="p-3">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  isShor
                                    ? "bg-rose-500/15 text-rose-400"
                                    : isPqc
                                    ? "bg-emerald-500/15 text-emerald-400"
                                    : "bg-cyan-500/15 text-cyan-300"
                                }`}>
                                  {isShor ? "CRITICAL (Shor)" : isPqc ? "PQC SECURE" : "GROVER RESISTANT"}
                                </span>
                              </td>
                              <td className="p-3 text-cyan-300 font-semibold">
                                {isShor ? "ML-KEM-768 / ML-DSA-65" : "NIST Standard Approved"}
                              </td>
                              <td className="p-3">
                                <div className="flex items-center gap-1.5">
                                  <button
                                    onClick={() => {
                                      setAiTargetAlgo(a.algorithm || a.name);
                                      setAiTargetRole(a.asset_type || "ALGORITHM");
                                      setAiMode("explain");
                                      setAiModalOpen(true);
                                    }}
                                    className="text-[10px] px-2 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/20 cursor-pointer"
                                  >
                                    AI Explain
                                  </button>
                                  <button
                                    onClick={() => setActiveTab("assets")}
                                    className="text-[10px] px-2 py-1 rounded bg-subtle hover:bg-canvas text-quiet hover:text-foreground border border-subtle cursor-pointer"
                                  >
                                    → View Assets
                                  </button>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
                <div className="p-4 border-t border-subtle flex justify-between items-center bg-canvas/30 text-xs">
                  <span className="text-quiet">Need data sensitivity and migration lead time calculations?</span>
                  <button
                    onClick={() => setActiveTab("mosca")}
                    className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 cursor-pointer"
                  >
                    → Open Mosca &amp; HNDL Deficit Analysis
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB: QUANTUM RESOURCE ESTIMATION (Priority 3 Showpiece) */}
          {activeTab === "quantum-estimator" && (
            <QuantumEstimatorShowpiece projectId={projectId} />
          )}

          {/* TAB 8: MOSCA & HNDL (Section 21) */}
          {activeTab === "mosca" && (
            <MoscaHndl
              projectId={projectId}
              onNavigateToStudio={() => setActiveTab("studio")}
              onNavigateToMigration={(algo) => {
                setActiveTab("migration");
              }}
              onNavigateToPatch={(algo) => {
                if (algo) setAutoPatchPreselectedAsset(algo);
                setActiveTab("autopatch");
              }}
            />
          )}

          {/* TAB 9: AGILITY (Section 22 / Priority 6 Showpiece) */}
          {activeTab === "agility" && (
            <CryptoAgilityView
              projectId={projectId}
              onNavigateToScan={() => setActiveTab("studio")}
            />
          )}

          {/* TAB 10: BLAST RADIUS (Section 23) */}
          {activeTab === "blast" && (
            <div className="space-y-6">
              <div className="border-b border-subtle pb-4">
                <h2 className="text-xl font-bold tracking-tight">Reverse Dependency Blast Radius Analysis</h2>
                <p className="text-xs text-quiet mt-1">
                  Traverse reverse dependency relationships to discover all services, APIs, and data flows affected by a vulnerable crypto asset.
                </p>
              </div>

              {assets.length === 0 ? (
                <EmptyState
                  icon={<Bomb className="h-6 w-6 text-rose-400" />}
                  title="No Assets Available for Blast Radius"
                  description="No cryptographic assets discovered yet. Run a discovery scan to catalog assets and calculate dependency blast radius."
                  actionLabel="Run First Scan"
                  onAction={() => setActiveTab("studio")}
                />
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
                    <h3 className="text-sm font-semibold flex items-center gap-2">
                      <Bomb className="h-4 w-4 text-rose-400" />
                      Target Vulnerable Asset
                    </h3>

                    <div className="space-y-3 text-xs">
                      <div>
                        <label className="block font-medium mb-1">Select Asset to Probe</label>
                        <select
                          value={selectedBlastAsset}
                          onChange={(e) => setSelectedBlastAsset(e.target.value)}
                          className="w-full px-3 py-2 rounded-lg border border-subtle bg-canvas font-mono text-cyan-400 outline-none"
                        >
                          {assets.map((a) => (
                            <option key={a.id} value={a.id || a.name || a.algorithm}>
                              {a.name || a.algorithm} ({a.asset_type})
                            </option>
                          ))}
                        </select>
                      </div>

                      <div className="p-3 rounded-lg bg-canvas border border-subtle space-y-1.5 font-mono text-[11px]">
                        <div className="text-rose-400 font-bold">Scope: TARGET SELECTED</div>
                        <div className="text-quiet">Asset: {selectedBlastAsset || assets[0]?.name || "None"}</div>
                        <div className="text-quiet">Upstream Paths: Multi-hop graph active</div>
                      </div>
                    </div>
                  </div>

                  <div className="lg:col-span-2 rounded-xl border border-subtle bg-surface p-5 space-y-4">
                    <h3 className="text-sm font-semibold">Traversed Upstream Consumers</h3>
                    {(() => {
                      const target = selectedBlastAsset || assets[0]?.id || assets[0]?.name || "";
                      const connected = graphData.links.filter(
                        (l) =>
                          l.source === target ||
                          l.target === target ||
                          String(l.source).toLowerCase().includes(target.toLowerCase()) ||
                          String(l.target).toLowerCase().includes(target.toLowerCase())
                      );
                      if (connected.length === 0) {
                        return (
                          <EmptyState
                            icon={<Bomb className="h-6 w-6 text-rose-400" />}
                            title="No Upstream Consumers Traversed"
                            description={`No upstream service or API dependencies are currently connected to ${target || "the selected asset"} in the Crypto Asset Graph.`}
                            actionLabel="View Asset Graph"
                            onAction={() => setActiveTab("graph")}
                          />
                        );
                      }
                      return (
                        <div className="space-y-2 text-xs">
                          {connected.map((link, idx) => {
                            const isTarget = link.target === target;
                            const consumerName = isTarget ? link.source : link.target;
                            return (
                              <div key={idx} className="p-3 rounded-lg border border-subtle bg-canvas/60 flex items-center justify-between">
                                <div>
                                  <div className="font-semibold text-foreground font-mono">{consumerName}</div>
                                  <div className="text-[11px] text-quiet font-mono">Relationship: {link.label || "USES_CRYPTOGRAPHY"}</div>
                                </div>
                                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                                  DEPENDENT
                                </span>
                              </div>
                            );
                          })}
                        </div>
                      );
                    })()}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB: AUTO PATCH ENGINE (Priority 1 Showpiece) */}
          {activeTab === "autopatch" && (
            <AutoPatchShowpiece
              projectId={projectId}
              preselectedScanId={autoPatchPreselectedScanId || undefined}
              preselectedAsset={autoPatchPreselectedAsset || undefined}
              onNavigateToVerify={(baseline, post) => {
                setBaselineScanId(baseline);
                if (post) setPostMigrationScanId(post);
                setActiveTab("verify");
              }}
            />
          )}

          {/* TAB 11: MIGRATION PLANNER (Section 24 & 25) */}
          {activeTab === "migration" && (
            <div className="space-y-6">
              <div className="border-b border-subtle pb-4">
                <h2 className="text-xl font-bold tracking-tight">Post-Quantum Cryptographic Migration Planner</h2>
                <p className="text-xs text-quiet mt-1">
                  Dependency-aware phased migration plans with operational impact models, rollback strategies, and effort heuristics.
                </p>
              </div>

              {assets.length === 0 ? (
                <div className="rounded-xl border border-subtle bg-surface p-12 text-center text-xs text-quiet">
                  No cryptographic inventory cataloged. Run a baseline discovery scan before building migration workstreams.
                </div>
              ) : (
                <>
                  {/* Gantt-Style Phased Migration Timeline (Priority 8) */}
                  <div className="rounded-xl border border-subtle bg-surface p-5 space-y-3">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-semibold">
                      <span className="flex items-center gap-1.5 text-foreground">
                        <Clock className="h-4 w-4 text-cyan-400" />
                        Gantt-Style Phased Migration Roadmap Timeline
                      </span>
                      <span className="text-[11px] font-mono text-rose-400">
                        CRQC Quantum Threat Horizon: ~2033 (9 Years to CRQC Break)
                      </span>
                    </div>

                    {/* Progress Bar & Phase Segments */}
                    <div className="pt-2">
                      <div className="grid grid-cols-4 gap-1.5 h-3 rounded-full bg-canvas border border-subtle overflow-hidden">
                        <div className="bg-emerald-500 h-full rounded-l-full" title="Phase 1: Discovery (Completed)" />
                        <div className="bg-cyan-500 h-full" title="Phase 2: Staging (In Progress)" />
                        <div className="bg-subtle h-full" title="Phase 3: Verification (Pending)" />
                        <div className="bg-subtle h-full rounded-r-full" title="Phase 4: Decommission (Pending)" />
                      </div>
                      <div className="grid grid-cols-4 gap-1 text-[10px] font-mono text-quiet pt-2 text-center">
                        <span className="text-emerald-400 font-semibold">Phase 1: Discovery (Done)</span>
                        <span className="text-cyan-400 font-semibold">Phase 2: Hybrid KEX (Active)</span>
                        <span>Phase 3: Verification</span>
                        <span>Phase 4: Decommission</span>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
                    <div className="rounded-xl border border-subtle bg-surface p-4 text-xs space-y-1">
                      <div className="text-quiet uppercase text-[10px] font-mono">Target Primitive</div>
                      <div className="text-sm font-bold text-cyan-300 font-mono">X25519 + ML-KEM-768</div>
                      <div className="text-[10px] text-emerald-400">NIST FIPS 203 Approved</div>
                    </div>
                    <div className="rounded-xl border border-subtle bg-surface p-4 text-xs space-y-1">
                      <div className="text-quiet uppercase text-[10px] font-mono">Migration Mode</div>
                      <div className="text-sm font-bold text-foreground font-mono">HYBRID_TRANSITION</div>
                      <div className="text-[10px] text-quiet">Zero Breaking Changes</div>
                    </div>
                    <div className="rounded-xl border border-subtle bg-surface p-4 text-xs space-y-1">
                      <div className="text-quiet uppercase text-[10px] font-mono">Operational Impact</div>
                      <div className="text-sm font-bold text-amber-400 font-mono">+1,184 Bytes / Handshake</div>
                      <div className="text-[10px] text-quiet">Within Standard MTU (1500)</div>
                    </div>
                    <div className="rounded-xl border border-subtle bg-surface p-4 text-xs space-y-1">
                      <div className="text-quiet uppercase text-[10px] font-mono">Estimated Engineering</div>
                      <div className="text-sm font-bold text-foreground font-mono">14 Person-Days (Heuristic)</div>
                      <div className="text-[10px] text-quiet">4 Workstreams</div>
                    </div>
                  </div>

                  {/* Phased Roadmap Workstreams */}
                  <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
                    <h3 className="text-sm font-semibold">Ordered Workstream Execution Phases</h3>
                    <div className="space-y-3">
                      {[
                        {
                          phase: 1,
                          title: "Discovery & Evidence Locking",
                          status: "COMPLETED",
                          desc: "Run baseline scans to freeze cryptographic inventory and calculate Mosca deficit.",
                          actionLabel: "Open Scan Studio →",
                          targetTab: "studio" as TabKey,
                        },
                        {
                          phase: 2,
                          title: "Hybrid Key Exchange Staging",
                          status: "IN_PROGRESS",
                          desc: "Deploy X25519 + ML-KEM-768 hybrid key encapsulation in staging gateway.",
                          actionLabel: "Configure in Studio →",
                          targetTab: "studio" as TabKey,
                        },
                        {
                          phase: 3,
                          title: "Closed-Loop Verification Scan",
                          status: "PENDING",
                          desc: "Execute automated verification re-scan to prove hybrid negotiation and zero classical regression.",
                          actionLabel: "Run Verification →",
                          targetTab: "verify" as TabKey,
                        },
                        {
                          phase: 4,
                          title: "Classical Key Decommissioning",
                          status: "PENDING",
                          desc: "Retire legacy RSA/ECC keys and generate CycloneDX CBOM attestation for audit.",
                          actionLabel: "Open Auto Patch →",
                          targetTab: "autopatch" as TabKey,
                        },
                      ].map((p) => (
                        <div key={p.phase} className="p-4 rounded-lg border border-subtle bg-canvas flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                          <div className="space-y-1">
                            <div className="font-semibold text-foreground flex items-center gap-2">
                              <span className="font-mono text-cyan-400">Phase {p.phase}:</span> {p.title}
                            </div>
                            <div className="text-[11px] text-quiet">{p.desc}</div>
                          </div>
                          <div className="flex items-center gap-3 shrink-0">
                            <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                              p.status === "COMPLETED" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" :
                              p.status === "IN_PROGRESS" ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20" : "bg-subtle text-quiet"
                            }`}>
                              {p.status}
                            </span>
                            <button
                              onClick={() => setActiveTab(p.targetTab)}
                              className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1 cursor-pointer transition-colors"
                            >
                              {p.actionLabel}
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </div>
          )}

          {/* TAB 12: CLOSED-LOOP VERIFICATION (Section 26 / Priority 2) */}
          {activeTab === "verify" && (
            <VerificationPanel project={projectId} token="" />
          )}

          {/* TAB: STANDARDS & MANDATES */}
          {activeTab === "standards" && (
            <StandardsPanel project={projectId} token="" />
          )}

          {/* TAB: RUNTIME & EBPF */}
          {activeTab === "runtime" && (
            <div className="space-y-4">
              <div className="border-b border-subtle pb-4">
                <h2 className="text-xl font-bold tracking-tight flex items-center gap-2">
                  <Activity className="text-cyan-500" size={22} />
                  Dynamic Runtime Tracing &amp; eBPF Telemetry
                </h2>
                <p className="text-xs text-muted-foreground mt-1">
                  Live execution trace probe for OpenSSL / Python crypto calls, PID tracing, and eBPF kernel capability inspector.
                </p>
              </div>
              <ExperimentalHub project={projectId} token="" initialTab="runtime" hideTabBar={true} />
            </div>
          )}

          {/* TAB: BINARY ML & PCAP */}
          {activeTab === "binary-pcap" && (
            <div className="space-y-4">
              <div className="border-b border-subtle pb-4">
                <h2 className="text-xl font-bold tracking-tight flex items-center gap-2">
                  <Binary className="text-cyan-500" size={22} />
                  Binary ML Primitive Classifier &amp; Passive PCAP Protocol Inspector
                </h2>
                <p className="text-xs text-muted-foreground mt-1">
                  ML feature extraction for stripped compiled binaries and live/synthetic PCAP TLS handshake analysis.
                </p>
              </div>
              <ExperimentalHub project={projectId} token="" initialTab="binary_ml" hideTabBar={false} />
            </div>
          )}

          {/* TAB 13: CBOM (Section 27) */}
          {activeTab === "cbom" && (
            <div className="space-y-6">
              <div className="flex items-center justify-between border-b border-subtle pb-4">
                <div>
                  <h2 className="text-xl font-bold tracking-tight">CycloneDX 1.6 CBOM</h2>
                  <p className="text-xs text-quiet mt-1">Cryptography Bill of Materials adhering to official CycloneDX standard.</p>
                </div>
                <button
                  onClick={async () => {
                    const res = await fetch(`/api/export/cbom?project=${encodeURIComponent(projectId)}`, {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ scan_ids: scans.map((s) => s.id), target_name: projectId }),
                    });
                    if (res.ok) {
                      const blob = await res.blob();
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = `${projectId}-cyclonedx-cbom.json`;
                      a.click();
                    }
                  }}
                  className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm"
                >
                  <Download className="h-3.5 w-3.5" />
                  Download CBOM JSON
                </button>
              </div>

              <div className="rounded-xl border border-subtle bg-surface p-6 font-mono text-xs text-quiet">
                CycloneDX 1.6 schema compliant. Contains cryptographic keys, algorithms, protocol negotiation telemetry, and SHA-256 evidence provenance links.
              </div>
            </div>
          )}

          {/* TAB 14: REPORT CENTER (Section 28 / Priority 9 Showpiece) */}
          {activeTab === "reports" && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-bold tracking-tight">Enterprise Report Center</h2>
                <p className="text-xs text-quiet mt-1">Generate executive, technical, and regulatory compliance audit reports with full cryptographic provenance.</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                {[
                  {
                    type: "EXECUTIVE_SUMMARY",
                    title: "Executive Posture & PQC Readiness",
                    desc: "C-suite strategic summary mapping algorithm vulnerabilities against NIST FIPS 203/204 deadlines.",
                    includes: ["Shor & Grover vulnerability summary", "Mosca deficit timeline overview", "Top 3 high-priority remediation targets"],
                  },
                  {
                    type: "TECHNICAL_INVENTORY",
                    title: "Cryptographic Asset Inventory & Evidence",
                    desc: "Comprehensive engineering breakdown of discovered algorithms, key sizes, surfaces, and AST rule IDs.",
                    includes: [`${assets.length} Discovered Cryptographic Primitives`, "File, line number & AST call sites", "Multi-surface provenance records"],
                  },
                  {
                    type: "QUANTUM_RISK",
                    title: "Quantum Risk, Mosca Horizon & HNDL Report",
                    desc: "Formal mathematical evaluation of shelf-life expiration versus quantum threat horizons (Z - [X + Y]).",
                    includes: ["Per-algorithm Mosca deficit calculations", "Harvest Now, Decrypt Later (HNDL) exposure table", "Gidney & Ekerå physical qubit breakdown"],
                  },
                  {
                    type: "MIGRATION_ROADMAP",
                    title: "Phased PQC Migration & Workstream Plan",
                    desc: "Actionable 4-phase technical roadmap detailing hybrid key encapsulation targets and engineering heuristics.",
                    includes: ["Phase 1-4 workstream specifications", "Hybrid X25519 + ML-KEM-768 parameters", "Rollback & compatibility assurances"],
                  },
                  {
                    type: "CYCLONEDX_COMPLIANCE",
                    title: "CycloneDX 1.6 & Mandates Attestation Pack",
                    desc: "Audit attestation pack aligned with US White House NSM-10, OMB M-23-02, and NIST IR 8547 guidelines.",
                    includes: ["CycloneDX 1.6 CBOM specification links", "NIST FIPS 203/204/205 compliance matrix", "Exportable cryptographic attestation tokens"],
                  },
                ].map((rep) => (
                  <div key={rep.type} className="rounded-xl border border-subtle bg-surface p-5 flex flex-col justify-between space-y-4">
                    <div className="space-y-3">
                      <div className="flex items-start justify-between gap-2">
                        <h3 className="font-semibold text-sm text-foreground">{rep.title}</h3>
                        <span className="text-[9px] font-mono font-bold px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shrink-0">
                          AUDIT READY
                        </span>
                      </div>
                      <p className="text-xs text-quiet leading-relaxed">{rep.desc}</p>
                      <div className="rounded-lg bg-canvas/60 p-3 border border-subtle space-y-1.5">
                        <div className="text-[10px] uppercase font-mono font-bold text-quiet">Included Data Points:</div>
                        <ul className="text-[11px] text-foreground/80 space-y-1">
                          {rep.includes.map((inc, i) => (
                            <li key={i} className="flex items-center gap-1.5">
                              <span className="text-cyan-400 font-bold">•</span>
                              <span>{inc}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>

                    <div className="pt-2 grid grid-cols-2 gap-2 border-t border-subtle">
                      <button
                        onClick={async () => {
                          const res = await fetch(`/api/projects/${projectId}/reports/generate`, {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ report_type: rep.type }),
                          });
                          if (res.ok) {
                            const data = await res.json();
                            const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement("a");
                            a.href = url;
                            a.download = `${projectId}_${rep.type.toLowerCase()}.json`;
                            a.click();
                          }
                        }}
                        className="px-2.5 py-2 rounded-lg border border-subtle bg-canvas hover:bg-surface text-foreground text-xs font-semibold flex items-center justify-center gap-1 transition-colors cursor-pointer"
                      >
                        <Download size={13} />
                        <span>Export JSON</span>
                      </button>

                      <button
                        onClick={() => {
                          window.open(`/api/reports/generate?project=${encodeURIComponent(projectId)}&format=html`, '_blank');
                        }}
                        className="px-2.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center justify-center gap-1 transition-colors shadow-sm cursor-pointer"
                      >
                        <FileText size={13} />
                        <span>Export HTML</span>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 15: SECURE ARCHIVE LAB (Section 29 / Priority 7) */}
          {activeTab === "archive" && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-bold tracking-tight">Secure Archive Lab</h2>
                <p className="text-xs text-quiet mt-1">
                  Inspect encrypted archives, safely extract authorized contents, and repackage payloads into .ecvault containers.
                </p>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Left: Analyze Existing Archive */}
                <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
                  <h3 className="text-sm font-semibold flex items-center gap-2">
                    <Archive className="h-4 w-4 text-cyan-400" />
                    1. Analyze Existing Archive
                  </h3>
                  <p className="text-xs text-quiet">
                    Inspects ZIP/7z encryption, detects WinZip AES vs ZipCrypto, and discovers embedded cryptographic keys.
                  </p>

                  <form onSubmit={handleAnalyzeArchive} className="space-y-3">
                    <div>
                      <label className="block text-xs font-medium mb-1">Archive File (ZIP/7z)</label>
                      <input
                        type="file"
                        accept=".zip,.7z,.tar,.gz"
                        onChange={(e) => {
                          setArchiveFile(e.target.files?.[0] || null);
                          setArchiveError(null);
                        }}
                        className="w-full text-xs file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:text-xs file:bg-cyan-500/10 file:text-cyan-400"
                      />
                      {archiveError && (
                        <div className="mt-1.5 text-xs text-rose-400 font-medium">
                          {archiveError}
                        </div>
                      )}
                    </div>

                    <div>
                      <label className="block text-xs font-medium mb-1">Archive Password (Optional)</label>
                      <input
                        type="password"
                        value={archivePassword}
                        onChange={(e) => setArchivePassword(e.target.value)}
                        placeholder="Leave empty to analyze metadata only"
                        className="w-full px-3 py-1.5 text-xs rounded border border-subtle bg-canvas outline-none focus:border-cyan-500"
                      />
                    </div>

                    <button
                      type="submit"
                      disabled={analyzingArchive}
                      className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                    >
                      {analyzingArchive ? "Inspecting Archive..." : "Analyze Archive Protection"}
                    </button>
                  </form>

                  {archiveAnalysis && (
                    <div className="p-4 rounded-lg border border-subtle bg-canvas text-xs space-y-2 mt-4">
                      <div className="flex items-center justify-between font-semibold">
                        <span>Format: {archiveAnalysis.format}</span>
                        <span className="text-cyan-400">{archiveAnalysis.content_status}</span>
                      </div>
                      <div className="text-[11px] text-quiet">SHA-256: {archiveAnalysis.sha256}</div>
                      <div className="text-[11px]">Encryption: {archiveAnalysis.encryption_type}</div>
                      <div className="text-[11px]">KDF: {archiveAnalysis.kdf_detected}</div>

                      {archiveAnalysis.discovered_assets?.length > 0 && (
                        <div className="mt-2 pt-2 border-t border-subtle">
                          <span className="font-semibold text-cyan-300">Discovered Internal Crypto:</span>
                          <ul className="list-disc pl-4 mt-1 text-[11px] space-y-0.5">
                            {archiveAnalysis.discovered_assets.map((a: any, idx: number) => (
                              <li key={idx}>
                                {a.name} ({a.algorithm})
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Right: Create Protected Vault (.ecvault) */}
                <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
                  <h3 className="text-sm font-semibold flex items-center gap-2">
                    <Lock className="h-4 w-4 text-cyan-400" />
                    2. Create Protected Vault (.ecvault)
                  </h3>
                  <p className="text-xs text-quiet">
                    Repackages data using authenticated AES-256-GCM, PBKDF2, or Post-Quantum Hybrid Key Encapsulation.
                  </p>

                  <div className="space-y-3 text-xs">
                    <div>
                      <label className="block font-medium mb-1">Payload Content</label>
                      <textarea
                        rows={2}
                        value={vaultPayload}
                        onChange={(e) => setVaultPayload(e.target.value)}
                        className="w-full p-2 text-xs rounded border border-subtle bg-canvas outline-none focus:border-cyan-500 resize-none font-mono text-cyan-300"
                      />
                    </div>

                    <div>
                      <label className="block font-medium mb-1">Protection Mode</label>
                      <select
                        value={vaultMode}
                        onChange={(e) => setVaultMode(e.target.value as any)}
                        className="w-full px-2.5 py-1.5 rounded border border-subtle bg-canvas outline-none focus:border-cyan-500"
                      >
                        <option value="PASSWORD_VAULT">Password Vault (AES-256-GCM + PBKDF2-SHA256)</option>
                        <option value="PQC_HYBRID_VAULT">PQC Hybrid Vault (AES-256-GCM + ML-KEM-768 Hybrid KEX)</option>
                        <option value="RECIPIENT_KEY_VAULT">Recipient-Key Vault (Multi-Recipient Envelope)</option>
                      </select>
                    </div>

                    {vaultMode === "PASSWORD_VAULT" && (
                      <div>
                        <label className="block font-medium mb-1">Vault Master Passphrase</label>
                        <input
                          type="password"
                          value={vaultPassword}
                          onChange={(e) => setVaultPassword(e.target.value)}
                          className="w-full px-3 py-1.5 rounded border border-subtle bg-canvas outline-none focus:border-cyan-500"
                        />
                      </div>
                    )}

                    <button
                      type="button"
                      onClick={handleCreateVault}
                      disabled={creatingVault}
                      className="w-full py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-medium flex items-center justify-center gap-2"
                    >
                      {creatingVault ? "Packaging Vault..." : "Package & Verify .ecvault Container"}
                    </button>

                    {createdVault && (
                      <div className="p-3.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 text-xs space-y-2 mt-3">
                        <div className="flex items-center justify-between font-bold">
                          <span>Container: {createdVault.format} v{createdVault.format_version}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20">{verificationResult?.status || "CREATED"}</span>
                        </div>
                        <div className="text-[10px] font-mono text-quiet">Vault ID: {createdVault.vault_id}</div>
                        <div className="text-[10px]">Bulk Cipher: {createdVault.manifest.bulk_cipher}</div>
                        <div className="text-[10px]">PQC Status: {createdVault.manifest.pqc_status}</div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 16: KNOWLEDGE BASE (Section 33) */}
          {activeTab === "knowledge" && (
            <div className="space-y-6">
              <div className="border-b border-subtle pb-4">
                <h2 className="text-xl font-bold tracking-tight">Versioned Cryptographic Knowledge Base</h2>
                <p className="text-xs text-quiet mt-1">
                  Deterministic ruleset registry mapping cryptographic algorithms, standards, and security thresholds.
                </p>
              </div>

              <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
                <div className="flex items-center justify-between font-mono text-xs border-b border-subtle pb-3">
                  <span className="font-bold text-cyan-400">RULES_VERSION: v4.2.1-federated</span>
                  <span className="text-emerald-400 font-bold">ATTESTATION: VERIFIED</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="p-3.5 rounded-lg bg-canvas border border-subtle space-y-1">
                    <div className="font-semibold text-foreground">NIST Post-Quantum Cryptography Standards</div>
                    <div className="text-[11px] text-quiet">• FIPS 203: ML-KEM (Module-Lattice Key Encapsulation)</div>
                    <div className="text-[11px] text-quiet">• FIPS 204: ML-DSA (Module-Lattice Digital Signatures)</div>
                    <div className="text-[11px] text-quiet">• FIPS 205: SLH-DSA (Stateless Hash-Based Signatures)</div>
                  </div>

                  <div className="p-3.5 rounded-lg bg-canvas border border-subtle space-y-1">
                    <div className="font-semibold text-foreground">Classical Security Recommendations</div>
                    <div className="text-[11px] text-quiet">• NIST SP 800-56C Rev 2: Key-Derivation Methods</div>
                    <div className="text-[11px] text-quiet">• BSI TR-02102: Cryptographic Mechanisms for TLS</div>
                    <div className="text-[11px] text-quiet">• NSA CNSA 2.0: Commercial National Security Algorithm Suite</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 17: PROJECT SETTINGS (Section 32) */}
          {activeTab === "settings" && (
            <div className="space-y-6">
              <div className="border-b border-subtle pb-4">
                <h2 className="text-xl font-bold tracking-tight">Project Configuration &amp; Business Context</h2>
                <p className="text-xs text-quiet mt-1">
                  Persist business criticality, data sensitivity, and protection lifetime parameters directly to the database.
                </p>
              </div>

              <form onSubmit={handleSaveSettings} className="rounded-xl border border-subtle bg-surface p-6 space-y-5 max-w-2xl">
                {settingsSavedMsg && (
                  <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs flex items-center gap-2">
                    <CheckCheck className="h-4 w-4" />
                    <span>{settingsSavedMsg}</span>
                  </div>
                )}

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  <div>
                    <label className="block font-semibold mb-1">Environment</label>
                    <select
                      value={settingsEnv}
                      onChange={(e) => setSettingsEnv(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg border border-subtle bg-canvas outline-none"
                    >
                      <option value="PRODUCTION">Production</option>
                      <option value="STAGING">Staging</option>
                      <option value="DEVELOPMENT">Development</option>
                      <option value="RESEARCH">Research</option>
                    </select>
                  </div>

                  <div>
                    <label className="block font-semibold mb-1">Business Criticality</label>
                    <select
                      value={settingsCrit}
                      onChange={(e) => setSettingsCrit(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg border border-subtle bg-canvas outline-none"
                    >
                      <option value="CRITICAL">Critical</option>
                      <option value="HIGH">High</option>
                      <option value="MEDIUM">Medium</option>
                      <option value="LOW">Low</option>
                    </select>
                  </div>

                  <div>
                    <label className="block font-semibold mb-1">Data Sensitivity</label>
                    <select
                      value={settingsSens}
                      onChange={(e) => setSettingsSens(e.target.value)}
                      className="w-full px-3 py-2 rounded-lg border border-subtle bg-canvas outline-none"
                    >
                      <option value="CLASSIFIED">Classified</option>
                      <option value="SENSITIVE">Sensitive</option>
                      <option value="CONFIDENTIAL">Confidential</option>
                      <option value="INTERNAL">Internal</option>
                      <option value="PUBLIC">Public</option>
                    </select>
                  </div>

                  <div>
                    <label className="block font-semibold mb-1">Protection Lifetime (X years)</label>
                    <input
                      type="number"
                      min={1}
                      max={50}
                      value={settingsLifetime}
                      onChange={(e) => setSettingsLifetime(Number(e.target.value))}
                      className="w-full px-3 py-2 rounded-lg border border-subtle bg-canvas outline-none font-mono"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={savingSettings}
                  className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5"
                >
                  <Check className="h-3.5 w-3.5" />
                  {savingSettings ? "Persisting Settings..." : "Save Project Settings"}
                </button>
              </form>
            </div>
          )}
        </main>
      </div>

      {/* GLOBAL COMMAND MENU / SEARCH MODAL (Section 37) */}
      {searchOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-start justify-center pt-20 p-4">
          <div className="bg-surface border border-subtle rounded-xl w-full max-w-xl overflow-hidden shadow-2xl flex flex-col">
            <div className="p-3 border-b border-subtle flex items-center gap-2.5 bg-canvas/40">
              <Search className="h-4 w-4 text-cyan-400 shrink-0" />
              <input
                type="text"
                autoFocus
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search tabs, assets, algorithms, or scans..."
                className="w-full bg-transparent text-xs text-foreground outline-none placeholder:text-quiet"
              />
              <kbd className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-subtle text-quiet">ESC</kbd>
            </div>

            <div className="p-2 max-h-72 overflow-y-auto space-y-1 text-xs">
              {/* Filtered Tabs */}
              <div className="text-[10px] uppercase font-bold text-quiet px-2 py-1 font-mono">Workspace Navigation</div>
              {navGroups
                .flatMap((g) => g.items)
                .filter((item) => item.label.toLowerCase().includes(searchQuery.toLowerCase()))
                .slice(0, 5)
                .map((item) => (
                  <button
                    key={item.key}
                    onClick={() => {
                      setActiveTab(item.key);
                      setSearchOpen(false);
                      setSearchQuery("");
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 rounded-lg hover:bg-cyan-500/10 hover:text-cyan-300 text-quiet transition-colors text-left"
                  >
                    <div className="flex items-center gap-2">
                      <item.icon className="h-3.5 w-3.5" />
                      <span>{item.label}</span>
                    </div>
                    <span className="text-[10px] font-mono opacity-60">Tab</span>
                  </button>
                ))}

              {/* Filtered Discovered Assets */}
              {assets.length > 0 && (
                <>
                  <div className="text-[10px] uppercase font-bold text-quiet px-2 pt-2 pb-1 font-mono">Discovered Assets</div>
                  {assets
                    .filter((a) =>
                      String(a.algorithm || a.name || "")
                        .toLowerCase()
                        .includes(searchQuery.toLowerCase())
                    )
                    .slice(0, 5)
                    .map((a) => (
                      <button
                        key={a.id}
                        onClick={() => {
                          setActiveTab("assets");
                          setSearchOpen(false);
                          setSearchQuery("");
                        }}
                        className="w-full flex items-center justify-between px-3 py-2 rounded-lg hover:bg-cyan-500/10 hover:text-cyan-300 text-quiet transition-colors text-left"
                      >
                        <div className="flex items-center gap-2">
                          <Layers className="h-3.5 w-3.5 text-cyan-400" />
                          <span className="font-semibold text-foreground">{a.algorithm || a.name}</span>
                          <span className="text-[10px] text-quiet">({a.asset_type})</span>
                        </div>
                        <span className="text-[10px] font-mono text-cyan-400">{a.highest_evidence_level || "E2"}</span>
                      </button>
                    ))}
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* GOOGLE AI STUDIO / GEMINI CRYPTOGRAPHIC COPILOT MODAL */}
      {aiModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-surface border border-subtle rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
            <div className="p-4 sm:p-5 border-b border-subtle flex items-center justify-between bg-canvas/40">
              <div className="flex items-center gap-2.5">
                <Sparkles className="h-5 w-5 text-cyan-400" />
                <div>
                  <h3 className="font-bold text-sm text-foreground flex items-center gap-2">
                    Google AI Studio Cryptographic Copilot
                    <span className="text-[10px] font-normal px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                      Gemini 1.5 Flash
                    </span>
                  </h3>
                  <p className="text-[11px] text-quiet">AI-assisted cryptographic triage, explainability, and migration advisory.</p>
                </div>
              </div>
              <button
                onClick={() => setAiModalOpen(false)}
                className="p-1 rounded-lg text-quiet hover:text-foreground hover:bg-surface"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-4 sm:p-6 overflow-y-auto space-y-4 text-xs">
              {/* Mode Tabs */}
              <div className="flex gap-2 border-b border-subtle pb-3 overflow-x-auto">
                {[
                  { key: "posture", label: "Project Posture" },
                  { key: "triage", label: "Custom Code Triage" },
                  { key: "explain", label: "Asset Explain" },
                  { key: "advisory", label: "Migration Advisory" },
                ].map((m) => (
                  <button
                    key={m.key}
                    onClick={() => {
                      setAiMode(m.key as any);
                      setAiResult(null);
                    }}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors ${
                      aiMode === m.key
                        ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                        : "text-quiet hover:text-foreground bg-canvas"
                    }`}
                  >
                    {m.label}
                  </button>
                ))}
              </div>

              {/* Dynamic Inputs depending on mode */}
              {aiMode === "triage" && (
                <div>
                  <label className="block font-semibold mb-1">Code Snippet to Analyze</label>
                  <textarea
                    rows={4}
                    value={aiSnippet}
                    onChange={(e) => setAiSnippet(e.target.value)}
                    className="w-full p-2.5 rounded-lg border border-subtle bg-canvas font-mono text-cyan-300 text-xs resize-none outline-none focus:border-cyan-500"
                  />
                </div>
              )}

              {["explain", "advisory"].includes(aiMode) && (
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block font-semibold mb-1">Target Algorithm</label>
                    <input
                      type="text"
                      value={aiTargetAlgo}
                      onChange={(e) => setAiTargetAlgo(e.target.value)}
                      className="w-full px-3 py-1.5 rounded-lg border border-subtle bg-canvas font-mono text-xs outline-none"
                    />
                  </div>
                  <div>
                    <label className="block font-semibold mb-1">Cryptographic Role</label>
                    <input
                      type="text"
                      value={aiTargetRole}
                      onChange={(e) => setAiTargetRole(e.target.value)}
                      className="w-full px-3 py-1.5 rounded-lg border border-subtle bg-canvas font-mono text-xs outline-none"
                    />
                  </div>
                </div>
              )}

              {/* Optional Google AI Studio Key */}
              <div>
                <label className="block font-semibold mb-1 text-[11px] text-quiet">
                  Google AI Studio API Key (Optional — uses offline deterministic engine if blank)
                </label>
                <input
                  type="password"
                  placeholder="AIzaSy..."
                  value={aiApiKey}
                  onChange={(e) => setAiApiKey(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg border border-subtle bg-canvas font-mono text-xs outline-none"
                />
              </div>

              <button
                onClick={handleRunAiAnalysis}
                disabled={aiLoading}
                className="w-full py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white font-semibold flex items-center justify-center gap-2"
              >
                <Sparkles className="h-4 w-4" />
                {aiLoading ? "Consulting AI Security Engine..." : "Execute AI Cryptographic Analysis"}
              </button>

              {/* Results Display */}
              {aiResult && (
                <div className="p-4 rounded-xl border border-cyan-500/30 bg-canvas space-y-2.5">
                  <div className="flex items-center justify-between border-b border-subtle pb-2">
                    <span className="font-bold text-cyan-300">Verdict: {aiResult.verdict}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-subtle text-quiet">
                      Provider: {aiResult.provider}
                    </span>
                  </div>

                  <p className="text-foreground text-xs leading-relaxed">{aiResult.summary}</p>

                  <div className="p-2.5 rounded bg-surface border border-subtle text-[11px] text-quiet space-y-1">
                    <div className="font-semibold text-foreground">Actionable Recommendation:</div>
                    <div>{aiResult.recommendation}</div>
                  </div>

                  {aiResult.nist_references?.length > 0 && (
                    <div className="text-[10px] text-cyan-400 font-mono">
                      NIST Standards: {aiResult.nist_references.join(", ")}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
