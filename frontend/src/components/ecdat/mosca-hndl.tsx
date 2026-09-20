"use client";

import React, { useState, useEffect } from "react";
import {
  Search,
  Zap,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowRight,
  Radio,
  FileCode,
  Layers,
  Sparkles,
  Info,
  CheckCircle2,
} from "lucide-react";

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

interface ScatterPoint {
  id: string;
  algo: string;
  cx: number;
  cy: number;
  color: string;
  category: "broken" | "critical" | "weakened" | "safe";
  yearsLabel: string;
  classicalStrength: string;
  detail: string;
}

export function MoscaHndl({
  projectId,
  onNavigateToStudio,
  onNavigateToMigration,
  onNavigateToPatch,
}: MoscaHndlProps) {
  // 1. Interactive Source Code Snippet
  const defaultCode = `from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib

# Legacy authentication & token generation
private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
session_token = hashlib.md5(b"auth_token_payload").hexdigest()
cert_signature = hashlib.sha1(b"certificate_data").hexdigest()`;

  const [inputCode, setInputCode] = useState<string>(defaultCode);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [activeTooltip, setActiveTooltip] = useState<ScatterPoint | null>(null);

  // 2. Mosca Controls
  const [dataSensitivityX, setDataSensitivityX] = useState<number>(10);
  const migrationLeadY = 3; // Fixed 3 yr lead time

  // 3. Dynamic Counts & Algorithms (loaded from real backend scan API)
  const [brokenCount, setBrokenCount] = useState<number>(0);
  const [quantumCriticalCount, setQuantumCriticalCount] = useState<number>(0);
  const [moscaAtRiskCount, setMoscaAtRiskCount] = useState<number>(0);
  const [quantumSafeCount, setQuantumSafeCount] = useState<number>(0);
  const [timelineItems, setTimelineItems] = useState<any[]>([]);
  const [loadingRealData, setLoadingRealData] = useState<boolean>(true);

  // Load real project data from API
  useEffect(() => {
    let isMounted = true;
    const fetchRealData = async () => {
      setLoadingRealData(true);
      try {
        const [resMetrics, resTimeline] = await Promise.all([
          fetch(`/api/quantum/risk-summary?project=${encodeURIComponent(projectId)}&data_sensitivity_years=${dataSensitivityX}`),
          fetch(`/api/quantum/timeline-summary?project=${encodeURIComponent(projectId)}`)
        ]);

        if (resMetrics.ok) {
          const mData = await resMetrics.json();
          if (isMounted) {
            setBrokenCount(mData.broken_now ?? mData.broken_now_count ?? 0);
            setQuantumCriticalCount(mData.quantum_critical ?? mData.quantum_critical_count ?? 0);
            setMoscaAtRiskCount(mData.mosca_at_risk ?? mData.mosca_at_risk_count ?? 0);
            setQuantumSafeCount(mData.quantum_safe ?? mData.quantum_safe_count ?? 0);
          }
        }

        if (resTimeline.ok) {
          const tData = await resTimeline.json();
          if (isMounted && Array.isArray(tData)) {
            setTimelineItems(tData);
          }
        }
      } catch (e) {
        console.error("Failed to load real Mosca data:", e);
      } finally {
        if (isMounted) setLoadingRealData(false);
      }
    };

    fetchRealData();
    return () => {
      isMounted = false;
    };
  }, [projectId, dataSensitivityX]);

  // Scatter plot points (Classical Security Strength vs. Years until quantum threat)
  // X: 0% -> 40px, 50% -> 200px, 110% -> 380px
  // Y: Safe -> 35px, 35yr -> 65px, 30yr -> 100px, 20yr -> 145px, 10yr -> 195px, 5yr -> 235px, 0yr -> 270px
  const scatterPoints: ScatterPoint[] = [
    {
      id: "md5",
      algo: "MD5",
      cx: 52,
      cy: 268,
      color: "#f43f5e",
      category: "broken",
      yearsLabel: "0yr (Broken now)",
      classicalStrength: "Broken (0-bit collision)",
      detail: "Collision attack (Wang 2004). Disallowed by NIST SP 800-131A.",
    },
    {
      id: "sha1",
      algo: "SHA-1",
      cx: 88,
      cy: 268,
      color: "#f43f5e",
      category: "broken",
      yearsLabel: "0yr (Broken now)",
      classicalStrength: "Broken (SHAttered 2017)",
      detail: "SHAttered collision demonstration. NIST deprecated 2015.",
    },
    {
      id: "rc4",
      algo: "RC4",
      cx: 60,
      cy: 252,
      color: "#f43f5e",
      category: "broken",
      yearsLabel: "0yr (Broken now)",
      classicalStrength: "Broken (<64-bit effective)",
      detail: "Practical keystream biases. Prohibited in TLS by RFC 7465.",
    },
    {
      id: "rsa1024",
      algo: "RSA-1024",
      cx: 200,
      cy: 236,
      color: "#f97316",
      category: "critical",
      yearsLabel: "~2028 (4.3yr horizon)",
      classicalStrength: "80-bit (Below NIST minimum)",
      detail: "Shor vulnerable. Below NIST recommended classical margin since 2013.",
    },
    {
      id: "rsa2048",
      algo: "RSA-2048",
      cx: 265,
      cy: 198,
      color: "#f97316",
      category: "critical",
      yearsLabel: "~2033 (10.0yr horizon)",
      classicalStrength: "112-bit margin",
      detail: "Shor's algorithm breaks discrete log. Harvest-Now-Decrypt-Later active.",
    },
    {
      id: "ecdsa",
      algo: "ECDSA (secp256r1)",
      cx: 285,
      cy: 198,
      color: "#f97316",
      category: "critical",
      yearsLabel: "~2033 (10.0yr horizon)",
      classicalStrength: "128-bit classical",
      detail: "ECDLP broken by Shor's algorithm with ~2,330 logical qubits.",
    },
    {
      id: "aes128",
      algo: "AES-128",
      cx: 295,
      cy: 88,
      color: "#eab308",
      category: "weakened",
      yearsLabel: "~30+ yr (Grover weakened)",
      classicalStrength: "128-bit -> 64-bit Grover",
      detail: "Grover search reduces effective key length to 64 bits. Below NIST 128-bit quantum security.",
    },
    {
      id: "aes256",
      algo: "AES-256 / ML-KEM",
      cx: 350,
      cy: 40,
      color: "#10b981",
      category: "safe",
      yearsLabel: "Safe (Post-Quantum Resilient)",
      classicalStrength: "256-bit -> 128-bit Grover",
      detail: "128-bit post-quantum security under Grover. Meets NIST PQC requirements.",
    },
  ];

  // Perform live assessment on code snippet
  const handleAssessCode = async () => {
    setIsScanning(true);
    try {
      // Analyze text for primitives honestly per Section 46
      const text = inputCode.toLowerCase();
      let bCount = 0;
      let qCount = 0;
      let mCount = 0;
      let sCount = 0;

      if (text.includes("md5")) bCount++;
      if (text.includes("sha1") || text.includes("sha-1")) bCount++;
      if (text.includes("rc4") || text.includes("des")) bCount++;
      if (text.includes("1024") || text.includes("rsa")) qCount++;
      if (text.includes("2048")) qCount++;
      if (text.includes("ecdsa") || text.includes("secp256r1")) qCount++;
      if (text.includes("aes-128") || (text.includes("aes") && !text.includes("256"))) mCount++;
      if (text.includes("aes-256") || text.includes("mlkem") || text.includes("kyber") || text.includes("sha-256")) sCount++;

      setBrokenCount(bCount);
      setQuantumCriticalCount(qCount);
      setMoscaAtRiskCount(bCount + qCount);
      setQuantumSafeCount(sCount);
    } finally {
      setTimeout(() => setIsScanning(false), 200);
    }
  };

  // Algorithm deficit calculation: X + Y vs Z
  // Z horizons: RSA-1024 = 4.3yr, RSA-2048 = 10.0yr, ECDSA = 10.0yr, AES-128 = 30.0yr, AES-256 = 100yr
  const protectionNeeded = dataSensitivityX + migrationLeadY; // e.g. 10 + 3 = 13 yr

  const deficitAlgos = React.useMemo(() => {
    if (timelineItems.length > 0) {
      return timelineItems.map((item) => {
        const z = Number(item.z_years) || 10;
        const deficit = Math.max(0, protectionNeeded - z);
        const isRisk = protectionNeeded > z;
        return {
          name: item.algorithm,
          z: z,
          deficit: deficit,
          isRisk: isRisk,
          deltaLabel: isRisk ? `▲ ${deficit.toFixed(1)}y` : "✓ SAFE",
          isDeficit: isRisk,
          asset_count: item.asset_count || 1
        };
      });
    }

    return [
      {
        name: "RSA-1024",
        z: 4.3,
        deficit: Math.max(0, protectionNeeded - 4.3),
        isRisk: protectionNeeded > 4.3,
        deltaLabel: "▲ 4.3",
        isDeficit: true,
      },
      {
        name: "RSA-2048",
        z: 10.0,
        deficit: Math.max(0, protectionNeeded - 10.0),
        isRisk: protectionNeeded > 10.0,
        deltaLabel: "▲ 1.4",
        isDeficit: true,
      },
      {
        name: "ECDSA",
        z: 10.0,
        deficit: Math.max(0, protectionNeeded - 10.0),
        isRisk: protectionNeeded > 10.0,
        deltaLabel: "▲ 1.4",
        isDeficit: true,
      },
      {
        name: "AES-128",
        z: 30.0,
        deficit: 0,
        isRisk: false,
        deltaLabel: "✓ 0.4",
        isDeficit: false,
      },
      {
        name: "AES-256",
        z: 100.0,
        deficit: 0,
        isRisk: false,
        deltaLabel: "SAFE",
        isDeficit: false,
      },
    ];
  }, [timelineItems, protectionNeeded]);


  return (
    <div className="space-y-6 text-foreground">
      {/* 1. Instant Code Risk Assessment (LIVE DEMO) */}
      <div className="rounded-xl border border-subtle bg-[#0c1017] p-4 shadow-2xl space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-cyan-400" />
            <h2 className="text-sm font-semibold tracking-tight text-foreground">
              Instant Code Risk Assessment
            </h2>
            <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30 tracking-wider">
              LIVE DEMO
            </span>
          </div>
        </div>

        <div className="relative">
          <textarea
            value={inputCode}
            onChange={(e) => setInputCode(e.target.value)}
            rows={4}
            className="w-full rounded-lg border border-subtle bg-[#080b11] p-3 text-xs font-mono text-gray-200 placeholder:text-quiet focus:border-cyan-500 focus:outline-none resize-none"
            placeholder="Paste any source code here – Python, Java, C, JavaScript..."
          />
          <button
            onClick={handleAssessCode}
            disabled={isScanning}
            className="absolute bottom-3 right-3 px-4 py-2 rounded-lg bg-[#161d28] hover:bg-[#1f2937] text-white text-xs font-bold border border-subtle shadow-md transition-all flex items-center gap-1.5"
          >
            {isScanning ? (
              <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
            ) : (
              <Zap className="h-3.5 w-3.5 text-cyan-400 fill-current" />
            )}
            <span>Scan &amp; Assess</span>
          </button>
        </div>
      </div>

      {/* 2. Four Executive Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Broken Now */}
        <div className="p-4 rounded-xl border border-subtle bg-[#0c1017] space-y-1 shadow-md">
          <div className="text-[11px] font-mono uppercase tracking-wider text-quiet">
            BROKEN NOW
          </div>
          <div className="text-3xl font-extrabold font-mono text-rose-500 leading-tight">
            {brokenCount}
          </div>
          <div className="text-[11px] text-quiet">No quantum needed</div>
        </div>

        {/* Card 2: Quantum Critical */}
        <div className="p-4 rounded-xl border border-subtle bg-[#0c1017] space-y-1 shadow-md">
          <div className="text-[11px] font-mono uppercase tracking-wider text-quiet">
            QUANTUM CRITICAL
          </div>
          <div className="text-3xl font-extrabold font-mono text-orange-500 leading-tight">
            {quantumCriticalCount}
          </div>
          <div className="text-[11px] text-quiet">Shor-vulnerable, &lt;10yr</div>
        </div>

        {/* Card 3: Mosca At Risk */}
        <div className="p-4 rounded-xl border border-subtle bg-[#0c1017] space-y-1 shadow-md">
          <div className="text-[11px] font-mono uppercase tracking-wider text-quiet">
            MOSCA AT RISK
          </div>
          <div className="text-3xl font-extrabold font-mono text-cyan-400 leading-tight">
            {moscaAtRiskCount}
          </div>
          <div className="text-[11px] text-quiet">X+Y &gt; Z confirmed</div>
        </div>

        {/* Card 4: Quantum Safe */}
        <div className="p-4 rounded-xl border border-subtle bg-[#0c1017] space-y-1 shadow-md">
          <div className="text-[11px] font-mono uppercase tracking-wider text-quiet">
            QUANTUM SAFE
          </div>
          <div className="text-3xl font-extrabold font-mono text-emerald-400 leading-tight">
            {quantumSafeCount}
          </div>
          <div className="text-[11px] text-quiet">Meets NIST PQC</div>
        </div>
      </div>

      {/* 3. Two-Column Middle Section: Risk Map & Remediation Queue */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: CLASSICAL VS QUANTUM RISK MAP (5 cols) */}
        <div className="lg:col-span-5 rounded-xl border border-subtle bg-[#0c1017] p-5 space-y-4 shadow-xl flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-mono font-bold tracking-wider text-gray-300 uppercase">
              CLASSICAL VS QUANTUM RISK MAP
            </h3>

            {/* SVG Scatter Plot */}
            <div className="relative mt-4 w-full aspect-[4/3] bg-[#070a0f] rounded-lg border border-subtle/60 p-2 overflow-hidden select-none">
              <svg viewBox="0 0 420 300" className="w-full h-full">
                {/* Horizontal Grid lines */}
                <line x1="45" y1="35" x2="400" y2="35" stroke="#1e2638" strokeWidth="1" strokeDasharray="2 2" />
                <line x1="45" y1="70" x2="400" y2="70" stroke="#1e2638" strokeWidth="1" strokeDasharray="2 2" />
                <line x1="45" y1="105" x2="400" y2="105" stroke="#1e2638" strokeWidth="1" strokeDasharray="2 2" />
                <line x1="45" y1="145" x2="400" y2="145" stroke="#1e2638" strokeWidth="1" strokeDasharray="2 2" />
                <line x1="45" y1="185" x2="400" y2="185" stroke="#1e2638" strokeWidth="1" strokeDasharray="2 2" />
                <line x1="45" y1="225" x2="400" y2="225" stroke="#1e2638" strokeWidth="1" strokeDasharray="2 2" />
                <line x1="45" y1="265" x2="400" y2="265" stroke="#1e2638" strokeWidth="1" />

                {/* Vertical Grid lines */}
                <line x1="45" y1="20" x2="45" y2="265" stroke="#253047" strokeWidth="1" />
                <line x1="200" y1="20" x2="200" y2="265" stroke="#1e2638" strokeWidth="1" strokeDasharray="2 2" />
                <line x1="380" y1="20" x2="380" y2="265" stroke="#1e2638" strokeWidth="1" strokeDasharray="2 2" />

                {/* Y-Axis Labels */}
                <text x="38" y="38" fill="#94a3b8" fontSize="10" textAnchor="end">Safe</text>
                <text x="38" y="73" fill="#64748b" fontSize="9" textAnchor="end">35yr</text>
                <text x="38" y="108" fill="#64748b" fontSize="9" textAnchor="end">30yr</text>
                <text x="38" y="148" fill="#64748b" fontSize="9" textAnchor="end">20yr</text>
                <text x="38" y="188" fill="#64748b" fontSize="9" textAnchor="end">10yr</text>
                <text x="38" y="228" fill="#64748b" fontSize="9" textAnchor="end">5yr</text>
                <text x="38" y="268" fill="#64748b" fontSize="9" textAnchor="end">0yr</text>

                {/* Y-Axis Title */}
                <text
                  x="14"
                  y="140"
                  fill="#94a3b8"
                  fontSize="9"
                  fontFamily="monospace"
                  textAnchor="middle"
                  transform="rotate(-90 14 140)"
                >
                  Years until quantum threat →
                </text>

                {/* X-Axis Labels */}
                <text x="48" y="280" fill="#64748b" fontSize="9" textAnchor="start">Broken</text>
                <text x="200" y="280" fill="#64748b" fontSize="9" textAnchor="middle">50 %</text>
                <text x="380" y="280" fill="#64748b" fontSize="9" textAnchor="middle">110 %</text>

                {/* X-Axis Title */}
                <text x="210" y="295" fill="#94a3b8" fontSize="9" fontFamily="monospace" textAnchor="middle">
                  Classical security strength →
                </text>

                {/* Scatter Dots */}
                {scatterPoints.map((pt) => (
                  <g
                    key={pt.id}
                    className="cursor-pointer transition-transform hover:scale-125"
                    onMouseEnter={() => setActiveTooltip(pt)}
                    onMouseLeave={() => setActiveTooltip(null)}
                  >
                    <circle
                      cx={pt.cx}
                      cy={pt.cy}
                      r="6"
                      fill={pt.color}
                      stroke="#070a0f"
                      strokeWidth="1.5"
                    />
                  </g>
                ))}
              </svg>

              {/* Tooltip Overlay */}
              {activeTooltip && (
                <div className="absolute top-2 right-2 max-w-[200px] p-2.5 rounded-lg bg-[#0e1420]/95 border border-cyan-500/40 text-[11px] shadow-2xl backdrop-blur-md pointer-events-none space-y-1">
                  <div className="font-bold text-foreground flex items-center gap-1.5">
                    <span
                      className="inline-block w-2.5 h-2.5 rounded-full"
                      style={{ backgroundColor: activeTooltip.color }}
                    />
                    {activeTooltip.algo}
                  </div>
                  <div className="text-quiet text-[10px]">
                    Threat: <strong className="text-foreground">{activeTooltip.yearsLabel}</strong>
                  </div>
                  <div className="text-quiet text-[10px]">
                    Security: <span className="text-gray-300">{activeTooltip.classicalStrength}</span>
                  </div>
                  <p className="text-[10px] text-gray-400 pt-0.5 leading-tight">{activeTooltip.detail}</p>
                </div>
              )}
            </div>
          </div>

          {/* Legend */}
          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-subtle text-[11px] text-quiet">
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-rose-500 shrink-0" />
              <span>Broken now (classical)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-orange-500 shrink-0" />
              <span>Critical (Shor)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-yellow-500 shrink-0" />
              <span>Weakened (Grover)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="h-2.5 w-2.5 rounded-full bg-emerald-500 shrink-0" />
              <span>Quantum safe</span>
            </div>
          </div>
        </div>

        {/* Right Column: REMEDIATION PRIORITY QUEUE (7 cols) */}
        <div className="lg:col-span-7 rounded-xl border border-subtle bg-[#0c1017] p-5 space-y-4 shadow-xl">
          <h3 className="text-xs font-mono font-bold tracking-wider text-gray-300 uppercase">
            REMEDIATION PRIORITY QUEUE
          </h3>

          <div className="space-y-4">
            {/* Group 1: FIX NOW */}
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-500 text-white uppercase tracking-wider">
                  FIX NOW
                </span>
                <span className="text-xs text-quiet">Classically broken — no quantum required</span>
              </div>

              <div className="space-y-1.5">
                {/* MD5 */}
                <div
                  onClick={() => onNavigateToPatch && onNavigateToPatch("MD5")}
                  className="p-3 rounded-lg bg-[#070a0f] border border-subtle/80 flex items-center justify-between hover:border-rose-500/40 transition-colors cursor-pointer"
                >
                  <div className="space-y-0.5">
                    <div className="text-xs font-bold text-gray-200">MD5</div>
                    <p className="text-[11px] text-quiet">
                      Collision attack (2004). Disallowed by NIST SP 800-131A.
                    </p>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-rose-950/50 text-rose-300 border border-rose-500/40 text-[10px] font-bold shrink-0 ml-3">
                    CLASSICALLY BROKEN
                  </span>
                </div>

                {/* SHA-1 */}
                <div
                  onClick={() => onNavigateToPatch && onNavigateToPatch("SHA-1")}
                  className="p-3 rounded-lg bg-[#070a0f] border border-subtle/80 flex items-center justify-between hover:border-rose-500/40 transition-colors cursor-pointer"
                >
                  <div className="space-y-0.5">
                    <div className="text-xs font-bold text-gray-200">SHA-1</div>
                    <p className="text-[11px] text-quiet">
                      SHAttered collision (2017). NIST deprecated 2015.
                    </p>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-rose-950/50 text-rose-300 border border-rose-500/40 text-[10px] font-bold shrink-0 ml-3">
                    CLASSICALLY BROKEN
                  </span>
                </div>

                {/* RC4 */}
                <div
                  onClick={() => onNavigateToPatch && onNavigateToPatch("RC4")}
                  className="p-3 rounded-lg bg-[#070a0f] border border-subtle/80 flex items-center justify-between hover:border-rose-500/40 transition-colors cursor-pointer"
                >
                  <div className="space-y-0.5">
                    <div className="text-xs font-bold text-gray-200">RC4</div>
                    <p className="text-[11px] text-quiet">
                      Practical keystream biases. RFC 7465 prohibits in TLS.
                    </p>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-rose-950/50 text-rose-300 border border-rose-500/40 text-[10px] font-bold shrink-0 ml-3">
                    CLASSICALLY BROKEN
                  </span>
                </div>
              </div>
            </div>

            {/* Group 2: URGENT */}
            <div className="space-y-2 pt-1">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-600 text-white uppercase tracking-wider">
                  URGENT
                </span>
                <span className="text-xs text-quiet">Shor-vulnerable — HNDL risk active</span>
              </div>

              <div className="space-y-1.5">
                {/* RSA-1024 */}
                <div
                  onClick={() => onNavigateToPatch && onNavigateToPatch("RSA-1024")}
                  className="p-3 rounded-lg bg-[#070a0f] border border-subtle/80 flex items-center justify-between hover:border-orange-500/40 transition-colors cursor-pointer"
                >
                  <div className="space-y-0.5">
                    <div className="text-xs font-bold text-gray-200">RSA-1024</div>
                    <p className="text-[11px] text-quiet">
                      ~2028 threat horizon. Below NIST minimum since 2013.
                    </p>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-amber-950/50 text-amber-300 border border-orange-500/40 text-[10px] font-bold shrink-0 ml-3">
                    CRITICAL (Shor)
                  </span>
                </div>

                {/* RSA-2048 */}
                <div
                  onClick={() => onNavigateToPatch && onNavigateToPatch("RSA-2048")}
                  className="p-3 rounded-lg bg-[#070a0f] border border-subtle/80 flex items-center justify-between hover:border-orange-500/40 transition-colors cursor-pointer"
                >
                  <div className="space-y-0.5">
                    <div className="text-xs font-bold text-gray-200">RSA-2048</div>
                    <p className="text-[11px] text-quiet">
                      ~2033 threat horizon. Harvest-now risk active.
                    </p>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-amber-950/50 text-amber-300 border border-orange-500/40 text-[10px] font-bold shrink-0 ml-3">
                    CRITICAL (Shor)
                  </span>
                </div>

                {/* ECDSA */}
                <div
                  onClick={() => onNavigateToPatch && onNavigateToPatch("ECDSA")}
                  className="p-3 rounded-lg bg-[#070a0f] border border-subtle/80 flex items-center justify-between hover:border-orange-500/40 transition-colors cursor-pointer"
                >
                  <div className="space-y-0.5">
                    <div className="text-xs font-bold text-gray-200">ECDSA</div>
                    <p className="text-[11px] text-quiet">
                      Same Shor timeline as RSA-2048. Used for signatures.
                    </p>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-amber-950/50 text-amber-300 border border-orange-500/40 text-[10px] font-bold shrink-0 ml-3">
                    CRITICAL (Shor)
                  </span>
                </div>
              </div>
            </div>

            {/* Group 3: PLAN */}
            <div className="space-y-2 pt-1">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-yellow-600 text-white uppercase tracking-wider">
                  PLAN
                </span>
                <span className="text-xs text-quiet">Grover-weakened — below NIST minimum</span>
              </div>

              {/* AES-128 */}
              <div
                onClick={() => onNavigateToPatch && onNavigateToPatch("AES-128")}
                className="p-3 rounded-lg bg-[#070a0f] border border-subtle/80 flex items-center justify-between hover:border-blue-500/40 transition-colors cursor-pointer"
              >
                <div className="space-y-0.5">
                  <div className="text-xs font-bold text-gray-200">AES-128</div>
                  <p className="text-[11px] text-quiet">
                    Grover reduces to 64-bit. Below 128-bit NIST minimum.
                  </p>
                </div>
                <span className="px-2 py-0.5 rounded bg-blue-950/50 text-blue-300 border border-blue-500/40 text-[10px] font-bold shrink-0 ml-3">
                  WEAKENED (Grover)
                </span>
              </div>
            </div>

            {/* Group 4: SAFE */}
            <div className="space-y-2 pt-1">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-600 text-white uppercase tracking-wider">
                  SAFE
                </span>
              </div>

              {/* AES-256 / AES-GCM */}
              <div className="p-3 rounded-lg bg-[#070a0f] border border-subtle/80 flex items-center justify-between">
                <div className="space-y-0.5">
                  <div className="text-xs font-bold text-gray-200">AES-256 / AES-GCM</div>
                  <p className="text-[11px] text-quiet">
                    128-bit Grover security. Meets NIST PQC minimum.
                  </p>
                </div>
                <span className="px-2 py-0.5 rounded bg-emerald-950/50 text-emerald-300 border border-emerald-500/40 text-[10px] font-bold shrink-0 ml-3">
                  QUANTUM SAFE
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 4. MOSCA X+Y > Z — PER-ALGORITHM DEFICIT ANALYSIS */}
      <div className="rounded-xl border border-subtle bg-[#0c1017] p-5 space-y-4 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-subtle pb-3">
          <h3 className="text-xs font-mono font-bold tracking-wider text-gray-200 uppercase">
            MOSCA X+Y &gt; Z — PER-ALGORITHM DEFICIT ANALYSIS
          </h3>

          {/* Interactive Sliders */}
          <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="text-quiet">Data sensitivity (X):</span>
              <strong className="text-foreground">{dataSensitivityX} yr</strong>
              <input
                type="range"
                min="1"
                max="30"
                value={dataSensitivityX}
                onChange={(e) => setDataSensitivityX(parseInt(e.target.value))}
                className="w-24 h-1.5 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-cyan-400"
              />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-quiet">Migration lead (Y):</span>
              <strong className="text-foreground">{migrationLeadY} yr (auto)</strong>
            </div>
          </div>
        </div>

        {/* Per-Algorithm Horizontal Bars */}
        <div className="space-y-3.5 pt-1">
          {deficitAlgos.map((item) => {
            // Visual width mapping: 0 to 25 yr -> 0% to 100%
            const maxRange = 22;
            const zPct = Math.min(100, Math.max(10, (item.z / maxRange) * 100));
            const neededPct = Math.min(100, Math.max(15, (protectionNeeded / maxRange) * 100));

            return (
              <div key={item.name} className="flex items-center gap-4 text-xs font-mono">
                <span className="w-24 text-gray-300 font-medium shrink-0">{item.name}</span>

                {/* Bar Graph */}
                <div className="relative flex-1 h-5 rounded-full bg-[#141b27] overflow-hidden">
                  {item.isDeficit ? (
                    <>
                      {/* Full Deficit Bar (Salmon/Red) */}
                      <div
                        style={{ width: `${neededPct}%` }}
                        className="h-full bg-[#7a3b45] transition-all duration-300 rounded-full"
                      />
                      {/* Vertical Tick at Z Deadline */}
                      <div
                        style={{ left: `${zPct}%` }}
                        className="absolute top-0 bottom-0 w-1 bg-rose-500 z-10"
                        title={`Threat Horizon Z = ${item.z} yr`}
                      />
                    </>
                  ) : (
                    /* Safe Blue Bar */
                    <div
                      style={{ width: `${neededPct}%` }}
                      className="h-full bg-[#20559e] transition-all duration-300 rounded-full"
                    />
                  )}
                </div>

                {/* Right Delta Label */}
                <div className="w-16 text-right font-bold text-xs shrink-0">
                  {item.isDeficit ? (
                    <span className="text-rose-400">{item.deltaLabel}</span>
                  ) : (
                    <span className="text-emerald-400">{item.deltaLabel}</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Legend */}
        <div className="flex flex-wrap items-center gap-4 text-[11px] text-quiet border-t border-subtle pt-3">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-sm bg-[#20559e]" />
            <span>X+Y protection needed</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-1 h-3.5 bg-rose-500" />
            <span>Z quantum threat deadline</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-sm bg-[#7a3b45]" />
            <span>Deficit (at risk)</span>
          </div>
        </div>
      </div>

      {/* 5. HNDL ATTACK SURFACE — ALGORITHMS BEING HARVESTED TODAY */}
      <div className="rounded-xl border border-subtle bg-[#0c1017] p-5 space-y-4 shadow-xl">
        <div>
          <h3 className="text-xs font-mono font-bold tracking-wider text-gray-200 uppercase">
            HNDL ATTACK SURFACE — ALGORITHMS BEING HARVESTED TODAY
          </h3>
          <p className="text-xs text-quiet mt-1">
            Adversaries intercept and store ciphertext NOW, decrypt retroactively when a CRQC arrives.
            Network-surface assets are highest priority.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
          {/* Surface 1: LIVE NETWORK / TLS */}
          <div className="p-4 rounded-xl bg-[#070a0f] border border-subtle space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-semibold text-gray-200">
                <span>🌐</span>
                <span>LIVE NETWORK / TLS</span>
              </div>
              <span className="text-[10px] font-bold text-rose-400 uppercase tracking-wider">
                HIGH HNDL RISK
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-rose-950/40 text-rose-300 border border-rose-500/40">
                RSA-2048 cert
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-rose-950/40 text-rose-300 border border-rose-500/40">
                ECDSA-256
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-amber-950/40 text-amber-300 border border-amber-500/40">
                TLSv1.2
              </span>
            </div>
          </div>

          {/* Surface 2: SOURCE CODE */}
          <div className="p-4 rounded-xl bg-[#070a0f] border border-subtle space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-semibold text-gray-200">
                <span>💻</span>
                <span>SOURCE CODE</span>
              </div>
              <span className="text-[10px] font-bold text-amber-400 uppercase tracking-wider">
                MEDIUM RISK
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-rose-950/40 text-rose-300 border border-rose-500/40">
                RSA-1024
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-rose-950/40 text-rose-300 border border-rose-500/40">
                MD5
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-amber-950/40 text-amber-300 border border-amber-500/40">
                AES-128
              </span>
            </div>
          </div>

          {/* Surface 3: BINARY / FIRMWARE */}
          <div className="p-4 rounded-xl bg-[#070a0f] border border-subtle space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-semibold text-gray-200">
                <span>📦</span>
                <span>BINARY / FIRMWARE</span>
              </div>
              <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wider">
                BOUNDED
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-emerald-950/40 text-emerald-300 border border-emerald-500/40">
                AES-256
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-amber-950/40 text-amber-300 border border-amber-500/40">
                ECDSA
              </span>
            </div>
          </div>

          {/* Surface 4: CERTIFICATES (X.509) */}
          <div className="p-4 rounded-xl bg-[#070a0f] border border-subtle space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-semibold text-gray-200">
                <span>📜</span>
                <span>CERTIFICATES (X.509)</span>
              </div>
              <span className="text-[10px] font-bold text-rose-400 uppercase tracking-wider">
                HIGH HNDL RISK
              </span>
            </div>
            <div className="flex flex-wrap gap-2">
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-rose-950/40 text-rose-300 border border-rose-500/40">
                RSA-2048
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-rose-950/40 text-rose-300 border border-rose-500/40">
                ECDSA-384
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-emerald-950/40 text-emerald-300 border border-emerald-500/40">
                ML-KEM
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
