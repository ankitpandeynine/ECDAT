"use client";

import React, { useState, useEffect, useRef } from "react";
import {
  X,
  Send,
  Sparkles,
  Bot,
  User,
  Settings,
  Trash2,
  Cpu,
  Key,
  ShieldAlert,
  Loader2,
  ChevronRight,
  Info,
  CheckCircle2,
  Layers,
  ArrowUpRight
} from "lucide-react";
import { AISettings } from "./ai-settings-modal";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  provider?: string;
  model?: string;
  timestamp: string;
  pageContext?: string;
}

interface AISidebarProps {
  isOpen: boolean;
  onClose: () => void;
  projectId: string;
  activePage: string;
  projectData?: any;
  assets?: any[];
  riskMetrics?: any;
  onOpenSettings: () => void;
}

export function AISidebar({
  isOpen,
  onClose,
  projectId,
  activePage,
  projectData,
  assets = [],
  riskMetrics,
  onOpenSettings
}: AISidebarProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome",
      role: "assistant",
      content: `Hello! I am the **ECDAT Security Intelligence Copilot**.\n\nI have complete contextual awareness of **${projectId}** and notice you are currently reviewing the **${activePage}** view.\n\nAsk me anything about your cryptographic posture, quantum vulnerability status, Mosca exposure, or remediation options!`,
      provider: "system",
      model: "ecdat_intelligence_v4",
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      pageContext: activePage
    }
  ]);
  const [inputQuestion, setInputQuestion] = useState("");
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Read saved settings
  const [aiSettings, setAiSettings] = useState<AISettings>({
    provider: "auto",
    geminiKey: "",
    nvidiaKey: ""
  });

  useEffect(() => {
    try {
      const stored = localStorage.getItem("ecdat_ai_settings");
      if (stored) setAiSettings(JSON.parse(stored));
    } catch {
      // ignore
    }
  }, [isOpen]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  if (!isOpen) return null;

  // Context summary metrics
  const totalAssetsCount = assets?.length || 0;
  const quantumVulnCount = assets?.filter((a: any) => a.quantum_vulnerable || a.quantum_risk === "HIGH" || a.quantum_risk === "CRITICAL").length || 0;
  const criticalCount = assets?.filter((a: any) => a.vulnerability_status === "BROKEN" || a.vulnerability_status === "CRITICAL" || a.priority === "FIX_NOW").length || 0;
  const currentSecurityScore = riskMetrics?.security_score ?? riskMetrics?.score ?? "78";
  const moscaDeficit = riskMetrics?.quantum_deficit_years ? `${riskMetrics.quantum_deficit_years}y` : "2.4y";

  // Dynamic suggestion chips based on active page
  const getSuggestions = () => {
    switch (activePage) {
      case "Network Scan":
        return [
          "Explain the TLS and cipher posture for this domain",
          "What security headers are missing and how do I fix them?",
          "Does this endpoint support HTTP/3 or PQC hybrid key exchange?"
        ];
      case "Quantum Risk":
      case "Mosca & HNDL":
        return [
          "Explain Mosca's theorem and my data shelf-life deficit",
          "Which algorithms are immediately vulnerable to Shor's algorithm?",
          "What is the recommended NIST FIPS 203/204 transition timeline?"
        ];
      case "Autonomous Loop":
      case "Auto-Patch Engine":
        return [
          "How does the AST-safe transformation engine prevent regressions?",
          "What is the difference between NIST Hybrid and CNSA 2.0 suites?",
          "How do I verify the patched archive after remediation?"
        ];
      case "Asset Inventory":
      case "Asset Graph":
        return [
          "Identify the highest priority cryptographic assets to migrate",
          "How many RSA keys are under 2048 bits in this project?",
          "Explain blast radius propagation if an asymmetric key is compromised"
        ];
      default:
        return [
          "Summarize my project's overall cryptographic health",
          "What are the top 3 post-quantum migration priorities?",
          "How does ECDAT classify broken vs deprecated algorithms?"
        ];
    }
  };

  const handleSendMessage = async (textToSend?: string) => {
    const query = (textToSend || inputQuestion).trim();
    if (!query || loading) return;

    const userMsg: Message = {
      id: Date.now().toString(),
      role: "user",
      content: query,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      pageContext: activePage
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuestion("");
    setLoading(true);

    try {
      const historyPayload = messages
        .filter((m) => m.id !== "welcome")
        .slice(-6)
        .map((m) => ({ role: m.role, content: m.content }));

      const contextPayload = {
        active_page: activePage,
        project_name: projectData?.name || projectId,
        total_assets: totalAssetsCount,
        quantum_vulnerable_assets: quantumVulnCount,
        critical_assets: criticalCount,
        security_score: currentSecurityScore,
        mosca_deficit: moscaDeficit,
        recent_findings: assets.slice(0, 6).map((a: any) => ({
          name: a.name || a.algorithm || "Asset",
          algorithm: a.algorithm,
          status: a.vulnerability_status || a.priority
        }))
      };

      const res = await fetch("/api/ai/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question: query,
          context: contextPayload,
          history: historyPayload,
          provider: aiSettings.provider,
          gemini_api_key: aiSettings.geminiKey || undefined,
          nvidia_api_key: aiSettings.nvidiaKey || undefined
        })
      });

      if (!res.ok) {
        throw new Error(`AI service returned ${res.statusText}`);
      }

      const data = await res.json();

      const assistantMsg: Message = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: data.reply || "No response received.",
        provider: data.provider,
        model: data.model,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        pageContext: activePage
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      const errorMsg: Message = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: `I encountered an issue processing your request: **${err.message || "Network error"}**. Please verify your AI settings.`,
        provider: "error",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        pageContext: activePage
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  const handleClearHistory = () => {
    setMessages([
      {
        id: "welcome",
        role: "assistant",
        content: `Chat history cleared. Context reset to **${projectId}** on page **${activePage}**.`,
        provider: "system",
        model: "ecdat_intelligence_v4",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        pageContext: activePage
      }
    ]);
  };

  return (
    <div className="fixed inset-y-0 right-0 z-40 w-full sm:w-[460px] md:w-[500px] bg-surface/95 backdrop-blur-md border-l border-subtle shadow-2xl flex flex-col transition-all animate-in slide-in-from-right duration-300">
      {/* Header */}
      <div className="px-5 py-4 border-b border-subtle flex items-center justify-between bg-canvas/60">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center text-white shadow-md">
            <Sparkles size={16} />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <h2 className="text-sm font-bold text-foreground">ECDAT Intelligence Copilot</h2>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 uppercase">
                {aiSettings.geminiKey ? "Gemini" : aiSettings.nvidiaKey ? "NVIDIA" : "Expert Engine"}
              </span>
            </div>
            <p className="text-[11px] text-muted-foreground truncate max-w-[240px]">
              Active Page: <span className="text-cyan-400 font-medium">{activePage}</span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1">
          <button
            onClick={onOpenSettings}
            title="Configure AI API Keys"
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-surface border border-transparent hover:border-subtle transition-colors"
          >
            <Settings size={16} />
          </button>
          <button
            onClick={handleClearHistory}
            title="Clear Chat"
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-surface border border-transparent hover:border-subtle transition-colors"
          >
            <Trash2 size={16} />
          </button>
          <button
            onClick={onClose}
            title="Close Sidebar"
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-surface border border-transparent hover:border-subtle transition-colors"
          >
            <X size={18} />
          </button>
        </div>
      </div>

      {/* Project Context Quick Strip */}
      <div className="px-4 py-2 bg-canvas/80 border-b border-subtle flex items-center justify-between text-[11px] font-mono text-muted-foreground">
        <span>Assets: <strong className="text-foreground">{totalAssetsCount}</strong></span>
        <span>Quantum Vuln: <strong className="text-amber-400">{quantumVulnCount}</strong></span>
        <span>Critical: <strong className="text-rose-400">{criticalCount}</strong></span>
        <span>Score: <strong className="text-cyan-400">{currentSecurityScore}/100</strong></span>
      </div>

      {/* Chat Messages Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((m) => (
          <div
            key={m.id}
            className={`flex flex-col ${m.role === "user" ? "items-end" : "items-start"}`}
          >
            <div className="flex items-center gap-1.5 mb-1 px-1">
              {m.role === "user" ? (
                <>
                  <span className="text-[10px] text-muted-foreground">{m.timestamp}</span>
                  <span className="text-xs font-semibold text-foreground">You</span>
                </>
              ) : (
                <>
                  <Bot size={13} className="text-cyan-400" />
                  <span className="text-xs font-semibold text-foreground">ECDAT Advisor</span>
                  {m.provider && (
                    <span className="text-[9px] font-mono px-1 rounded bg-surface border border-subtle text-muted-foreground uppercase">
                      {m.provider.replace("google_ai_studio_", "").replace("_engine", "")}
                    </span>
                  )}
                  <span className="text-[10px] text-muted-foreground">{m.timestamp}</span>
                </>
              )}
            </div>

            <div
              className={`p-3.5 rounded-2xl max-w-[92%] text-xs leading-relaxed ${
                m.role === "user"
                  ? "bg-gradient-to-br from-cyan-600 to-indigo-600 text-white rounded-tr-none shadow-md"
                  : "bg-canvas/90 border border-subtle text-foreground rounded-tl-none shadow-sm"
              }`}
            >
              {/* Parse lightweight markdown (bold, lists, code) */}
              <div className="space-y-2 whitespace-pre-wrap">
                {m.content.split("\n\n").map((para, i) => (
                  <p key={i}>
                    {para.split("\n").map((line, j) => {
                      // format bullets
                      if (line.startsWith("- ") || line.startsWith("* ")) {
                        return (
                          <span key={j} className="block pl-3 relative before:content-['•'] before:absolute before:left-0 before:text-cyan-400">
                            {line.slice(2)}
                          </span>
                        );
                      }
                      if (/^\d+\.\s/.test(line)) {
                        return (
                          <span key={j} className="block pl-3 font-medium text-foreground">
                            {line}
                          </span>
                        );
                      }
                      return (
                        <span key={j} className="block">
                          {line}
                        </span>
                      );
                    })}
                  </p>
                ))}
              </div>

              {m.role === "assistant" && (
                <div className="mt-2.5 pt-2 border-t border-subtle flex items-center justify-between text-[10px] text-muted-foreground">
                  <span className="inline-flex items-center gap-1 text-amber-400">
                    <ShieldAlert size={10} /> ADVISORY (Sec. 46)
                  </span>
                  {m.pageContext && (
                    <span className="font-mono text-muted-foreground/80 truncate max-w-[150px]">
                      ctx: {m.pageContext}
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-2 p-3 rounded-2xl bg-canvas border border-subtle text-xs text-muted-foreground max-w-[80%] animate-pulse">
            <Loader2 size={14} className="animate-spin text-cyan-400" />
            <span>Analyzing cryptographic context and generating advisory...</span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Suggested prompts strip */}
      <div className="px-4 py-2 border-t border-subtle bg-canvas/40">
        <div className="text-[10px] uppercase font-semibold text-muted-foreground mb-1.5 flex items-center gap-1">
          <Sparkles size={11} className="text-cyan-400" />
          <span>Suggested for {activePage}</span>
        </div>
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 no-scrollbar">
          {getSuggestions().map((s, idx) => (
            <button
              key={idx}
              onClick={() => handleSendMessage(s)}
              className="px-2.5 py-1 rounded-full text-[11px] whitespace-nowrap bg-surface hover:bg-surface/80 border border-subtle hover:border-cyan-500 text-muted-foreground hover:text-foreground transition-all shrink-0 flex items-center gap-1"
            >
              <span>{s}</span>
              <ArrowUpRight size={10} />
            </button>
          ))}
        </div>
      </div>

      {/* Input Form */}
      <div className="p-4 border-t border-subtle bg-surface">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSendMessage();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            value={inputQuestion}
            onChange={(e) => setInputQuestion(e.target.value)}
            placeholder={`Ask about ${activePage}, quantum risk, or assets...`}
            disabled={loading}
            className="flex-1 px-3.5 py-2.5 text-xs rounded-xl bg-canvas border border-subtle focus:border-cyan-500 text-foreground placeholder:text-muted-foreground outline-none transition-colors"
          />
          <button
            type="submit"
            disabled={!inputQuestion.trim() || loading}
            className="p-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-40 transition-all shadow-md cursor-pointer"
          >
            <Send size={15} />
          </button>
        </form>
      </div>
    </div>
  );
}
