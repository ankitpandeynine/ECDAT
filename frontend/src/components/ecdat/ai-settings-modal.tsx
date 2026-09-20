"use client";

import React, { useState, useEffect } from "react";
import {
  X,
  Sparkles,
  Key,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  ExternalLink,
  ShieldAlert,
  Eye,
  EyeOff
} from "lucide-react";

export interface AISettings {
  provider: "auto" | "gemini" | "nvidia";
  geminiKey: string;
  nvidiaKey: string;
}

interface AISettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSettingsSaved?: (settings: AISettings) => void;
}

export function AISettingsModal({ isOpen, onClose, onSettingsSaved }: AISettingsModalProps) {
  const [provider, setProvider] = useState<"auto" | "gemini" | "nvidia">("auto");
  const [geminiKey, setGeminiKey] = useState("");
  const [nvidiaKey, setNvidiaKey] = useState("");
  const [showGeminiKey, setShowGeminiKey] = useState(false);
  const [showNvidiaKey, setShowNvidiaKey] = useState(false);

  const [testingGemini, setTestingGemini] = useState(false);
  const [testingNvidia, setTestingNvidia] = useState(false);
  const [geminiStatus, setGeminiStatus] = useState<{ ok?: boolean; msg?: string } | null>(null);
  const [nvidiaStatus, setNvidiaStatus] = useState<{ ok?: boolean; msg?: string } | null>(null);
  const [saveSuccess, setSaveSuccess] = useState(false);

  useEffect(() => {
    try {
      const stored = localStorage.getItem("ecdat_ai_settings");
      if (stored) {
        const parsed: AISettings = JSON.parse(stored);
        if (parsed.provider) setProvider(parsed.provider);
        if (parsed.geminiKey) setGeminiKey(parsed.geminiKey);
        if (parsed.nvidiaKey) setNvidiaKey(parsed.nvidiaKey);
      }
    } catch {
      // ignore
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const testKey = async (target: "gemini" | "nvidia") => {
    const key = target === "gemini" ? geminiKey : nvidiaKey;
    if (!key.trim()) {
      if (target === "gemini") setGeminiStatus({ ok: false, msg: "Please enter an API key first." });
      else setNvidiaStatus({ ok: false, msg: "Please enter an API key first." });
      return;
    }

    if (target === "gemini") {
      setTestingGemini(true);
      setGeminiStatus(null);
    } else {
      setTestingNvidia(true);
      setNvidiaStatus(null);
    }

    try {
      const res = await fetch("/api/ai/test-key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: target, api_key: key.trim() })
      });
      const data = await res.json();
      if (data.ok) {
        if (target === "gemini") setGeminiStatus({ ok: true, msg: data.message || "Connection verified!" });
        else setNvidiaStatus({ ok: true, msg: data.message || "Connection verified!" });
      } else {
        if (target === "gemini") setGeminiStatus({ ok: false, msg: data.error || "Connection failed." });
        else setNvidiaStatus({ ok: false, msg: data.error || "Connection failed." });
      }
    } catch (err: any) {
      if (target === "gemini") setGeminiStatus({ ok: false, msg: err.message || "Network error." });
      else setNvidiaStatus({ ok: false, msg: err.message || "Network error." });
    } finally {
      if (target === "gemini") setTestingGemini(false);
      else setTestingNvidia(false);
    }
  };

  const handleSave = () => {
    const settings: AISettings = {
      provider,
      geminiKey: geminiKey.trim(),
      nvidiaKey: nvidiaKey.trim()
    };
    try {
      localStorage.setItem("ecdat_ai_settings", JSON.stringify(settings));
    } catch {
      // ignore
    }
    setSaveSuccess(true);
    if (onSettingsSaved) onSettingsSaved(settings);
    setTimeout(() => {
      setSaveSuccess(false);
      onClose();
    }, 600);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="relative w-full max-w-lg rounded-2xl border border-subtle bg-surface shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-subtle bg-canvas/60">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Sparkles size={18} />
            </div>
            <div>
              <h2 className="text-base font-bold text-foreground">AI Intelligence Settings</h2>
              <p className="text-xs text-muted-foreground">Configure Google AI Studio (Gemini) &amp; NVIDIA NIM APIs</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-surface border border-transparent hover:border-subtle transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto">
          {/* Provider Selection */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-foreground uppercase tracking-wider">
              Preferred Intelligence Provider
            </label>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setProvider("auto")}
                className={`px-3 py-2.5 rounded-xl border text-xs font-medium text-center transition-all ${
                  provider === "auto"
                    ? "border-cyan-500 bg-cyan-500/15 text-cyan-400 font-semibold"
                    : "border-subtle bg-canvas text-muted-foreground hover:text-foreground"
                }`}
              >
                <Sparkles size={14} className="mx-auto mb-1" />
                Auto (Smart)
              </button>
              <button
                type="button"
                onClick={() => setProvider("gemini")}
                className={`px-3 py-2.5 rounded-xl border text-xs font-medium text-center transition-all ${
                  provider === "gemini"
                    ? "border-blue-500 bg-blue-500/15 text-blue-400 font-semibold"
                    : "border-subtle bg-canvas text-muted-foreground hover:text-foreground"
                }`}
              >
                <Cpu size={14} className="mx-auto mb-1" />
                Google Gemini
              </button>
              <button
                type="button"
                onClick={() => setProvider("nvidia")}
                className={`px-3 py-2.5 rounded-xl border text-xs font-medium text-center transition-all ${
                  provider === "nvidia"
                    ? "border-emerald-500 bg-emerald-500/15 text-emerald-400 font-semibold"
                    : "border-subtle bg-canvas text-muted-foreground hover:text-foreground"
                }`}
              >
                <Key size={14} className="mx-auto mb-1" />
                NVIDIA NIM
              </button>
            </div>
            <p className="text-[11px] text-muted-foreground">
              If no keys are provided, ECDAT automatically falls back to its deterministic cryptographic knowledge engine.
            </p>
          </div>

          {/* Gemini API Key */}
          <div className="space-y-2 p-3.5 rounded-xl border border-subtle bg-canvas/40">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-blue-500" />
                <span className="text-xs font-semibold text-foreground">Google AI Studio (Gemini API)</span>
              </div>
              <a
                href="https://aistudio.google.com/app/apikey"
                target="_blank"
                rel="noreferrer"
                className="text-[11px] text-cyan-400 hover:underline inline-flex items-center gap-1"
              >
                Get Key <ExternalLink size={10} />
              </a>
            </div>
            <div className="relative">
              <input
                type={showGeminiKey ? "text" : "password"}
                value={geminiKey}
                onChange={(e) => setGeminiKey(e.target.value)}
                placeholder="AIzaSy..."
                className="w-full px-3 py-2 pr-20 text-xs font-mono rounded-lg bg-surface border border-subtle focus:border-blue-500 text-foreground outline-none transition-colors"
              />
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => setShowGeminiKey(!showGeminiKey)}
                  className="p-1 text-muted-foreground hover:text-foreground"
                >
                  {showGeminiKey ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
                <button
                  type="button"
                  onClick={() => testKey("gemini")}
                  disabled={testingGemini || !geminiKey.trim()}
                  className="px-2 py-0.5 text-[10px] font-medium rounded bg-blue-500/20 text-blue-400 hover:bg-blue-500/30 border border-blue-500/30 disabled:opacity-40 transition-colors"
                >
                  {testingGemini ? <Loader2 size={10} className="animate-spin" /> : "Test"}
                </button>
              </div>
            </div>
            {geminiStatus && (
              <div
                className={`text-[11px] flex items-center gap-1.5 ${
                  geminiStatus.ok ? "text-emerald-400" : "text-rose-400"
                }`}
              >
                {geminiStatus.ok ? <CheckCircle2 size={12} /> : <AlertTriangle size={12} />}
                <span>{geminiStatus.msg}</span>
              </div>
            )}
          </div>

          {/* NVIDIA NIM API Key */}
          <div className="space-y-2 p-3.5 rounded-xl border border-subtle bg-canvas/40">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                <span className="text-xs font-semibold text-foreground">NVIDIA NIM API Key</span>
              </div>
              <a
                href="https://build.nvidia.com"
                target="_blank"
                rel="noreferrer"
                className="text-[11px] text-cyan-400 hover:underline inline-flex items-center gap-1"
              >
                Get Key <ExternalLink size={10} />
              </a>
            </div>
            <div className="relative">
              <input
                type={showNvidiaKey ? "text" : "password"}
                value={nvidiaKey}
                onChange={(e) => setNvidiaKey(e.target.value)}
                placeholder="nvapi-..."
                className="w-full px-3 py-2 pr-20 text-xs font-mono rounded-lg bg-surface border border-subtle focus:border-emerald-500 text-foreground outline-none transition-colors"
              />
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => setShowNvidiaKey(!showNvidiaKey)}
                  className="p-1 text-muted-foreground hover:text-foreground"
                >
                  {showNvidiaKey ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
                <button
                  type="button"
                  onClick={() => testKey("nvidia")}
                  disabled={testingNvidia || !nvidiaKey.trim()}
                  className="px-2 py-0.5 text-[10px] font-medium rounded bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30 border border-emerald-500/30 disabled:opacity-40 transition-colors"
                >
                  {testingNvidia ? <Loader2 size={10} className="animate-spin" /> : "Test"}
                </button>
              </div>
            </div>
            {nvidiaStatus && (
              <div
                className={`text-[11px] flex items-center gap-1.5 ${
                  nvidiaStatus.ok ? "text-emerald-400" : "text-rose-400"
                }`}
              >
                {nvidiaStatus.ok ? <CheckCircle2 size={12} /> : <AlertTriangle size={12} />}
                <span>{nvidiaStatus.msg}</span>
              </div>
            )}
          </div>

          {/* Epistemic disclaimer */}
          <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 text-[11px] text-amber-300 flex items-start gap-2">
            <ShieldAlert size={15} className="shrink-0 mt-0.5" />
            <span>
              <strong>ECDAT Section 46 Epistemic Notice:</strong> AI responses are assistive advisories for architectural planning and code understanding. Deterministic scan results and formal verification tests remain the ground truth.
            </span>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-subtle bg-canvas/60">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium rounded-lg text-muted-foreground hover:text-foreground hover:bg-surface border border-transparent hover:border-subtle transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            className="px-5 py-2 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition-all shadow-md flex items-center gap-1.5"
          >
            {saveSuccess ? (
              <>
                <CheckCircle2 size={14} className="text-white" />
                <span>Saved!</span>
              </>
            ) : (
              <span>Save &amp; Apply</span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
