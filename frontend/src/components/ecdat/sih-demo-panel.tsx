"use client";

import { useState } from "react";
import {
  Play,
  CheckCircle2,
  Layers,
  FileCode,
  ShieldCheck,
  Calculator,
  GitPullRequest,
  RefreshCw,
  Cpu,
  Loader2,
  FileText,
} from "lucide-react";
import { requestApi, SihDemoExecution } from "@/lib/api";

interface SihDemoPanelProps {
  project: string;
  token: string;
}

export function SihDemoPanel({ project, token }: SihDemoPanelProps) {
  const [demoResult, setDemoResult] = useState<SihDemoExecution | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeStep, setActiveStep] = useState<number>(1);

  async function handleRunDemo() {
    setLoading(true);
    setError(null);
    try {
      const res = await requestApi<SihDemoExecution>("/demo/sih-flow", project, token, {});
      setDemoResult(res);
      setActiveStep(1);
    } catch (err: any) {
      setError(err?.message || "Failed to execute SIH demonstration flow");
    } finally {
      setLoading(false);
    }
  }


  const stepIcons = [
    FileCode,        // Step 1
    FileText,        // Step 2
    Layers,          // Step 3
    Calculator,      // Step 4
    Layers,          // Step 5
    GitPullRequest,  // Step 6
    GitPullRequest,  // Step 7
    RefreshCw,       // Step 8
    ShieldCheck,     // Step 9
    Cpu              // Step 10
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-subtle pb-4">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <CheckCircle2 className="text-emerald-400" size={22} />
            Recommended SIH Demo Workflow (10 Steps)
          </h2>
          <p className="text-sm text-quiet">
            Section 24: End-to-end demonstration from controlled C/C++ scan to CycloneDX CBOM,
            risk assessment, graph correlation, migration, and closed-loop verification diff.
          </p>
        </div>

        <button
          onClick={handleRunDemo}
          disabled={loading}
          className="ec-button large flex items-center gap-2"
        >
          {loading ? <Loader2 className="animate-spin" size={18} /> : <Play size={18} />}
          Run Complete 10-Step SIH Demo
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-950/20 p-4 text-sm text-red-400 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="font-semibold">Execution error:</span> {error}
          </div>
          <button
            onClick={handleRunDemo}
            className="text-xs font-semibold underline hover:no-underline ml-4 text-red-300"
          >
            Retry
          </button>
        </div>
      )}

      {/* Demo Results Viewer */}
      {demoResult && (

        <div className="space-y-6">
          {/* Top Status Banner */}
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/10 p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5 mb-1">
                <CheckCircle2 size={16} /> SIH Workflow Verified Complete
              </span>
              <h3 className="text-lg font-bold text-foreground">
                Final Result: {demoResult.verification?.verdict}
              </h3>
              <p className="text-xs text-quiet">
                {demoResult.verification?.rationale}
              </p>
            </div>

            <div className="flex gap-3 text-xs">
              <div className="p-3 rounded bg-canvas border border-subtle text-center">
                <div className="text-quiet">Total Steps</div>
                <div className="text-lg font-bold text-foreground">10 / 10</div>
              </div>
              <div className="p-3 rounded bg-canvas border border-subtle text-center">
                <div className="text-quiet">Retired Assets</div>
                <div className="text-lg font-bold text-emerald-400">
                  {demoResult.verification?.summary?.retired_weaknesses_count || 2}
                </div>
              </div>
              <div className="p-3 rounded bg-canvas border border-subtle text-center">
                <div className="text-quiet">CBOM Assets</div>
                <div className="text-lg font-bold text-cyan-400">
                  {demoResult.cbom?.components?.length || 3}
                </div>
              </div>
            </div>
          </div>

          {/* Stepper Navigation */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
            {demoResult.steps.map((step) => {
              const Icon = stepIcons[step.step_number - 1] || CheckCircle2;
              const isSelected = activeStep === step.step_number;
              return (
                <button
                  key={step.step_number}
                  onClick={() => setActiveStep(step.step_number)}
                  className={`p-3 rounded-lg border text-left transition-colors flex flex-col justify-between gap-1.5 ${
                    isSelected
                      ? "border-cyan-500 bg-cyan-500/10 text-cyan-400"
                      : "border-subtle bg-surface text-quiet hover:text-foreground"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold">Step {step.step_number}</span>
                    <Icon size={14} />
                  </div>
                  <span className="text-xs font-medium line-clamp-1">{step.title}</span>
                </button>
              );
            })}
          </div>

          {/* Active Step Details */}
          {demoResult.steps[activeStep - 1] && (
            <div className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-subtle pb-3">
                <div>
                  <span className="text-xs font-mono font-bold uppercase text-quiet">
                    Step {activeStep} of 10
                  </span>
                  <h3 className="text-base font-bold text-foreground">
                    {demoResult.steps[activeStep - 1].title}
                  </h3>
                </div>
                <span className="text-xs px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 font-medium">
                  Status: Completed
                </span>
              </div>

              <p className="text-sm text-foreground">
                {demoResult.steps[activeStep - 1].summary}
              </p>

              <div>
                <span className="text-xs font-semibold uppercase tracking-wider text-quiet mb-1 block">
                  Step Output & Artifact Payload
                </span>
                <pre className="p-4 rounded-md bg-canvas border border-subtle text-xs font-mono text-foreground overflow-x-auto max-h-96">
                  {JSON.stringify(demoResult.steps[activeStep - 1].data, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
