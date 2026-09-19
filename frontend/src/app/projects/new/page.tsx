"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ShieldCheck, ArrowLeft, ArrowRight, Building, Lock, Clock, AlertTriangle, Layers } from "lucide-react";
import { ThemeToggle } from "@/components/ecdat/theme-toggle";

export default function NewProjectPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [projectId, setProjectId] = useState("");
  const [description, setDescription] = useState("");
  const [organization, setOrganization] = useState("Enterprise Cyber Operations");
  const [environment, setEnvironment] = useState("Production");
  const [criticality, setCriticality] = useState("Critical");
  const [sensitivity, setSensitivity] = useState("Sensitive");
  const [lifetimeYears, setLifetimeYears] = useState(20);
  const [targetDate, setTargetDate] = useState("2030-01-01");
  const [tagsInput, setTagsInput] = useState("core, production, hndl-critical");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const rawId = projectId.trim() || name.trim();
    const finalId = rawId
      .toLowerCase()
      .replace(/[^a-z0-9_-]/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 32) || `proj-${Date.now()}`;

    const tags = tagsInput
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);

    try {
      const res = await fetch("/api/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: finalId,
          name,
          description,
          organization,
          environment,
          business_criticality: criticality,
          data_sensitivity: sensitivity,
          data_lifetime_years: Number(lifetimeYears),
          migration_target_date: targetDate || null,
          tags,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Failed to create project");
      }

      router.push(`/projects/${data.id}`);
    } catch (err: any) {
      setError(err.message || "Project initialization failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-canvas text-foreground flex flex-col">
      <header className="border-b border-subtle bg-surface/50 backdrop-blur sticky top-0 z-20 px-4 sm:px-8 py-3.5 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link href="/projects" className="p-1.5 rounded-lg border border-subtle hover:border-cyan-500/40 text-quiet hover:text-foreground transition-colors">
            <ArrowLeft className="h-4 w-4" />
          </Link>
          <div className="flex items-center gap-2">
            <div className="h-7 w-7 rounded bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold">
              <ShieldCheck className="h-4 w-4" />
            </div>
            <span className="font-semibold text-sm">New Cryptographic Project</span>
          </div>
        </div>
        <ThemeToggle />
      </header>

      <main className="flex-1 max-w-3xl w-full mx-auto px-4 sm:px-8 py-10">
        <div className="rounded-xl border border-subtle bg-surface p-6 sm:p-8 shadow-xl">
          <div className="mb-6">
            <h1 className="text-xl font-bold tracking-tight">Define Cryptographic Boundary</h1>
            <p className="text-xs text-quiet mt-1">
              Configure project parameters, business criticality, and data confidentiality lifetime for PQC risk modeling.
            </p>
          </div>

          {error && (
            <div className="mb-6 p-3.5 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-400 text-xs flex items-start gap-2.5">
              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-foreground mb-1.5">Project Name *</label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => {
                    setName(e.target.value);
                    if (!projectId) {
                      setProjectId(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, "-").slice(0, 32));
                    }
                  }}
                  className="w-full px-3 py-2 text-xs rounded-lg border border-subtle bg-canvas text-foreground placeholder:text-quiet outline-none focus:border-cyan-500"
                  placeholder="e.g. Global Payment Settlement Gateway"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-foreground mb-1.5">Project Identifier (Slug)</label>
                <input
                  type="text"
                  value={projectId}
                  onChange={(e) => setProjectId(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-lg border border-subtle bg-canvas font-mono text-cyan-400 placeholder:text-quiet outline-none focus:border-cyan-500"
                  placeholder="e.g. payment-gateway"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-foreground mb-1.5">Business Unit / Organization</label>
              <input
                type="text"
                value={organization}
                onChange={(e) => setOrganization(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-lg border border-subtle bg-canvas text-foreground placeholder:text-quiet outline-none focus:border-cyan-500"
                placeholder="e.g. Defense Communications Command"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-foreground mb-1.5">Scope Description</label>
              <textarea
                rows={2}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-lg border border-subtle bg-canvas text-foreground placeholder:text-quiet outline-none focus:border-cyan-500 resize-none"
                placeholder="Cryptographic boundary protecting customer PII, payment tokens, and external TLS termination..."
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2 border-t border-subtle">
              <div>
                <label className="block text-xs font-semibold text-foreground mb-1.5">Environment</label>
                <select
                  value={environment}
                  onChange={(e) => setEnvironment(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-lg border border-subtle bg-canvas text-foreground outline-none focus:border-cyan-500"
                >
                  <option value="Production">Production</option>
                  <option value="Staging">Staging</option>
                  <option value="Development">Development</option>
                  <option value="Research">Research</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-foreground mb-1.5">Business Criticality</label>
                <select
                  value={criticality}
                  onChange={(e) => setCriticality(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-lg border border-subtle bg-canvas text-foreground outline-none focus:border-cyan-500"
                >
                  <option value="Critical">Critical (Tier 1)</option>
                  <option value="High">High (Tier 2)</option>
                  <option value="Medium">Medium (Internal)</option>
                  <option value="Low">Low (Dev/Test)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-foreground mb-1.5">Data Sensitivity</label>
                <select
                  value={sensitivity}
                  onChange={(e) => setSensitivity(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-lg border border-subtle bg-canvas text-foreground outline-none focus:border-cyan-500"
                >
                  <option value="Classified">Classified / Secret</option>
                  <option value="Sensitive">Sensitive / Regulated</option>
                  <option value="Confidential">Confidential</option>
                  <option value="Internal">Internal</option>
                  <option value="Public">Public</option>
                </select>
              </div>
            </div>

            <div className="pt-2 border-t border-subtle">
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                  <Clock className="h-3.5 w-3.5 text-cyan-400" />
                  Expected Data Confidentiality Lifetime (X Parameter)
                </label>
                <span className="text-xs font-mono font-bold text-cyan-400">{lifetimeYears} Years</span>
              </div>
              <input
                type="range"
                min={1}
                max={50}
                value={lifetimeYears}
                onChange={(e) => setLifetimeYears(Number(e.target.value))}
                className="w-full h-1.5 bg-subtle rounded-lg appearance-none cursor-pointer accent-cyan-500"
              />
              <p className="text-[11px] text-quiet mt-1.5">
                Feeds directly into Mosca&apos;s Theorem (X + Y &gt; Z) to evaluate Harvest Now, Decrypt Later (HNDL) exposure.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-subtle">
              <div>
                <label className="block text-xs font-semibold text-foreground mb-1.5">PQC Cutover Target Date</label>
                <input
                  type="date"
                  value={targetDate}
                  onChange={(e) => setTargetDate(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-lg border border-subtle bg-canvas text-foreground outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-foreground mb-1.5">Tags (comma-separated)</label>
                <input
                  type="text"
                  value={tagsInput}
                  onChange={(e) => setTagsInput(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-lg border border-subtle bg-canvas text-foreground placeholder:text-quiet outline-none focus:border-cyan-500"
                  placeholder="swift, scada, core"
                />
              </div>
            </div>

            <div className="pt-4 border-t border-subtle flex items-center justify-end gap-3">
              <Link
                href="/projects"
                className="px-4 py-2 text-xs text-quiet hover:text-foreground font-medium transition-colors"
              >
                Cancel
              </Link>
              <button
                type="submit"
                disabled={loading || !name}
                className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-colors disabled:opacity-50"
              >
                {loading ? "Initializing..." : "Create Project Workspace"}
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </form>
        </div>
      </main>
    </div>
  );
}
