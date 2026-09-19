"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  Plus,
  Search,
  Building,
  Clock,
  Layers,
  ArrowRight,
  Filter,
  Flame,
  Radio,
  Lock,
  Globe
} from "lucide-react";
import { ThemeToggle } from "@/components/ecdat/theme-toggle";
import { Project } from "@/lib/api";

export default function ProjectsCatalogPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [envFilter, setEnvFilter] = useState("ALL");
  const [criticalityFilter, setCriticalityFilter] = useState("ALL");

  const loadProjects = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/projects");
      if (res.ok) {
        const data = await res.json();
        setProjects(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadProjects();
  }, []);

  const filtered = projects.filter((p) => {
    const matchSearch =
      !search ||
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      p.id.toLowerCase().includes(search.toLowerCase()) ||
      (p.organization && p.organization.toLowerCase().includes(search.toLowerCase()));

    const matchEnv = envFilter === "ALL" || p.environment === envFilter;
    const matchCrit = criticalityFilter === "ALL" || p.business_criticality === criticalityFilter;
    return matchSearch && matchEnv && matchCrit;
  });

  return (
    <div className="min-h-screen bg-canvas text-foreground flex flex-col">
      {/* Top Header */}
      <header className="ecdat-topbar">
        <div className="ecdat-topbar-left">
          <Link href="/" className="ecdat-brand">
            <ShieldCheck className="h-5 w-5" />
            <span className="ecdat-brand-text">ECDAT</span>
          </Link>
          <nav className="hidden sm:flex items-center gap-4 text-xs font-medium">
            <Link href="/dashboard" className="text-quiet hover:text-foreground">Command Center</Link>
            <Link href="/projects" className="text-cyan-400">Projects</Link>
          </nav>
        </div>

        <div className="ecdat-topbar-right">
          <Link
            href="/projects/new"
            className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition-colors flex items-center gap-1.5 shadow-sm"
          >
            <Plus className="h-3.5 w-3.5" />
            New Project
          </Link>
          <ThemeToggle />
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-8 py-8">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Enterprise Projects</h1>
            <p className="text-xs text-quiet mt-1">
              Inventory of cryptographic perimeters, business applications, and infrastructure projects.
            </p>
          </div>

          <div className="flex items-center gap-3">
            {/* Search Input */}
            <div className="relative min-w-[220px]">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-quiet" />
              <input
                type="text"
                placeholder="Search projects..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 text-xs rounded-lg border border-subtle bg-surface text-foreground placeholder:text-quiet outline-none focus:border-cyan-500"
              />
            </div>

            {/* Environment Filter */}
            <select
              value={envFilter}
              onChange={(e) => setEnvFilter(e.target.value)}
              className="px-2.5 py-1.5 text-xs rounded-lg border border-subtle bg-surface text-foreground outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Environments</option>
              <option value="Production">Production</option>
              <option value="Staging">Staging</option>
              <option value="Development">Development</option>
              <option value="Research">Research</option>
            </select>

            {/* Criticality Filter */}
            <select
              value={criticalityFilter}
              onChange={(e) => setCriticalityFilter(e.target.value)}
              className="px-2.5 py-1.5 text-xs rounded-lg border border-subtle bg-surface text-foreground outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Criticalities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        </div>

        {/* Project Grid */}
        {loading ? (
          <div className="py-20 text-center text-xs text-quiet">Loading enterprise project catalog...</div>
        ) : filtered.length === 0 ? (
          <div className="rounded-xl border border-subtle bg-surface p-12 text-center">
            <Layers className="h-10 w-10 text-quiet mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-foreground">No projects match criteria</h3>
            <p className="text-xs text-quiet mt-1 max-w-sm mx-auto">
              Create a new cryptographic boundary or adjust your search filters.
            </p>
            <Link
              href="/projects/new"
              className="mt-4 inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium"
            >
              <Plus className="h-3.5 w-3.5" />
              Create Project
            </Link>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 stagger-children">
            {filtered.map((proj) => (
              <div
                key={proj.id}
                className="rounded-xl border border-subtle bg-surface hover:border-cyan-500/40 p-5 flex flex-col justify-between transition-all group hover:shadow-lg hover:shadow-cyan-500/5"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-3">
                    <span className="font-mono text-[11px] text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded">
                      {proj.id}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`text-[10px] font-semibold px-2 py-0.5 rounded uppercase tracking-wider ${
                          proj.environment === "Production"
                            ? "bg-rose-500/10 border border-rose-500/20 text-rose-400"
                            : proj.environment === "Staging"
                            ? "bg-amber-500/10 border border-amber-500/20 text-amber-400"
                            : "bg-blue-500/10 border border-blue-500/20 text-blue-400"
                        }`}
                      >
                        {proj.environment}
                      </span>
                      <span
                        className={`text-[10px] font-semibold px-2 py-0.5 rounded uppercase tracking-wider ${
                          proj.business_criticality === "Critical"
                            ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                            : "bg-subtle text-quiet"
                        }`}
                      >
                        {proj.business_criticality}
                      </span>
                    </div>
                  </div>

                  <h3 className="font-semibold text-base text-foreground group-hover:text-cyan-400 transition-colors">
                    {proj.name}
                  </h3>
                  <p className="text-xs text-quiet mt-1 line-clamp-2">
                    {proj.description || "No project description provided."}
                  </p>

                  <div className="mt-4 pt-3 border-t border-subtle/60 grid grid-cols-3 gap-2 text-center text-xs">
                    <div className="bg-canvas/50 p-2 rounded-lg border border-subtle/40">
                      <div className="font-bold text-foreground text-sm">
                        {proj.metrics?.asset_count ?? 0}
                      </div>
                      <div className="text-[10px] text-quiet mt-0.5">Assets</div>
                    </div>
                    <div className="bg-canvas/50 p-2 rounded-lg border border-subtle/40">
                      <div className="font-bold text-rose-400 text-sm">
                        {proj.metrics?.quantum_risk_count ?? 0}
                      </div>
                      <div className="text-[10px] text-quiet mt-0.5">Q-Risks</div>
                    </div>
                    <div className="bg-canvas/50 p-2 rounded-lg border border-subtle/40">
                      <div className="font-bold text-foreground text-sm">
                        {proj.metrics?.scan_count ?? 0}
                      </div>
                      <div className="text-[10px] text-quiet mt-0.5">Scans</div>
                    </div>
                  </div>

                  <div className="mt-3 flex items-center justify-between text-[11px] text-quiet">
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {proj.data_lifetime_years} yr lifetime
                    </span>
                    <span className="flex items-center gap-1 text-cyan-400/80">
                      <Lock className="h-3 w-3" />
                      {proj.data_sensitivity}
                    </span>
                  </div>
                </div>

                <div className="mt-5 pt-3 border-t border-subtle flex items-center justify-between">
                  <span className="text-[10px] font-mono text-quiet">
                    {proj.metrics?.last_scan_at ? `Scanned ${new Date(proj.metrics.last_scan_at).toLocaleDateString()}` : "Not scanned"}
                  </span>
                  <Link
                    href={`/projects/${proj.id}`}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition-colors"
                  >
                    Open Workspace
                    <ArrowRight className="h-3.5 w-3.5" />
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
