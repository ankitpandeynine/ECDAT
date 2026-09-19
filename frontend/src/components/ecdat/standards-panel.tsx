"use client";

import { useState, useEffect } from "react";
import {
  ShieldCheck,
  Scale,
  ExternalLink,
  Calendar,
  AlertCircle,
  FileCheck,
} from "lucide-react";
import { requestApi, StandardMapping } from "@/lib/api";

interface StandardsPanelProps {
  project: string;
  token: string;
}

export function StandardsPanel({ project, token }: StandardsPanelProps) {
  const [catalog, setCatalog] = useState<{
    frameworks: Array<{ name: string; status: string }>;
    mappings: StandardMapping[];
  } | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadStandards();
  }, [project, token]);

  async function loadStandards() {
    setLoading(true);
    try {
      const res = await requestApi<any>("/standards/mapping", project, token);
      setCatalog(res);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-subtle pb-4">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <Scale className="text-cyan-400" size={22} />
            Standards & Regulatory Compliance Matrix
          </h2>
          <p className="text-sm text-quiet">
            Section 21: Explicit, versioned mapping of all cryptographic findings to NIST FIPS 203/204/205,
            Commercial National Security Algorithm Suite (CNSA 2.0), and OMB M-23-02 directives.
          </p>
        </div>
      </div>

      {/* Framework Badges */}
      {catalog && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {catalog.frameworks.map((fw, idx) => (
            <div key={idx} className="p-3.5 rounded-lg border border-subtle bg-surface">
              <div className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-1">
                {fw.status}
              </div>
              <div className="text-sm font-bold text-foreground">{fw.name}</div>
            </div>
          ))}
        </div>
      )}

      {/* Standards Catalog */}
      {catalog && (
        <div className="space-y-6">
          {catalog.mappings.map((mapping, idx) => (
            <div key={idx} className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-subtle pb-3 gap-2">
                <div>
                  <div className="text-xs font-bold uppercase tracking-wider text-quiet">
                    {mapping.category}
                  </div>
                  <div className="text-base font-bold text-foreground">
                    {mapping.legacy_primitive} →{" "}
                    <span className="text-cyan-400">{mapping.target_standard}</span>
                  </div>
                </div>
                <span className="text-xs px-2.5 py-1 rounded bg-cyan-500/10 text-cyan-400 font-mono">
                  {mapping.security_strength_bits}-bit Post-Quantum Strength
                </span>
              </div>

              <p className="text-xs text-foreground">{mapping.guidance}</p>

              {/* Regulatory Controls Table */}
              <div className="space-y-2 pt-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-quiet block">
                  Applicable Regulatory Mandates
                </span>
                <div className="grid grid-cols-1 gap-2">
                  {mapping.controls.map((ctrl, cIdx) => (
                    <div
                      key={cIdx}
                      className="p-3 rounded bg-canvas border border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-foreground">{ctrl.standard}</span>
                          <span className="text-quiet">({ctrl.jurisdiction})</span>
                          <span className="text-xs px-2 py-0.5 rounded bg-surface border border-subtle text-quiet">
                            {ctrl.status}
                          </span>
                        </div>
                        <p className="text-quiet">{ctrl.requirement}</p>
                        {ctrl.deadline_or_milestone && (
                          <div className="flex items-center gap-1.5 text-amber-400 text-xs">
                            <Calendar size={12} /> Timeline: {ctrl.deadline_or_milestone}
                          </div>
                        )}
                      </div>

                      <a
                        href={ctrl.source_url}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-cyan-400 hover:underline shrink-0"
                      >
                        Official Spec <ExternalLink size={12} />
                      </a>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
