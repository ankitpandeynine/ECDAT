"use client";

import React, { useState, useEffect, useMemo, useCallback } from "react";
import Link from "next/link";
import {
  GitFork,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Sparkles,
  Loader2,
  ArrowRight,
  RefreshCw,
  AlertTriangle,
} from "lucide-react";

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  risk_level: string;
  evidence_count: number;
  blast_radius_count: number;
  group?: string;
  severity?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
  confidence: number;
  label?: string;
}

interface CryptoGraphProps {
  projectId: string;
  onNavigateToStudio?: () => void;
  onNavigateToBlast?: (assetLabel: string) => void;
  onNodeCountChange?: (count: number) => void;
}

export function CryptoGraph({
  projectId,
  onNavigateToStudio,
  onNavigateToBlast,
  onNodeCountChange,
}: CryptoGraphProps) {
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedGraphNode, setSelectedGraphNode] = useState<GraphNode | null>(null);
  const [graphZoom, setGraphZoom] = useState<number>(1);
  const [graphFilter, setGraphFilter] = useState<string>("ALL");

  const fetchGraph = useCallback(async () => {
    if (!projectId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/graph?project=${encodeURIComponent(projectId)}`);
      if (!res.ok) {
        throw new Error(`Failed to load asset graph (HTTP ${res.status})`);
      }
      const data = await res.json();
      const rawNodes: GraphNode[] = (data.nodes || []).map((n: any) => ({
        id: String(n.id),
        label: String(n.label || n.id),
        type: String(n.type || "algorithm"),
        risk_level: String(n.risk_level || n.severity || "low"),
        evidence_count: Number(n.evidence_count || 0),
        blast_radius_count: Number(n.blast_radius_count || 0),
        group: String(n.group || n.type || "algorithm"),
        severity: String(n.risk_level || n.severity || "low"),
      }));

      // Support either "edges" or "links" from API
      const rawEdgesList = data.edges || data.links || [];
      const rawEdges: GraphEdge[] = rawEdgesList.map((e: any) => ({
        source: String(e.source?.id || e.source),
        target: String(e.target?.id || e.target),
        relationship: String(e.relationship || e.label || "uses"),
        confidence: Number(e.confidence !== undefined ? e.confidence : 1.0),
        label: String(e.relationship || e.label || "uses"),
      }));

      setNodes(rawNodes);
      setEdges(rawEdges);
      onNodeCountChange?.(rawNodes.length);

      // Deselect if active node no longer exists
      setSelectedGraphNode((prev) => {
        if (!prev) return null;
        return rawNodes.find((n) => n.id === prev.id) || null;
      });
    } catch (err: any) {
      console.error("CryptoGraph fetch error:", err);
      setError(err.message || "Failed to load graph data");
    } finally {
      setLoading(false);
    }
  }, [projectId, onNodeCountChange]);

  useEffect(() => {
    fetchGraph();
  }, [fetchGraph]);

  // Strict Data Integrity: Never render edges whose source or target is not in the nodes array
  const validEdges = useMemo(() => {
    const nodeIds = new Set(nodes.map((n) => n.id));
    return edges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target));
  }, [nodes, edges]);

  // Filtered nodes based on selected toolbar filter
  const filteredGraphNodes = useMemo(() => {
    if (graphFilter === "ALL") return nodes;
    return nodes.filter(
      (n) =>
        (n.group && n.group.toUpperCase() === graphFilter) ||
        (n.type && n.type.toUpperCase() === graphFilter)
    );
  }, [nodes, graphFilter]);

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-subtle pb-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight">Enterprise Crypto Asset Graph</h2>
          <p className="text-xs text-quiet mt-1">
            Multi-tier relational graph connecting applications, services, libraries, algorithms, certificates, and endpoints.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchGraph}
            disabled={loading}
            className="p-1.5 rounded-lg border border-subtle hover:border-cyan-500/40 text-quiet hover:text-foreground text-xs flex items-center gap-1 transition-colors"
            title="Refresh graph from database"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          </button>
          <div className="flex items-center gap-3 font-mono text-xs text-cyan-400 bg-cyan-500/10 px-3 py-1.5 rounded-lg border border-cyan-500/20">
            <span>{nodes.length} Nodes</span>
            <span>•</span>
            <span>{validEdges.length} Edges</span>
          </div>
        </div>
      </div>

      {/* Loading Skeleton State */}
      {loading && (
        <div className="rounded-xl border border-subtle bg-surface p-8 min-h-[420px] flex flex-col items-center justify-center space-y-4">
          <Loader2 className="h-8 w-8 text-cyan-400 animate-spin" />
          <div className="space-y-2 text-center">
            <p className="text-sm font-semibold text-foreground">Loading Cryptographic Topology...</p>
            <p className="text-xs text-quiet font-mono">Querying real graph_nodes and verified graph_edges</p>
          </div>
          <div className="grid grid-cols-3 gap-3 w-full max-w-md pt-4 opacity-40">
            <div className="h-16 rounded-lg bg-canvas animate-pulse border border-subtle" />
            <div className="h-16 rounded-lg bg-canvas animate-pulse border border-subtle" />
            <div className="h-16 rounded-lg bg-canvas animate-pulse border border-subtle" />
          </div>
        </div>
      )}

      {/* Error State */}
      {!loading && error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-8 text-center space-y-3">
          <AlertTriangle className="h-8 w-8 text-rose-400 mx-auto" />
          <h3 className="font-semibold text-sm text-rose-300">GRAPH DATA ERROR</h3>
          <p className="text-xs text-rose-300/80 max-w-sm mx-auto">{error}</p>
          <button
            onClick={fetchGraph}
            className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold"
          >
            Retry Fetch
          </button>
        </div>
      )}

      {/* Empty State: If nodes.length === 0 */}
      {!loading && !error && nodes.length === 0 && (
        <div className="rounded-xl border border-subtle bg-surface p-12 text-center space-y-3">
          <GitFork className="h-8 w-8 text-quiet mx-auto" />
          <h3 className="font-semibold text-sm">NO CRYPTO ASSETS TO GRAPH YET</h3>
          <p className="text-xs text-quiet max-w-md mx-auto">
            No crypto assets to graph yet. Complete a discovery scan to populate the asset graph.
          </p>
          <div className="flex items-center justify-center gap-3 pt-2">
            {onNavigateToStudio ? (
              <button
                onClick={onNavigateToStudio}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5"
              >
                Scan Studio <ArrowRight className="h-3.5 w-3.5" />
              </button>
            ) : (
              <Link
                href={`/projects/${encodeURIComponent(projectId)}?tab=studio`}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5"
              >
                Scan Studio <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            )}
          </div>
        </div>
      )}

      {/* Real Interactive Graph Canvas */}
      {!loading && !error && nodes.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Interactive SVG / Canvas Graph */}
          <div className="lg:col-span-2 rounded-xl border border-subtle bg-canvas p-4 min-h-[460px] flex flex-col justify-between relative overflow-hidden">
            {/* Graph Controls Toolbar */}
            <div className="flex items-center justify-between text-xs border-b border-subtle pb-3 z-10">
              <div className="flex items-center gap-2">
                <span className="text-quiet text-[11px] font-mono">Filter:</span>
                {["ALL", "SERVICE", "ALGORITHM", "PROTOCOL"].map((f) => (
                  <button
                    key={f}
                    onClick={() => setGraphFilter(f)}
                    className={`px-2 py-0.5 rounded text-[10px] font-mono transition-colors ${
                      graphFilter === f
                        ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                        : "bg-subtle text-quiet hover:text-foreground"
                    }`}
                  >
                    {f}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setGraphZoom((z) => Math.min(z + 0.2, 2.0))}
                  className="p-1 rounded bg-subtle hover:bg-subtle/80 text-quiet hover:text-foreground"
                  title="Zoom In"
                >
                  <ZoomIn className="h-3.5 w-3.5" />
                </button>
                <button
                  onClick={() => setGraphZoom((z) => Math.max(z - 0.2, 0.6))}
                  className="p-1 rounded bg-subtle hover:bg-subtle/80 text-quiet hover:text-foreground"
                  title="Zoom Out"
                >
                  <ZoomOut className="h-3.5 w-3.5" />
                </button>
                <button
                  onClick={() => setGraphZoom(1)}
                  className="p-1 rounded bg-subtle hover:bg-subtle/80 text-quiet hover:text-foreground"
                  title="Reset Zoom"
                >
                  <Maximize2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>

            {/* Interactive Node Canvas Area */}
            <div
              className="flex-1 py-6 flex flex-wrap items-center justify-center gap-4 transition-transform duration-200"
              style={{ transform: `scale(${graphZoom})` }}
            >
              {filteredGraphNodes.map((node) => {
                const isSelected = selectedGraphNode?.id === node.id;
                const isVuln =
                  node.risk_level === "critical" ||
                  node.risk_level === "high" ||
                  String(node.label).includes("RSA") ||
                  String(node.label).includes("ECDSA");
                return (
                  <button
                    key={node.id}
                    onClick={() => setSelectedGraphNode(node)}
                    className={`p-3.5 rounded-xl border text-left transition-all max-w-[200px] shadow-sm ${
                      isSelected
                        ? "ring-2 ring-cyan-400 bg-cyan-500/20 border-cyan-400 text-cyan-200"
                        : isVuln
                        ? "bg-rose-500/10 border-rose-500/30 text-rose-300 hover:border-rose-400"
                        : "bg-surface border-subtle text-foreground hover:border-cyan-500/40"
                    }`}
                  >
                    <div className="text-[10px] uppercase font-mono font-bold text-quiet truncate">
                      {node.group || node.type || "ASSET"}
                    </div>
                    <div className="text-xs font-semibold mt-1 truncate">{node.label}</div>
                    <div className="text-[9px] font-mono mt-1 text-quiet uppercase flex items-center justify-between gap-1">
                      <span>Risk: {node.risk_level || "low"}</span>
                      {node.evidence_count > 0 && <span>{node.evidence_count} ev</span>}
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Edge & Relationship Summary Bar */}
            <div className="text-[11px] text-quiet border-t border-subtle pt-3 flex items-center justify-between font-mono">
              <span>Edges: {validEdges.length} Connected Relationships</span>
              <span className="text-emerald-400">Strict Data Integrity (Zero Mock Edges)</span>
            </div>
          </div>

          {/* Node Detail Drawer */}
          <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <GitFork className="h-4 w-4 text-cyan-400" />
              Inspected Topology Node
            </h3>

            {selectedGraphNode ? (
              <div className="text-xs space-y-3">
                <div className="p-3.5 rounded-lg bg-canvas border border-subtle font-mono text-[11px] space-y-2">
                  <div className="text-cyan-300 font-bold">Label: {selectedGraphNode.label}</div>
                  <div className="text-quiet truncate">Node ID: {selectedGraphNode.id}</div>
                  <div className="text-quiet">Category: {selectedGraphNode.group || selectedGraphNode.type}</div>
                  <div className="text-quiet">Risk Level: {selectedGraphNode.risk_level}</div>
                  <div className="text-quiet">Evidence Count: {selectedGraphNode.evidence_count}</div>
                  <div className="text-quiet">Blast Radius: {selectedGraphNode.blast_radius_count} assets</div>
                </div>

                <div className="space-y-1">
                  <div className="font-semibold text-foreground">Connected Edges:</div>
                  <div className="space-y-1 max-h-40 overflow-y-auto font-mono text-[10px]">
                    {validEdges
                      .filter(
                        (l) => l.source === selectedGraphNode.id || l.target === selectedGraphNode.id
                      )
                      .map((l, idx) => (
                        <div key={idx} className="p-1.5 rounded bg-canvas border border-subtle/60 text-quiet">
                          <span className="truncate">{l.source}</span> →{" "}
                          <span className="text-cyan-400">{l.label || l.relationship || "CONNECTED_TO"}</span> →{" "}
                          <span className="truncate">{l.target}</span>
                        </div>
                      ))}
                    {validEdges.filter(
                      (l) => l.source === selectedGraphNode.id || l.target === selectedGraphNode.id
                    ).length === 0 && (
                      <div className="text-quiet italic p-2 text-center">No connected edges</div>
                    )}
                  </div>
                </div>

                {onNavigateToBlast && (
                  <button
                    onClick={() => onNavigateToBlast(selectedGraphNode.label)}
                    className="w-full py-2 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 text-cyan-300 text-xs font-semibold transition-colors"
                  >
                    Calculate Blast Radius for {selectedGraphNode.label} →
                  </button>
                )}
              </div>
            ) : (
              <div className="py-8 text-center text-quiet text-xs italic">
                Select a topology node on the graph canvas to inspect relationships, evidence depth, and blast radius.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
