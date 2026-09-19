"""
ECDAT V4 P2.3 Bounded Graph Traversal & Impact Analyzer.

Traverses incoming dependency edges in the Crypto Asset Graph to compute
blast radius while enforcing rigorous bounds against cycles, path explosion,
and unbounded graph traversal.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from .dependency_paths import build_dependency_path
from .models import DependencyPath, GraphConfidence
from .normalizer import is_relevant_relationship, normalize_edge, normalize_node


# Traversal safety bounds
DEFAULT_MAX_DEPTH = 10
DEFAULT_MAX_PATHS = 100
DEFAULT_MAX_NODES = 500
DEFAULT_MAX_EDGES = 1000


class BoundedGraphAnalyzer:
    """
    Executes bounded DFS/BFS traversal over crypto asset relationships.
    Reuses AssetGraphService edges while guaranteeing safety limits and cycle pruning.
    """

    def __init__(
        self,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_paths: int = DEFAULT_MAX_PATHS,
        max_nodes: int = DEFAULT_MAX_NODES,
        max_edges: int = DEFAULT_MAX_EDGES,
    ):
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.max_nodes = max_nodes
        self.max_edges = max_edges

    def analyze_blast_radius(
        self,
        target_asset_id: str,
        graph_service: Optional[Any] = None,
        raw_edges: Optional[List[Dict[str, Any]]] = None,
        raw_nodes: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Calculates all evidenced dependent paths terminating at target_asset_id.
        Traverses reverse incoming edges: (Caller) -> [USES/DEPENDS_ON/etc] -> (Target).
        """
        # Collect edges and nodes from service or memory
        edges: List[Dict[str, Any]] = []
        nodes_by_id: Dict[str, Dict[str, Any]] = {}

        if graph_service is not None:
            # Query incoming relationships from AssetGraphService
            if hasattr(graph_service, "get_relationships"):
                all_edges = graph_service.get_relationships()
                for e in all_edges:
                    edges.append(normalize_edge(e))
            if hasattr(graph_service, "find_assets_by_project"):
                # If project available, pull assets
                pass
        if raw_edges:
            for e in raw_edges:
                edges.append(normalize_edge(e))

        if raw_nodes:
            for n in raw_nodes:
                norm_n = normalize_node(n)
                nodes_by_id[norm_n["id"]] = norm_n

        # Filter to relevant edges
        relevant_edges = [e for e in edges if is_relevant_relationship(e["relationship"])]

        # Index incoming edges by target_id: target_id -> list of edges where edge.target == target_id
        # (meaning the source depends on / calls / uses the target)
        incoming_map: Dict[str, List[Dict[str, Any]]] = {}
        for e in relevant_edges:
            tid = e["target_id"]
            incoming_map.setdefault(tid, []).append(e)

        discovered_paths: List[DependencyPath] = []
        impacted_node_ids: Set[str] = set()
        traversed_edges: List[Dict[str, Any]] = []
        traversed_edge_ids: Set[str] = set()

        limitations: List[str] = []
        partial_result = False

        # DFS path exploration with cycle tracking and depth limiting
        # Stack frame: (current_node, path_nodes, path_relationships, path_evidences, visited_in_path)
        stack: List[Tuple[str, List[str], List[str], List[str], Set[str]]] = [
            (target_asset_id, [target_asset_id], [], [], {target_asset_id})
        ]

        while stack:
            # Check path bound
            if len(discovered_paths) >= self.max_paths:
                limitations.append("MAX_PATHS_REACHED")
                partial_result = True
                break

            current_node, path_nodes, path_rels, path_evs, path_visited = stack.pop()

            # Check node count bound
            if len(impacted_node_ids) >= self.max_nodes:
                limitations.append("MAX_NODES_REACHED")
                partial_result = True
                break

            # Check depth bound
            if len(path_rels) >= self.max_depth:
                limitations.append("MAX_DEPTH_REACHED")
                partial_result = True
                continue

            incoming = incoming_map.get(current_node, [])
            for edge in incoming:
                # Check edge bound
                if len(traversed_edges) >= self.max_edges:
                    limitations.append("MAX_EDGES_REACHED")
                    partial_result = True
                    break

                edge_key = f"{edge['source_id']}->{edge['relationship']}->{edge['target_id']}"
                if edge_key not in traversed_edge_ids:
                    traversed_edge_ids.add(edge_key)
                    traversed_edges.append(edge)

                caller_id = edge["source_id"]

                # Cycle detection along current branch
                if caller_id in path_visited:
                    if "CYCLE_DETECTED_AND_PRUNED" not in limitations:
                        limitations.append("CYCLE_DETECTED_AND_PRUNED")
                    continue

                # Check path bound
                if len(discovered_paths) >= self.max_paths:
                    limitations.append("MAX_PATHS_REACHED")
                    partial_result = True
                    break

                new_nodes = [caller_id] + path_nodes
                new_rels = [edge["relationship"]] + path_rels
                new_evs = path_evs + ([edge["evidence_id"]] if edge.get("evidence_id") else [])
                new_visited = path_visited | {caller_id}

                impacted_node_ids.add(caller_id)

                # Record path from caller_id to target_asset_id
                dp = build_dependency_path(
                    source_id=caller_id,
                    target_id=target_asset_id,
                    node_sequence=new_nodes,
                    relationship_sequence=new_rels,
                    evidence_refs=new_evs,
                    confidence=GraphConfidence.MEASURED.value if edge.get("confidence", 1.0) >= 0.8 else GraphConfidence.INFERRED.value,
                )
                discovered_paths.append(dp)

                # Continue traversal upstream from caller_id
                stack.append((caller_id, new_nodes, new_rels, new_evs, new_visited))

        # Query full node details for all impacted nodes if graph_service is available
        impacted_assets: List[Dict[str, Any]] = []
        for nid in sorted(impacted_node_ids):
            if nid in nodes_by_id:
                impacted_assets.append(nodes_by_id[nid])
            elif graph_service is not None and hasattr(graph_service, "get_asset"):
                a = graph_service.get_asset(nid)
                if a:
                    impacted_assets.append(normalize_node(a))
                else:
                    impacted_assets.append({"id": nid, "name": nid, "asset_type": "UNKNOWN"})
            else:
                impacted_assets.append({"id": nid, "name": nid, "asset_type": "UNKNOWN"})

        # Categorize direct vs transitive
        direct_ids = sorted([
            p.source_asset for p in discovered_paths if p.path_length == 1
        ])
        transitive_ids = sorted(list(set(
            p.source_asset for p in discovered_paths if p.path_length > 1
        )))

        return {
            "target_node_id": target_asset_id,
            "total_impacted_count": len(impacted_node_ids),
            "impacted_assets": impacted_assets,
            "dependency_paths": discovered_paths,
            "direct_dependents": direct_ids,
            "transitive_dependents": transitive_ids,
            "traversal_edges": traversed_edges,
            "partial_result": partial_result,
            "limitations": sorted(list(set(limitations))),
            "graph_scope": {
                "max_depth": self.max_depth,
                "max_paths": self.max_paths,
                "max_nodes": self.max_nodes,
                "max_edges": self.max_edges,
                "traversed_edge_count": len(traversed_edges),
                "discovered_path_count": len(discovered_paths),
            },
        }
