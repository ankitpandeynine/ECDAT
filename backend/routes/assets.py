"""
ECDAT Cryptographic Assets and Knowledge Graph Routes.

Implements GET /api/graph and GET /api/projects/{id}/graph.
Strictly queries graph_nodes and graph_edges tables.
Filters out edges referencing node IDs not present in the nodes array.
"""
from typing import Any, Dict, List
from fastapi import APIRouter, Query, Request

from urllib.parse import unquote_plus

router = APIRouter(tags=["assets"])


@router.get("/graph")
def get_graph(request: Request, project: str = Query("default", min_length=1, max_length=128)):
    """
    Returns the real cryptographic asset graph for a project.
    Strictly queries graph_nodes and graph_edges tables.
    If graph_nodes is empty for the project: returns {"nodes": [], "edges": []}.
    If graph_edges reference node IDs not in the nodes array: filters those edges OUT.
    """
    if project:
        project = unquote_plus(project)
        if '%' in project:
            project = unquote_plus(project)
        project = project.strip() or 'default'

    store = request.app.state.store
    with store.connect() as db:
        # Ensure graph_nodes table exists
        db.execute("""CREATE TABLE IF NOT EXISTS graph_nodes (
            id TEXT PRIMARY KEY,
            project TEXT NOT NULL,
            label TEXT NOT NULL,
            type TEXT NOT NULL,
            risk_level TEXT NOT NULL DEFAULT 'low',
            evidence_count INTEGER NOT NULL DEFAULT 0,
            blast_radius_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL)""")

        # If graph_nodes is empty but crypto_assets exist (e.g. initial migration), sync once
        node_count = db.execute("SELECT COUNT(*) FROM graph_nodes WHERE project = ?", (project,)).fetchone()[0]
        if node_count == 0:
            asset_count = db.execute("SELECT COUNT(*) FROM crypto_assets WHERE project = ?", (project,)).fetchone()[0]
            if asset_count > 0:
                from engine.knowledge_graph import sync_knowledge_graph_tables
                sync_knowledge_graph_tables(store, project)

        node_rows = db.execute(
            "SELECT id, label, type, risk_level, evidence_count, blast_radius_count FROM graph_nodes WHERE project = ? ORDER BY created_at ASC",
            (project,)
        ).fetchall()

        if not node_rows:
            return {
                "nodes": [],
                "edges": [],
                "links": []
            }

        nodes = [
            {
                "id": str(r["id"]),
                "label": str(r["label"]),
                "type": str(r["type"]),
                "risk_level": str(r["risk_level"]),
                "evidence_count": int(r["evidence_count"] or 0),
                "blast_radius_count": int(r["blast_radius_count"] or 0),
            }
            for r in node_rows
        ]

        node_ids = {n["id"] for n in nodes}

        edge_rows = db.execute(
            "SELECT source_id, target_id, relationship, confidence FROM graph_edges WHERE project = ?",
            (project,)
        ).fetchall()

        edges = []
        for er in edge_rows:
            src = str(er["source_id"])
            tgt = str(er["target_id"])
            # If graph_edges reference node IDs not in the nodes array: filter those edges OUT before returning.
            if src in node_ids and tgt in node_ids:
                edges.append({
                    "source": src,
                    "target": tgt,
                    "relationship": str(er["relationship"]),
                    "confidence": float(er["confidence"] if er["confidence"] is not None else 1.0),
                })

        return {
            "nodes": nodes,
            "edges": edges,
            "links": edges,  # Backward compatibility alias
        }


@router.get("/projects/{project_id}/graph")
def get_project_graph_by_id(project_id: str, request: Request):
    return get_graph(request, project=project_id)
