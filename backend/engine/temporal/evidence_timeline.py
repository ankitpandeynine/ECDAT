"""
ECDAT V4 Asset Evidence Timeline Builder.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import AssetTimeline, TimelineEvent, TimelineEventType
from ..evidence_model import Evidence


def build_asset_timeline(
    project: str,
    asset_key: str,
    scans_with_evidence: List[Dict[str, Any]],
    asset_id: Optional[str] = None,
    ttl_days: int = 90,
) -> AssetTimeline:
    """
    Constructs an evidence-backed historical timeline for an asset across ordered scans.
    """
    # Sort scans chronologically
    sorted_scans = sorted(
        scans_with_evidence,
        key=lambda s: str(s.get("timestamp") or s.get("created_at") or ""),
    )

    events: List[TimelineEvent] = []
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    last_dt: Optional[datetime] = None
    last_algo: Optional[str] = None

    for scan in sorted_scans:
        scan_id = scan.get("scan_id") or scan.get("id") or "unknown"
        ts_str = str(scan.get("timestamp") or scan.get("created_at") or datetime.now(timezone.utc).isoformat())

        # Parse scan timestamp
        try:
            curr_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if curr_dt.tzinfo is None:
                curr_dt = curr_dt.replace(tzinfo=timezone.utc)
        except Exception:
            curr_dt = datetime.now(timezone.utc)

        # Find evidence items in this scan matching asset_key
        raw_items = scan.get("evidence") or scan.get("evidence_items") or []
        matched_items: List[Evidence] = []
        for it in raw_items:
            ev: Optional[Evidence] = None
            if isinstance(it, Evidence):
                ev = it
            elif isinstance(it, dict):
                try:
                    ev = Evidence.from_dict(it)
                except Exception:
                    pass
            if ev:
                target_str = f"{ev.symbol or ''} {ev.description or ''} {(ev.raw_details.get('asset_key') if isinstance(ev.raw_details, dict) else '')}".lower()
                if asset_key.lower() in target_str:
                    matched_items.append(ev)

        if matched_items:
            # Asset was observed in this scan
            last_seen = ts_str
            if not first_seen:
                first_seen = ts_str

            # Check for staleness gap between consecutive observations
            if last_dt is not None:
                gap_days = (curr_dt - last_dt).days
                if gap_days > ttl_days:
                    events.append(
                        TimelineEvent(
                            scan_id=scan_id,
                            timestamp=ts_str,
                            event_type=TimelineEventType.STALE,
                            description=f"Evidence gap of {gap_days} days exceeded TTL threshold ({ttl_days} days).",
                            metadata={"gap_days": gap_days},
                        )
                    )

            # Check highest evidence level and primary algorithm
            highest_lvl = max(matched_items, key=lambda e: e.level.rank).level.value
            max_conf = max(e.confidence for e in matched_items)
            current_algo = matched_items[0].raw_details.get("algorithm") if isinstance(matched_items[0].raw_details, dict) else None

            if len(events) == 0:
                events.append(
                    TimelineEvent(
                        scan_id=scan_id,
                        timestamp=ts_str,
                        event_type=TimelineEventType.FIRST_OBSERVED,
                        description=f"Asset first discovered with {len(matched_items)} evidence item(s) at {highest_lvl}.",
                        evidence_level=highest_lvl,
                        confidence=max_conf,
                        metadata={"evidence_count": len(matched_items)},
                    )
                )
            else:
                if last_algo and current_algo and current_algo.upper() != last_algo.upper():
                    events.append(
                        TimelineEvent(
                            scan_id=scan_id,
                            timestamp=ts_str,
                            event_type=TimelineEventType.ALGORITHM_CHANGED,
                            description=f"Observed algorithm transition from {last_algo} to {current_algo}.",
                            evidence_level=highest_lvl,
                            confidence=max_conf,
                            metadata={"old_algorithm": last_algo, "new_algorithm": current_algo},
                        )
                    )
                else:
                    events.append(
                        TimelineEvent(
                            scan_id=scan_id,
                            timestamp=ts_str,
                            event_type=TimelineEventType.OBSERVED,
                            description=f"Re-observed across {len(matched_items)} evidence item(s) at {highest_lvl}.",
                            evidence_level=highest_lvl,
                            confidence=max_conf,
                            metadata={"evidence_count": len(matched_items)},
                        )
                    )

            if current_algo:
                last_algo = current_algo
            last_dt = curr_dt
        else:
            # Not observed in this scan (if it was previously seen)
            if first_seen is not None:
                events.append(
                    TimelineEvent(
                        scan_id=scan_id,
                        timestamp=ts_str,
                        event_type=TimelineEventType.UNOBSERVED,
                        description=f"Asset not observed during scan {scan_id}.",
                        metadata={"scan_id": scan_id},
                    )
                )

    return AssetTimeline(
        timeline_id=f"timeline-{uuid.uuid4().hex[:12]}",
        asset_id=asset_id or asset_key,
        asset_key=asset_key,
        project_id=project,
        first_seen=first_seen,
        last_seen=last_seen,
        observation_count=len([e for e in events if e.event_type in (TimelineEventType.FIRST_OBSERVED, TimelineEventType.OBSERVED)]),
        events=events,
        current_status="ACTIVE" if last_seen else "UNOBSERVED",
    )
