"""Threat-actor movement mapper for Windows host + network + ETW evidence."""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

SEVERITY = {"info": 0.1, "low": 0.3, "medium": 0.5, "high": 0.8, "critical": 1.0}

# Ordered kill-chain / movement stages (defensive mapping)
STAGES = [
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]

STAGE_RANK = {s: i for i, s in enumerate(STAGES)}

# (type_substr or tags) → (stage, technique, weight)
RULES: list[tuple[Any, str, str, float]] = [
    # Network exposure / initial access surface
    (("net.misconfig", "rdp", "3389"), "initial_access", "Remote Services: RDP", 0.9),
    (("smb", "445", "net.misconfig"), "lateral_movement", "Remote Services: SMB/Windows Admin Shares", 0.85),
    (("rpc", "135"), "lateral_movement", "Remote Services: RPC", 0.7),
    (("winrm", "5985", "5986"), "lateral_movement", "Remote Services: WinRM", 0.85),
    (("net.port.listen", "0.0.0.0"), "initial_access", "Exposed Service", 0.55),
    # Execution
    (("etw.process.start", "host.process", "powershell", "cmd", "wscript", "rundll32"), "execution", "Command and Scripting Interpreter", 0.8),
    (("etw.image.load",), "execution", "Shared Modules / Image Load", 0.45),
    # Persistence
    (("host.persistence", "runkey", "persist"), "persistence", "Boot or Logon Autostart Execution: Registry Run Keys", 0.9),
    (("host.service",), "persistence", "Create or Modify System Process: Windows Service", 0.55),
    # Credential access
    (("lsass",), "credential_access", "OS Credential Dumping: LSASS Memory", 0.75),
    # Discovery / auth
    (("host.process", "explorer"), "discovery", "System Owner/User Discovery", 0.35),
    # C2 / network movement
    (("etw.dns.query", "dns"), "command_and_control", "Application Layer Protocol: DNS", 0.7),
    (("etw.network.flow", "net.conn"), "command_and_control", "Network Connection", 0.55),
    (("net.conn.anomaly",), "exfiltration", "Automated Exfiltration / Fan-out", 0.6),
    # Pipes
    (("host.pipe",), "defense_evasion", "Inter-Process Communication", 0.4),
]


def _loads(text: str | None, fallback):
    try:
        v = json.loads(text or "")
        return v if v is not None else fallback
    except Exception:
        return fallback


def classify_event(event: dict) -> tuple[str, str, float]:
    blob = " ".join(
        [
            str(event.get("type") or ""),
            str(event.get("severity") or ""),
            json.dumps(event.get("entities") or [])[:800].lower(),
            json.dumps(event.get("raw") or {})[:800].lower(),
        ]
    ).lower()
    best = ("discovery", "Observed Activity", 0.25)
    for keys, stage, tech, weight in RULES:
        if any(k.lower() in blob for k in keys):
            score = weight * SEVERITY.get(event.get("severity") or "info", 0.3)
            if score >= best[2] * SEVERITY.get("info", 0.1) or weight > 0.5:
                # Prefer higher weight * severity
                cand = (stage, tech, weight * (0.5 + 0.5 * SEVERITY.get(event.get("severity") or "info", 0.3)))
                if cand[2] >= best[2]:
                    best = cand
    return best


def node_id_for(map_id: str, ent: dict) -> str:
    kind = ent.get("kind") or "asset"
    eid = ent.get("id") or "unknown"
    return f"node:{map_id}:{kind}:{eid}".replace(" ", "_")[:240]


def build_movement(conn, map_id: str, events: list) -> dict[str, Any]:
    """Map threat-actor movement across observed Windows/network/ETW evidence."""
    # Enrich events
    enriched = []
    for row in events:
        if hasattr(row, "keys"):
            e = dict(row)
        else:
            e = row
        entities = _loads(e.get("entities_json"), e.get("entities") or [])
        edges = _loads(e.get("edges_json"), e.get("edges") or [])
        raw = _loads(e.get("raw_json"), e.get("raw") or {})
        stage, tech, conf = classify_event(
            {"type": e.get("type"), "severity": e.get("severity"), "entities": entities, "raw": raw}
        )
        enriched.append(
            {
                "id": e.get("id"),
                "ts": e.get("ts"),
                "type": e.get("type"),
                "severity": e.get("severity") or "info",
                "agent": e.get("agent"),
                "host_id": e.get("host_id"),
                "entities": entities if isinstance(entities, list) else [],
                "edges": edges if isinstance(edges, list) else [],
                "raw": raw if isinstance(raw, dict) else {},
                "stage": stage,
                "technique": tech,
                "confidence": conf,
                "anomaly_score": e.get("anomaly_score"),
            }
        )

    # Sort chronologically when possible
    enriched.sort(key=lambda x: x.get("ts") or "")

    # Stage buckets
    by_stage: dict[str, list] = defaultdict(list)
    for e in enriched:
        by_stage[e["stage"]].append(e)

    # Build hops: connect successive high-signal events across increasing stages
    hop_candidates = [e for e in enriched if e["confidence"] >= 0.4 or e["severity"] in ("high", "critical", "medium")]
    hops = []
    path_nodes: list[str] = []
    path_edges: list[str] = []
    techniques = []

    prev = None
    seq = 0
    for e in hop_candidates:
        ents = e["entities"] or []
        primary = next((x for x in ents if x.get("kind") in ("process", "port", "finding", "service")), ents[0] if ents else None)
        if not primary:
            continue
        to_node = node_id_for(map_id, primary)
        from_node = None
        if prev:
            prev_ent = next(
                (x for x in (prev["entities"] or []) if x.get("kind") in ("process", "port", "finding", "host")),
                (prev["entities"] or [None])[0],
            )
            if prev_ent:
                from_node = node_id_for(map_id, prev_ent)

        # Only keep forward / same-stage meaningful transitions
        if prev and STAGE_RANK.get(e["stage"], 0) + 1 < STAGE_RANK.get(prev["stage"], 0):
            # allow some regression but lower confidence
            conf = e["confidence"] * 0.7
        else:
            conf = e["confidence"]

        label = primary.get("label") or primary.get("id")
        summary = f"{e['stage']}: {label} via {e['technique']}"
        mechanism = []
        raw = e.get("raw") or {}
        if raw.get("how"):
            mechanism.append(str(raw["how"]))
        if raw.get("bind"):
            mechanism.append(f"bind={raw['bind']}")
        if primary.get("attrs"):
            attrs = primary["attrs"]
            if isinstance(attrs, dict):
                for k in ("port", "proto", "bind", "pid", "cmdline", "exe", "image"):
                    if attrs.get(k) is not None:
                        mechanism.append(f"{k}={attrs[k]}")
        # Soft-cap hop confidence for stock Windows noise techniques
        if e["technique"] in (
            "Shared Modules / Image Load",
            "Inter-Process Communication",
            "System Owner/User Discovery",
            "Network Connection",
            "Application Layer Protocol: DNS",
            "Boot or Logon Autostart Execution: Registry Run Keys",
            "Remote Services: RPC",
        ):
            conf = min(conf, 0.45)
        hops.append(
            {
                "seq": seq,
                "stage": e["stage"],
                "technique": e["technique"],
                "from_node_id": from_node,
                "to_node_id": to_node,
                "event_id": e["id"],
                "summary": summary[:400],
                "mechanism": "; ".join(mechanism)[:500],
                "confidence": round(min(0.99, conf), 3),
                "severity": e["severity"],
                "ts": e["ts"],
                "type": e["type"],
            }
        )
        if to_node not in path_nodes:
            path_nodes.append(to_node)
        if from_node and to_node:
            edge_id = f"edge:{map_id}:{from_node}:targets:{to_node}"[:240]
            path_edges.append(edge_id)
        techniques.append({"stage": e["stage"], "technique": e["technique"], "confidence": conf})
        prev = e
        seq += 1
        if seq >= 80:
            break

    # Coverage across Windows attack surface categories
    coverage = {
        "host_process": any("process" in (e.get("type") or "") or e.get("agent") == "rust-host" for e in enriched),
        "network_listeners": any("port" in (e.get("type") or "") or e.get("agent") == "go-net" for e in enriched),
        "etw_kernel": any(str(e.get("type") or "").startswith("etw.") for e in enriched),
        "persistence": any(e["stage"] == "persistence" for e in enriched),
        "lateral_signals": any(e["stage"] == "lateral_movement" for e in enriched),
        "c2_dns_or_flow": any(e["stage"] in ("command_and_control", "exfiltration") for e in enriched),
        "credential_touch": any(e["stage"] == "credential_access" for e in enriched),
    }

    stage_summary = []
    for stage in STAGES:
        items = by_stage.get(stage) or []
        if not items:
            continue
        stage_summary.append(
            {
                "stage": stage,
                "count": len(items),
                "max_severity": max(items, key=lambda x: SEVERITY.get(x["severity"], 0))["severity"],
                "techniques": sorted({i["technique"] for i in items}),
                "sample": items[0]["type"],
            }
        )

    # Overall actor movement score — soft-cap when evidence is mostly stock Windows noise
    stage_bonus = len(stage_summary) * 0.07
    sev_bonus = max((SEVERITY.get(e["severity"], 0) for e in enriched), default=0) * 0.35
    hop_bonus = min(0.3, len(hops) * 0.01)
    raw_score = 0.15 + stage_bonus + sev_bonus + hop_bonus

    strong = _strong_corroboration(enriched, by_stage)
    if not strong["ok"]:
        # Normal box with PowerShell hosts, generic RPC, Run keys, ETW noise should not hit 0.99
        ml_score = round(min(0.55, raw_score * 0.55), 3)
        uncertainty = True
    else:
        ml_score = round(min(0.92, raw_score), 3)
        uncertainty = False

    actor = "Observed activity (low confidence)"
    if uncertainty:
        actor = "Uncertain — mostly stock Windows telemetry"
    elif any(e["stage"] == "lateral_movement" for e in enriched) and strong.get("lateral"):
        actor = "Possible network-adjacent / lateral operator"
    elif any(e["stage"] == "credential_access" for e in enriched) and strong.get("credential"):
        actor = "Possible credential-focused operator"
    elif (
        any(e["stage"] == "persistence" for e in enriched)
        and any(e["stage"] in ("initial_access", "lateral_movement") for e in enriched)
        and strong.get("persistence")
        and (strong.get("c2") or strong.get("credential") or strong.get("lateral"))
    ):
        actor = "Possible persistent intrusion operator"
    elif any(e["stage"] == "command_and_control" for e in enriched) and strong.get("c2"):
        actor = "Possible C2-oriented operator"
    else:
        actor = "Observed threat actor (inferred, limited corroboration)"

    summary_parts = [
        f"Mapped {len(hops)} movement hops across {len(stage_summary)} kill-chain stages.",
        f"Coverage: {', '.join(k for k, v in coverage.items() if v) or 'limited'}.",
    ]
    if uncertainty:
        summary_parts.append(
            "Confidence soft-capped: evidence looks like stock Windows noise "
            "(PowerShell/RPC/Run keys/ETW) without high-tier C2, suspicious credential dumping, "
            "or anomalous persistence corroboration."
        )
    if coverage.get("lateral_signals"):
        summary_parts.append("Lateral movement signals present (SMB/RPC/WinRM-class).")
    if coverage.get("persistence"):
        summary_parts.append("Persistence artifacts observed.")
    if coverage.get("etw_kernel"):
        summary_parts.append("Kernel ETW process/image/network telemetry included.")
    else:
        summary_parts.append("Kernel ETW sparse — elevate gateway for fuller movement fidelity.")

    return {
        "title": "Threat Actor Movement Map",
        "actor_label": actor,
        "confidence": ml_score,
        "ml_score": ml_score,
        "confidence_capped": uncertainty,
        "corroboration": strong,
        "summary": " ".join(summary_parts),
        "stages": stage_summary,
        "hops": hops,
        "path_node_ids": path_nodes,
        "path_edge_ids": list(dict.fromkeys(path_edges)),
        "techniques": techniques[:100],
        "coverage": coverage,
        "events_considered": len(enriched),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _strong_corroboration(enriched: list, by_stage: dict) -> dict[str, Any]:
    """Require high-signal corroboration before high actor confidence."""
    def blob(e: dict) -> str:
        return " ".join(
            [
                str(e.get("type") or ""),
                json.dumps(e.get("raw") or {})[:600].lower(),
                json.dumps(e.get("entities") or [])[:600].lower(),
            ]
        ).lower()

    # High-tier C2: explicit net.c2.candidate with elevated score, not bare DNS/ETW flow
    c2 = False
    for e in enriched:
        if e.get("type") == "net.c2.candidate":
            raw = e.get("raw") or {}
            score = float(raw.get("c2_score") or 0)
            if score >= 0.6:
                c2 = True
                break
        b = blob(e)
        if "unknown_process_public_egress" in b or "known_abuse_port" in b:
            c2 = True
            break

    # Credential dumping with real suspicion (not just lsass process existence)
    credential = False
    for e in by_stage.get("credential_access") or []:
        b = blob(e)
        sev = e.get("severity") or "info"
        if sev in ("high", "critical") and ("dump" in b or "minidump" in b or "procdump" in b or "lsass" in b):
            if "etw.image.load" not in (e.get("type") or "") or "lsass" in b and sev == "critical":
                credential = True
                break
        if "credential dump" in b or "os credential" in b and sev in ("high", "critical"):
            credential = True
            break

    # Persistence anomalies beyond a single ordinary Run key on a healthy box
    persistence = False
    persist_events = by_stage.get("persistence") or []
    if len(persist_events) >= 2:
        for e in persist_events:
            sev = e.get("severity") or "info"
            b = blob(e)
            if sev in ("high", "critical"):
                persistence = True
                break
            if "runkey" in b or "persist" in b:
                # Single generic runkey is weak; require medium+ and non-microsoft path hints
                if sev in ("medium", "high", "critical") and (
                    "temp\\" in b or "appdata" in b or "users\\" in b or "powershell" in b
                ):
                    persistence = True
                    break

    # Lateral: exposed SMB/RDP/WinRM with medium+ severity, not mere RPC 135 noise
    lateral = False
    for e in by_stage.get("lateral_movement") or []:
        b = blob(e)
        sev = e.get("severity") or "info"
        if sev in ("medium", "high", "critical") and any(
            x in b for x in ("smb", "445", "rdp", "3389", "winrm", "5985", "5986", "admin share")
        ):
            # Pure RPC endpoint mapper without exposure context stays weak
            if "rpc" in b and "135" in b and not any(x in b for x in ("445", "3389", "winrm", "smb", "rdp")):
                continue
            lateral = True
            break

    ok = c2 or credential or (persistence and (c2 or lateral or credential)) or (lateral and (c2 or persistence))
    return {
        "ok": ok,
        "c2": c2,
        "credential": credential,
        "persistence": persistence,
        "lateral": lateral,
    }


def persist_movement(conn, map_id: str, movement: dict) -> dict:
    campaign_id = str(uuid.uuid4())
    conn.execute(
        """INSERT INTO movement_campaigns
           (id, map_id, title, actor_label, confidence, summary, stages_json, path_node_ids_json,
            path_edge_ids_json, techniques_json, ml_score, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            campaign_id,
            map_id,
            movement["title"],
            movement["actor_label"],
            movement["confidence"],
            movement["summary"],
            json.dumps(movement["stages"]),
            json.dumps(movement["path_node_ids"]),
            json.dumps(movement["path_edge_ids"]),
            json.dumps(movement["techniques"][:100]),
            movement["ml_score"],
            movement["generated_at"],
        ),
    )

    # Materialize movement edges on the threat map
    for hop in movement["hops"]:
        hop_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO movement_hops
               (id, campaign_id, seq, stage, technique, from_node_id, to_node_id, event_id, summary, mechanism, confidence)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                hop_id,
                campaign_id,
                hop["seq"],
                hop["stage"],
                hop["technique"],
                hop.get("from_node_id"),
                hop.get("to_node_id"),
                hop.get("event_id"),
                hop.get("summary"),
                hop.get("mechanism"),
                hop.get("confidence"),
            ),
        )
        src, dst = hop.get("from_node_id"), hop.get("to_node_id")
        if src and dst and src != dst:
            # Ensure nodes exist (stubs ok)
            for nid, label in ((src, src), (dst, dst)):
                exists = conn.execute("SELECT id FROM map_nodes WHERE id = ?", (nid,)).fetchone()
                if not exists:
                    conn.execute(
                        """INSERT INTO map_nodes (id, map_id, kind, label, attrs_json, severity, created_at, updated_at)
                           VALUES (?, ?, 'asset', ?, '{}', 'medium', ?, ?)""",
                        (nid, map_id, label[-80:], movement["generated_at"], movement["generated_at"]),
                    )
            edge_id = f"edge:{map_id}:{src}:targets:{dst}"[:240]
            exists = conn.execute("SELECT id FROM map_edges WHERE id = ?", (edge_id,)).fetchone()
            if not exists:
                conn.execute(
                    """INSERT INTO map_edges
                       (id, map_id, src_id, dst_id, rel, confidence, suggested, attrs_json, created_at)
                       VALUES (?, ?, ?, ?, 'targets', ?, 1, ?, ?)""",
                    (
                        edge_id,
                        map_id,
                        src,
                        dst,
                        hop.get("confidence") or 0.55,
                        json.dumps(
                            {
                                "source": "aegis_ml_movement",
                                "stage": hop["stage"],
                                "technique": hop["technique"],
                            }
                        ),
                        movement["generated_at"],
                    ),
                )

    # Bump model residual risks
    for m in conn.execute("SELECT id FROM threat_models").fetchall():
        conn.execute(
            "UPDATE threat_models SET residual_risk = ?, updated_at = ? WHERE id = ?",
            (movement["ml_score"], movement["generated_at"], m["id"]),
        )

    return {"campaign_id": campaign_id, **movement}
