"""Aegis TI ML worker: anomaly scoring + threat-actor movement mapping."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

SEVERITY = {"info": 0.1, "low": 0.3, "medium": 0.5, "high": 0.8, "critical": 1.0}
ID_RE = re.compile(r"^[A-Za-z0-9_.:@\-/]{1,240}$")


def _safe_id(value: str | None, label: str = "id") -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not ID_RE.match(value):
        raise SystemExit(f"invalid {label}")
    return value


def _assert_db_path(db_path: str) -> Path:
    path = Path(db_path).resolve()
    cwd = Path.cwd().resolve()
    allowed = [
        (cwd / "data").resolve(),
        (cwd.parent / "data").resolve(),
        Path("/data").resolve(),
        Path("/app/data").resolve(),
    ]
    env_root = os.environ.get("AEGIS_DATA_ROOT")
    if env_root:
        allowed.append(Path(env_root).resolve())

    ok = any(path == base or str(path).startswith(str(base) + os.sep) for base in allowed)
    if not ok or path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
        raise SystemExit("database path not allowed")
    if not path.exists():
        raise SystemExit("database not found")
    return path


def connect(db_path: str) -> sqlite3.Connection:
    path = _assert_db_path(db_path)
    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=rw", uri=True, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def load_events(conn: sqlite3.Connection, run_id: str | None, limit: int = 1500):
    if run_id:
        rows = conn.execute(
            "SELECT * FROM events WHERE scan_run_id = ? ORDER BY ts LIMIT ?",
            (run_id, limit),
        ).fetchall()
        return list(rows)
    rows = conn.execute(
        "SELECT * FROM events ORDER BY ts DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return list(reversed(rows))


def resolve_map_id(conn: sqlite3.Connection, map_id: str | None) -> str | None:
    map_id = _safe_id(map_id, "map_id")
    if map_id:
        return map_id
    row = conn.execute(
        "SELECT value FROM settings WHERE key = 'active_map_id'"
    ).fetchone()
    return _safe_id(row["value"] if row else None, "map_id")


def features_for(events) -> np.ndarray:
    type_index: dict[str, int] = {}
    rows = []
    for e in events:
        t = e["type"] or "unknown"
        if t not in type_index:
            type_index[t] = len(type_index)
        try:
            entities = json.loads(e["entities_json"] or "[]")
            edges = json.loads(e["edges_json"] or "[]")
            if not isinstance(entities, list):
                entities = []
            if not isinstance(edges, list):
                edges = []
        except Exception:
            entities, edges = [], []
        rows.append(
            [
                SEVERITY.get(e["severity"], 0.2),
                float(type_index[t]),
                float(min(len(entities), 100)),
                float(min(len(edges), 200)),
                1.0 if e["agent"] == "go-net" else 0.0,
                1.0 if e["agent"] == "rust-host" else 0.0,
                1.0 if e["agent"] == "rust-etw" else 0.0,
                1.0 if str(e["type"] or "").startswith("etw.") else 0.0,
            ]
        )
    if not rows:
        return np.zeros((0, 8))
    return np.array(rows, dtype=float)


def score_events(conn: sqlite3.Connection, events) -> list[float]:
    X = features_for(events)
    if len(X) < 8:
        scores = [SEVERITY.get(e["severity"], 0.2) for e in events]
    else:
        try:
            from sklearn.ensemble import IsolationForest

            model = IsolationForest(
                n_estimators=120, contamination=0.12, random_state=42
            )
            model.fit(X)
            raw = -model.decision_function(X)
            mn, mx = float(raw.min()), float(raw.max())
            if mx - mn < 1e-9:
                scores = [0.5] * len(raw)
            else:
                scores = [float((v - mn) / (mx - mn)) for v in raw]
        except Exception:
            scores = [SEVERITY.get(e["severity"], 0.2) for e in events]

    for e, s in zip(events, scores):
        try:
            conn.execute(
                "UPDATE events SET anomaly_score = ? WHERE id = ?",
                (float(s), e["id"]),
            )
        except Exception:
            continue
    return scores


def suggest_edges(conn: sqlite3.Connection, map_id: str | None) -> int:
    map_id = _safe_id(map_id, "map_id")
    if not map_id:
        return 0

    hosts = conn.execute(
        "SELECT id FROM map_nodes WHERE map_id = ? AND kind = 'host' LIMIT 50",
        (map_id,),
    ).fetchall()
    targets = conn.execute(
        """SELECT id, severity FROM map_nodes
           WHERE map_id = ? AND kind IN ('finding','port','service','process')
           AND severity IN ('medium','high','critical')
           LIMIT 120""",
        (map_id,),
    ).fetchall()

    suggested = 0
    now = datetime.now(timezone.utc).isoformat()
    for h in hosts:
        for t in targets[:16]:
            edge_id = f"edge:{map_id}:{h['id']}:targets:{t['id']}"[:240]
            exists = conn.execute(
                "SELECT id FROM map_edges WHERE id = ?", (edge_id,)
            ).fetchone()
            if exists:
                continue
            conf = 0.45 + SEVERITY.get(t["severity"], 0.2) * 0.4
            try:
                conn.execute(
                    """INSERT INTO map_edges
                       (id, map_id, src_id, dst_id, rel, confidence, suggested, attrs_json, created_at)
                       VALUES (?, ?, ?, ?, 'targets', ?, 1, ?, ?)""",
                    (
                        edge_id,
                        map_id,
                        h["id"],
                        t["id"],
                        conf,
                        json.dumps({"source": "aegis_ml"}),
                        now,
                    ),
                )
                suggested += 1
            except Exception:
                continue
    return suggested


def score_models(conn: sqlite3.Connection, suggested: int, n_events: int) -> None:
    models = conn.execute("SELECT id FROM threat_models LIMIT 500").fetchall()
    now = datetime.now(timezone.utc).isoformat()
    for m in models:
        risk = min(0.95, 0.15 + suggested * 0.04 + n_events * 0.0015)
        try:
            conn.execute(
                "UPDATE threat_models SET residual_risk = ?, updated_at = ? WHERE id = ?",
                (risk, now, m["id"]),
            )
        except Exception:
            continue


def cmd_score(args: argparse.Namespace) -> int:
    try:
        conn = connect(args.db)
    except SystemExit as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 2
    except Exception as e:
        print(json.dumps({"ok": False, "error": "db_connect_failed", "detail": str(e)[:120]}))
        return 2

    run_id = _safe_id(args.run_id, "run_id")
    map_id = resolve_map_id(conn, args.map_id)
    movement_out = None
    scores: list[float] = []
    suggested = 0

    try:
        events = load_events(conn, run_id, limit=1500)
        scores = score_events(conn, events)
        suggested = suggest_edges(conn, map_id)
        score_models(conn, suggested, len(events))

        if map_id and events:
            from aegis_ml.movement import build_movement, persist_movement

            movement = build_movement(conn, map_id, events)
            movement_out = persist_movement(conn, map_id, movement)

        conn.commit()
    except Exception as e:
        conn.rollback()
        print(json.dumps({"ok": False, "error": "score_failed", "detail": str(e)[:200]}))
        return 1
    finally:
        conn.close()

    result = {
        "ok": True,
        "mode": "sklearn+movement",
        "events_scored": len(scores),
        "suggested_edges": suggested,
        "job_id": str(uuid.uuid4()),
        "mean_score": float(np.mean(scores)) if scores else 0.0,
        "movement": (
            {
                "campaign_id": movement_out.get("campaign_id"),
                "actor_label": movement_out.get("actor_label"),
                "ml_score": movement_out.get("ml_score"),
                "hops": len(movement_out.get("hops") or []),
                "stages": [s["stage"] for s in (movement_out.get("stages") or [])],
                "coverage": movement_out.get("coverage"),
                "summary": movement_out.get("summary"),
            }
            if movement_out
            else None
        ),
    }
    print(json.dumps(result))
    return 0


def cmd_map_movement(args: argparse.Namespace) -> int:
    try:
        conn = connect(args.db)
    except SystemExit as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 2

    run_id = _safe_id(args.run_id, "run_id")
    map_id = resolve_map_id(conn, args.map_id)
    if not map_id:
        print(json.dumps({"ok": False, "error": "map_id required"}))
        return 2

    try:
        from aegis_ml.movement import build_movement, persist_movement

        events = load_events(conn, run_id, limit=2000)
        score_events(conn, events)
        movement = build_movement(conn, map_id, events)
        out = persist_movement(conn, map_id, movement)
        conn.commit()
        print(
            json.dumps(
                {
                    "ok": True,
                    "mode": "movement",
                    "campaign_id": out["campaign_id"],
                    "actor_label": out["actor_label"],
                    "ml_score": out["ml_score"],
                    "hops": len(out["hops"]),
                    "stages": out["stages"],
                    "coverage": out["coverage"],
                    "summary": out["summary"],
                    "path_node_ids": out["path_node_ids"][:50],
                }
            )
        )
        return 0
    except Exception as e:
        conn.rollback()
        print(json.dumps({"ok": False, "error": "movement_failed", "detail": str(e)[:200]}))
        return 1
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis_ml")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("score")
    p.add_argument("--db", required=True)
    p.add_argument("--run-id", default=None)
    p.add_argument("--map-id", default=None)

    m = sub.add_parser("map-movement")
    m.add_argument("--db", required=True)
    m.add_argument("--run-id", default=None)
    m.add_argument("--map-id", default=None)

    args = parser.parse_args(argv)
    if args.cmd == "score":
        return cmd_score(args)
    if args.cmd == "map-movement":
        return cmd_map_movement(args)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(json.dumps({"ok": False, "error": "fatal", "detail": str(e)[:160]}))
        sys.exit(1)
