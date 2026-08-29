from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from app.schemas import Detection, NormalizedEvent

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Database:
    """Small, dependency-free event store with WAL and parameterized queries."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    sensor_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dest_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dest_port INTEGER,
                    protocol TEXT NOT NULL,
                    app_proto TEXT,
                    flow_id TEXT,
                    community_id TEXT,
                    bytes_to_server INTEGER NOT NULL,
                    bytes_to_client INTEGER NOT NULL,
                    packets_to_server INTEGER NOT NULL,
                    packets_to_client INTEGER NOT NULL,
                    duration REAL NOT NULL,
                    raw_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_occurred ON events(occurred_at DESC);
                CREATE INDEX IF NOT EXISTS idx_events_source ON events(src_ip, occurred_at DESC);

                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                    detected_at TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
                    confidence INTEGER NOT NULL CHECK(confidence BETWEEN 0 AND 100),
                    source TEXT NOT NULL,
                    description TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    mitre_json TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    response_eligible INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','triaged','contained','closed')),
                    src_ip TEXT NOT NULL,
                    dest_ip TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_detections_time ON detections(detected_at DESC);
                CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity, detected_at DESC);

                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    opened_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    title TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','triaged','contained','closed')),
                    detection_count INTEGER NOT NULL DEFAULT 1,
                    summary TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents(updated_at DESC);

                CREATE TABLE IF NOT EXISTS incident_detections (
                    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
                    detection_id INTEGER NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
                    PRIMARY KEY (incident_id, detection_id)
                );

                CREATE TABLE IF NOT EXISTS blocks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection_id INTEGER REFERENCES detections(id),
                    ip TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('simulated','active','expired','reverted','failed')),
                    command_json TEXT NOT NULL,
                    reverted_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks(ip, created_at DESC);

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    object_type TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
                """
            )

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    @staticmethod
    def _rows(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        return [dict(row) for row in rows]

    def insert_event(self, event: NormalizedEvent, raw: dict[str, Any]) -> int:
        with self.connect() as db:
            cursor = db.execute(
                """
                INSERT INTO events (
                    occurred_at, ingested_at, sensor_id, event_type, src_ip, dest_ip,
                    src_port, dest_port, protocol, app_proto, flow_id, community_id,
                    bytes_to_server, bytes_to_client, packets_to_server, packets_to_client,
                    duration, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.timestamp.isoformat(),
                    self._now(),
                    event.sensor_id,
                    event.event_type,
                    event.src_ip,
                    event.dest_ip,
                    event.src_port,
                    event.dest_port,
                    event.protocol,
                    event.app_proto,
                    event.flow_id,
                    event.community_id,
                    event.bytes_to_server,
                    event.bytes_to_client,
                    event.packets_to_server,
                    event.packets_to_client,
                    event.duration,
                    json.dumps(raw, sort_keys=True, default=str),
                ),
            )
            return int(cursor.lastrowid)

    def insert_detection(self, event_id: int, event: NormalizedEvent, item: Detection) -> int:
        with self.connect() as db:
            cursor = db.execute(
                """
                INSERT INTO detections (
                    event_id, detected_at, rule_id, title, severity, confidence, source,
                    description, evidence_json, mitre_json, recommended_action,
                    response_eligible, src_ip, dest_ip
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    self._now(),
                    item.rule_id,
                    item.title,
                    item.severity,
                    item.confidence,
                    item.source,
                    item.description,
                    json.dumps(item.evidence, sort_keys=True, default=str),
                    json.dumps(item.mitre_techniques),
                    item.recommended_action,
                    int(item.response_eligible),
                    event.src_ip,
                    event.dest_ip,
                ),
            )
            return int(cursor.lastrowid)

    def correlate_incident(self, detection_id: int) -> int:
        with self.connect() as db:
            detection = db.execute(
                "SELECT * FROM detections WHERE id = ?", (detection_id,)
            ).fetchone()
            if detection is None:
                raise KeyError(f"Detection {detection_id} not found")
            cutoff = (datetime.now(UTC) - timedelta(minutes=15)).isoformat()
            existing = db.execute(
                """
                SELECT * FROM incidents
                WHERE src_ip = ? AND status IN ('new','triaged') AND updated_at >= ?
                ORDER BY updated_at DESC LIMIT 1
                """,
                (detection["src_ip"], cutoff),
            ).fetchone()
            now = self._now()
            if existing:
                severity = (
                    detection["severity"]
                    if SEVERITY_RANK[detection["severity"]] > SEVERITY_RANK[existing["severity"]]
                    else existing["severity"]
                )
                db.execute(
                    """
                    UPDATE incidents SET updated_at = ?, severity = ?, detection_count = detection_count + 1,
                        summary = ? WHERE id = ?
                    """,
                    (
                        now,
                        severity,
                        f"Correlated activity from {detection['src_ip']}; latest: {detection['title']}",
                        existing["id"],
                    ),
                )
                incident_id = int(existing["id"])
            else:
                cursor = db.execute(
                    """
                    INSERT INTO incidents (opened_at, updated_at, title, src_ip, severity, summary)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        now,
                        now,
                        f"Suspicious activity from {detection['src_ip']}",
                        detection["src_ip"],
                        detection["severity"],
                        detection["description"],
                    ),
                )
                incident_id = int(cursor.lastrowid)
            db.execute(
                "INSERT OR IGNORE INTO incident_detections (incident_id, detection_id) VALUES (?, ?)",
                (incident_id, detection_id),
            )
            return incident_id

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM events ORDER BY occurred_at DESC LIMIT ?", (limit,)
            ).fetchall()
        items = self._rows(rows)
        for item in items:
            item.pop("raw_json", None)
        return items

    def list_detections(
        self, limit: int = 100, severity: str | None = None
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM detections"
        parameters: list[Any] = []
        if severity:
            query += " WHERE severity = ?"
            parameters.append(severity)
        query += " ORDER BY detected_at DESC LIMIT ?"
        parameters.append(limit)
        with self.connect() as db:
            rows = db.execute(query, parameters).fetchall()
        items = self._rows(rows)
        for item in items:
            item["evidence"] = json.loads(item.pop("evidence_json"))
            item["mitre_techniques"] = json.loads(item.pop("mitre_json"))
            item["response_eligible"] = bool(item["response_eligible"])
        return items

    def get_detection(self, detection_id: int) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM detections WHERE id = ?", (detection_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["evidence"] = json.loads(item.pop("evidence_json"))
        item["mitre_techniques"] = json.loads(item.pop("mitre_json"))
        item["response_eligible"] = bool(item["response_eligible"])
        return item

    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM incidents ORDER BY updated_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return self._rows(rows)

    def update_incident(self, incident_id: int, status: str, note: str, actor: str) -> bool:
        with self.connect() as db:
            cursor = db.execute(
                "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
                (status, self._now(), incident_id),
            )
            if cursor.rowcount == 0:
                return False
            db.execute(
                """
                INSERT INTO audit_log (created_at, actor, action, object_type, object_id, details_json)
                VALUES (?, ?, 'incident.status_changed', 'incident', ?, ?)
                """,
                (
                    self._now(),
                    actor,
                    str(incident_id),
                    json.dumps({"status": status, "note": note}),
                ),
            )
        return True

    def create_block(
        self,
        *,
        detection_id: int,
        ip: str,
        expires_at: str,
        reason: str,
        mode: str,
        status: str,
        command: list[str],
        actor: str,
    ) -> int:
        with self.connect() as db:
            cursor = db.execute(
                """
                INSERT INTO blocks (
                    detection_id, ip, created_at, expires_at, reason, mode, status, command_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    detection_id,
                    ip,
                    self._now(),
                    expires_at,
                    reason,
                    mode,
                    status,
                    json.dumps(command),
                ),
            )
            block_id = int(cursor.lastrowid)
            db.execute(
                """
                INSERT INTO audit_log (created_at, actor, action, object_type, object_id, details_json)
                VALUES (?, ?, 'response.block_created', 'block', ?, ?)
                """,
                (
                    self._now(),
                    actor,
                    str(block_id),
                    json.dumps({"ip": ip, "mode": mode, "status": status, "reason": reason}),
                ),
            )
            if status in {"active", "simulated"}:
                db.execute(
                    "UPDATE detections SET status = 'contained' WHERE id = ?", (detection_id,)
                )
        return block_id

    def list_blocks(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM blocks ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        items = self._rows(rows)
        for item in items:
            item["command"] = json.loads(item.pop("command_json"))
        return items

    def revert_block(self, block_id: int, actor: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM blocks WHERE id = ?", (block_id,)).fetchone()
            if row is None:
                return None
            now = self._now()
            db.execute(
                "UPDATE blocks SET status = 'reverted', reverted_at = ? WHERE id = ?",
                (now, block_id),
            )
            db.execute(
                """
                INSERT INTO audit_log (created_at, actor, action, object_type, object_id, details_json)
                VALUES (?, ?, 'response.block_reverted', 'block', ?, ?)
                """,
                (now, actor, str(block_id), json.dumps({"ip": row["ip"]})),
            )
        return dict(row)

    def metrics(self) -> dict[str, Any]:
        with self.connect() as db:
            event_count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            detection_count = db.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
            incident_count = db.execute(
                "SELECT COUNT(*) FROM incidents WHERE status != 'closed'"
            ).fetchone()[0]
            severity_rows = db.execute(
                "SELECT severity, COUNT(*) AS count FROM detections GROUP BY severity"
            ).fetchall()
            source_rows = db.execute(
                "SELECT source, COUNT(*) AS count FROM detections GROUP BY source"
            ).fetchall()
            active_blocks = db.execute(
                "SELECT COUNT(*) FROM blocks WHERE status IN ('active','simulated')"
            ).fetchone()[0]
            trend_rows = db.execute(
                """
                SELECT substr(detected_at, 1, 13) AS bucket, COUNT(*) AS count
                FROM detections GROUP BY bucket ORDER BY bucket DESC LIMIT 12
                """
            ).fetchall()
        severity = {name: 0 for name in ("critical", "high", "medium", "low", "info")}
        severity.update({row["severity"]: row["count"] for row in severity_rows})
        return {
            "events": event_count,
            "detections": detection_count,
            "open_incidents": incident_count,
            "active_blocks": active_blocks,
            "severity": severity,
            "sources": {row["source"]: row["count"] for row in source_rows},
            "trend": list(reversed(self._rows(trend_rows))),
        }

    def audit_log(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        items = self._rows(rows)
        for item in items:
            item["details"] = json.loads(item.pop("details_json"))
        return items

    def is_empty(self) -> bool:
        with self.connect() as db:
            return db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0

    def reset_demo_data(self) -> dict[str, int]:
        """Remove only built-in lab telemetry and repair any affected incidents.

        Real sensor/API events are retained. The demo endpoint uses this before a
        replay so repeated clicks remain deterministic instead of inflating the
        analyst queue.
        """

        with self.connect() as db:
            event_count = int(
                db.execute(
                    """
                    SELECT COUNT(*) FROM events
                    WHERE sensor_id = 'verified-demo-lab' OR sensor_id LIKE 'demo-%'
                    """
                ).fetchone()[0]
            )
            detection_count = int(
                db.execute(
                    """
                    SELECT COUNT(*) FROM detections
                    WHERE event_id IN (
                        SELECT id FROM events
                        WHERE sensor_id = 'verified-demo-lab' OR sensor_id LIKE 'demo-%'
                    )
                    """
                ).fetchone()[0]
            )
            affected_incidents = [
                int(row[0])
                for row in db.execute(
                    """
                    SELECT DISTINCT incident_id FROM incident_detections
                    WHERE detection_id IN (
                        SELECT id FROM detections
                        WHERE event_id IN (
                            SELECT id FROM events
                            WHERE sensor_id = 'verified-demo-lab' OR sensor_id LIKE 'demo-%'
                        )
                    )
                    """
                ).fetchall()
            ]
            block_rows = db.execute(
                """
                SELECT id FROM blocks
                WHERE detection_id IN (
                    SELECT id FROM detections
                    WHERE event_id IN (
                        SELECT id FROM events
                        WHERE sensor_id = 'verified-demo-lab' OR sensor_id LIKE 'demo-%'
                    )
                )
                """
            ).fetchall()
            block_ids = [str(row[0]) for row in block_rows]
            if block_ids:
                db.executemany(
                    "DELETE FROM audit_log WHERE object_type = 'block' AND object_id = ?",
                    [(block_id,) for block_id in block_ids],
                )
            db.execute(
                """
                DELETE FROM blocks
                WHERE detection_id IN (
                    SELECT id FROM detections
                    WHERE event_id IN (
                        SELECT id FROM events
                        WHERE sensor_id = 'verified-demo-lab' OR sensor_id LIKE 'demo-%'
                    )
                )
                """
            )
            db.execute(
                """
                DELETE FROM events
                WHERE sensor_id = 'verified-demo-lab' OR sensor_id LIKE 'demo-%'
                """
            )

            removed_incidents = 0
            for incident_id in affected_incidents:
                remaining = db.execute(
                    """
                    SELECT d.* FROM detections AS d
                    JOIN incident_detections AS link ON link.detection_id = d.id
                    WHERE link.incident_id = ? ORDER BY d.detected_at DESC
                    """,
                    (incident_id,),
                ).fetchall()
                if not remaining:
                    db.execute(
                        "DELETE FROM audit_log WHERE object_type = 'incident' AND object_id = ?",
                        (str(incident_id),),
                    )
                    db.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
                    removed_incidents += 1
                    continue
                latest = remaining[0]
                severity = max(
                    (row["severity"] for row in remaining), key=SEVERITY_RANK.__getitem__
                )
                db.execute(
                    """
                    UPDATE incidents
                    SET updated_at = ?, severity = ?, detection_count = ?, summary = ?
                    WHERE id = ?
                    """,
                    (
                        latest["detected_at"],
                        severity,
                        len(remaining),
                        f"Correlated activity from {latest['src_ip']}; latest: {latest['title']}",
                        incident_id,
                    ),
                )

        return {
            "events_removed": event_count,
            "detections_removed": detection_count,
            "incidents_removed": removed_incidents,
            "blocks_removed": len(block_ids),
        }
