"""SQLite storage for alerts. Every function opens its own short-lived
connection so calls from the sniffer thread and the Flask request threads
never share a connection object (sqlite3 connections aren't thread-safe)."""

import sqlite3
from contextlib import closing

import config


def _get_conn():
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with closing(_get_conn()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                detection_type TEXT,
                severity TEXT,
                description TEXT,
                score REAL,
                method TEXT,
                rule_id TEXT,
                category TEXT,
                baseline TEXT,
                action TEXT
            )
            """
        )
        # Handle migration if table exists without new columns
        try:
            conn.execute("ALTER TABLE alerts ADD COLUMN score REAL")
            conn.execute("ALTER TABLE alerts ADD COLUMN method TEXT")
            conn.execute("ALTER TABLE alerts ADD COLUMN rule_id TEXT")
            conn.execute("ALTER TABLE alerts ADD COLUMN category TEXT")
            conn.execute("ALTER TABLE alerts ADD COLUMN baseline TEXT")
            conn.execute("ALTER TABLE alerts ADD COLUMN action TEXT")
        except sqlite3.OperationalError:
            pass # Columns already exist
        conn.commit()


def insert_alert(alert: dict):
    with closing(_get_conn()) as conn:
        conn.execute(
            """
            INSERT INTO alerts
                (timestamp, src_ip, dst_ip, protocol, detection_type, severity, description, score, method, rule_id, category, baseline, action)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert["timestamp"],
                alert.get("src_ip"),
                alert.get("dst_ip"),
                alert.get("protocol"),
                alert.get("detection_type"),
                alert.get("severity"),
                alert.get("description"),
                alert.get("score"),
                alert.get("method"),
                alert.get("rule_id"),
                alert.get("category"),
                alert.get("baseline"),
                alert.get("action"),
            ),
        )
        conn.commit()


def get_recent_alerts(limit: int = 50):
    with closing(_get_conn()) as conn:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_alert_counts():
    with closing(_get_conn()) as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
        counts = {"total": total, "High": 0, "Medium": 0, "Low": 0}
        for row in conn.execute(
            "SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity"
        ):
            if row["severity"] in counts:
                counts[row["severity"]] = row["c"]
        return counts


def clear_alerts():
    with closing(_get_conn()) as conn:
        conn.execute("DELETE FROM alerts")
        conn.commit()
