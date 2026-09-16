import sqlite3
from datetime import datetime

DATABASE = "ids.db"


def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    conn = get_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            attack_type TEXT,
            severity TEXT,
            description TEXT
        )
    """)

    conn.commit()
    conn.close()


def add_event(source_ip, destination_ip, attack_type,
              severity, description):

    conn = get_connection()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn.execute("""
        INSERT INTO events
        (timestamp, source_ip, destination_ip,
         attack_type, severity, description)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        source_ip,
        destination_ip,
        attack_type,
        severity,
        description
    ))

    conn.commit()
    conn.close()


def get_events():

    conn = get_connection()

    events = conn.execute("""
        SELECT *
        FROM events
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    return events


def get_statistics():

    conn = get_connection()

    total = conn.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]

    port_scans = conn.execute(
        "SELECT COUNT(*) FROM events WHERE attack_type='Port Scan'"
    ).fetchone()[0]

    syn_floods = conn.execute(
        "SELECT COUNT(*) FROM events WHERE attack_type='SYN Flood'"
    ).fetchone()[0]

    high = conn.execute(
        "SELECT COUNT(*) FROM events WHERE severity='High'"
    ).fetchone()[0]

    conn.close()

    return {
        "total": total,
        "port_scans": port_scans,
        "syn_floods": syn_floods,
        "high": high
    }