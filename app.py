"""Flask backend for the NIDS dashboard. Serves the UI and a small JSON API
that the dashboard polls. Packet capture runs on a background thread
(sniffer.SnifferService) so it never blocks these request handlers."""

from flask import Flask, jsonify, render_template

import database
import config
from sniffer import sniffer_service

app = Flask(__name__)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/status")
def api_status():
    stats = sniffer_service.get_stats()
    return jsonify({"running": stats["running"], "error": stats["error"]})


@app.route("/api/start", methods=["POST"])
def api_start():
    ok, message = sniffer_service.start()
    return jsonify({"ok": ok, "message": message})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    ok, message = sniffer_service.stop()
    return jsonify({"ok": ok, "message": message})


@app.route("/api/stats")
def api_stats():
    return jsonify(sniffer_service.get_stats())


@app.route("/api/alerts")
def api_alerts():
    return jsonify(
        {
            "alerts": database.get_recent_alerts(limit=100),
            "counts": database.get_alert_counts(),
        }
    )


@app.route("/api/alerts/clear", methods=["POST"])
def api_alerts_clear():
    database.clear_alerts()
    return jsonify({"ok": True})


@app.route("/api/config")
def api_config():
    return jsonify(
        {
            "port_scan_threshold": config.PORT_SCAN_THRESHOLD,
            "port_scan_window": config.PORT_SCAN_WINDOW,
            "syn_flood_threshold": config.SYN_FLOOD_THRESHOLD,
            "syn_flood_window": config.SYN_FLOOD_WINDOW,
            "icmp_flood_threshold": config.ICMP_FLOOD_THRESHOLD,
            "icmp_flood_window": config.ICMP_FLOOD_WINDOW,
            "suspicious_ports": config.SUSPICIOUS_PORTS,
        }
    )


if __name__ == "__main__":
    database.init_db()
    app.run(host="127.0.0.1", port=5001, debug=False, threaded=True)
