"""Flask backend for the NIDS dashboard. Serves the UI and a small JSON API
that the dashboard polls. Packet capture runs on a background thread
(sniffer.SnifferService) so it never blocks these request handlers."""

from flask import Flask, jsonify, render_template, request, redirect, url_for, session

import database
import config
from sniffer import sniffer_service
import secrets

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.secret_key = "acm-vit-super-secret-key"


@app.route("/")
def index():
    return render_template("index.html")

VALID_USERNAME = "team1"
VALID_PASSWORD = "password123"

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == VALID_USERNAME and password == VALID_PASSWORD:
            session["authenticated"] = True
            return redirect(url_for("dashboard"))
        else:
            error = "Incorrect username or password. Please try again."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.pop("authenticated", None)
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    if not session.get("authenticated"):
        return redirect(url_for("login"))
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
