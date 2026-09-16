from flask import Flask, render_template, jsonify

from database import (
    init_database,
    get_events,
    get_statistics
)

import threading

from packet_sniffer import start_sniffer


app = Flask(__name__)


# =========================
# DATABASE
# =========================

init_database()


# =========================
# START PACKET SNIFFER
# =========================

def run_sniffer():

    try:
        start_sniffer()

    except Exception as e:

        print("Sniffer error:", e)


sniffer_thread = threading.Thread(
    target=run_sniffer,
    daemon=True
)

sniffer_thread.start()


# =========================
# DASHBOARD
# =========================

@app.route("/")
def dashboard():

    statistics = get_statistics()
    events = get_events()

    return render_template(
        "dashboard.html",
        statistics=statistics,
        events=events
    )


# =========================
# EVENTS API
# =========================

@app.route("/api/events")
def events_api():

    events = get_events()

    return jsonify([
        dict(event)
        for event in events
    ])


# =========================
# STATISTICS API
# =========================

@app.route("/api/statistics")
def statistics_api():

    statistics = get_statistics()

    return jsonify(statistics)


# =========================
# RUN FLASK
# =========================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )