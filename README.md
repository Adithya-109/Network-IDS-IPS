# Network Intrusion Detection System (NIDS) -- NextGen

A modern, multi-layered local NIDS built with **Python + Scapy + Flask + Scikit-Learn**. It captures live traffic and analyzes it using three distinct detection layers:
1. **Threshold-based Signatures:** Catch brute-force volumetric attacks like SYN Floods, ICMP Floods, UDP Floods, and Port Scans.
2. **Deep Packet Inspection (L7):** Reads packet payloads to catch Application-layer exploits like SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection, Path Traversal, and Malware C2 beacons.
3. **Machine Learning AI Engine (Isolation Forest):** Learns your network's baseline traffic automatically and flags anomalous traffic shapes/speeds that evade hardcoded rules.

Includes a safe local traffic generator (`demo.py`) so you can trigger every alert on demand without any real attack traffic.

## Project structure

```
app.py          Flask server + JSON API (runs on port 5001)
sniffer.py      Background packet capture (Scapy AsyncSniffer, own thread)
detector.py     ML Engine + Thresholds + DPI Rules
database.py     SQLite alert storage
config.py       Thresholds / suspicious ports
demo.py         Safe local traffic generator (portscan / floods / dpi / stealth)
templates/      dashboard.html
static/         style.css, script.js
```

## Running the Project (macOS / Linux)

1. **Install Dependencies:**
   ```bash
   sudo pip install -r requirements.txt scikit-learn numpy
   ```
   *(Note: The AI models require scikit-learn to be installed for the root user since the sniffer requires sudo).*

2. **Start the NIDS Server:**
   Open a terminal and run:
   ```bash
   sudo python app.py
   ```
   Open http://127.0.0.1:5001 in your browser and click **Start Monitoring**. Wait a few seconds for the AI to train its baseline.

3. **Launch Test Attacks:**
   Open a second terminal and run any of the simulation modules:
   ```bash
   sudo python3 demo.py portscan
   sudo python3 demo.py synflood
   sudo python3 demo.py icmpflood
   sudo python3 demo.py udpflood
   sudo python3 demo.py stealthscan
   sudo python3 demo.py dpi
   sudo python3 demo.py all
   ```

## How Detection Works (For Report/Viva)

1. **Volumetric Thresholds (`config.py`)**:
   - Simple sliding-window counters for Source IPs.
   - Example: >= 40 TCP SYN packets or >= 50 UDP packets in 5 seconds triggers a flood alert.
2. **Stealth Scans**:
   - Checks the raw TCP flags for impossible combinations used by nmap (e.g., NULL, XMAS, FIN scans).
3. **Deep Packet Inspection (DPI)**:
   - Converts raw byte payloads to UTF-8 and scans against a hardcoded signature dictionary (e.g., `<script>`, `union select`, `../`, `nc -e`).
4. **Machine Learning (Isolation Forest)**:
   - Tracks the Exponential Moving Average (EMA) of Inter-Arrival Time (IAT) and packet lengths.
   - Learns the baseline dynamically during the first 300 packets.
   - Flags sudden mathematical shifts in traffic shape (like a perfectly timed Python `for` loop in an attack script) using Scikit-Learn's `IsolationForest` with `auto` contamination.
