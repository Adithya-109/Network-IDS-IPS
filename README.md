# Network Intrusion Detection System (NIDS)

A modern, multi-layered Intrusion Detection System built with **Python, Scapy, Flask, and Scikit-Learn**. It captures live network traffic and analyzes it using three distinct, enterprise-grade detection layers to identify both known exploits and zero-day anomalies.

## Core Features

1. **Rule-Based Threat Intelligence (DPI):** 
   - Dynamically loads signatures from an external `rules.json` file—matching industry standards for decoupled threat intelligence.
   - Performs Deep Packet Inspection (L7) to catch application-layer exploits like SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection, Path Traversal, and Malware C2 beacons.
2. **Volumetric & State Analysis:** 
   - Uses sliding-window thresholds to catch brute-force network attacks (SYN Floods, ICMP Floods, UDP Floods, and Port Scans).
   - Inspects raw TCP headers for illegal flag combinations to detect stealth reconnaissance (NULL, XMAS, and FIN scans).
3. **Machine Learning Anomaly Engine (Zero-Day Catcher):** 
   - Utilizes Scikit-Learn's `IsolationForest` to learn your network's unique baseline automatically.
   - Operates as a fallback layer: if an attack evades all known JSON signatures, the AI flags mathematically anomalous traffic shapes, speeds, and packet sizes.

Includes a safe local traffic generator (`demo.py`) so you can trigger every alert on demand to test the system without requiring actual malware.

## Architecture

- **`app.py`**: Flask server and JSON API (runs on port 5001). Provides the real-time web dashboard.
- **`sniffer.py`**: Background packet capture engine utilizing Scapy's AsyncSniffer.
- **`detector.py`**: The core detection engine running ML Analysis, Thresholds, and DPI.
- **`rules.json`**: The decoupled Threat Intelligence database containing malware signatures and suspicious ports.
- **`database.py`**: SQLite storage for persisting alerts.
- **`demo.py`**: Safe local traffic generator with continuous simulation capabilities.

## Installation & Usage (macOS / Linux)

### 1. Install Dependencies

You will need `scikit-learn` and `numpy` installed for the root user, as the raw socket sniffer requires root privileges (`sudo`).

```bash
sudo pip install -r requirements.txt scikit-learn numpy
```

### 2. Start the NIDS Server

Open a terminal and launch the background engine and web server:

```bash
sudo python app.py
```
Open **http://127.0.0.1:5001** in your browser and click **Start Monitoring**. Allow the system a few seconds to ingest the first 300 packets and train the ML baseline.

### 3. Launch Test Attacks

Open a second terminal and use the provided simulation script to generate safe, local traffic that triggers the rules.

**Run individual attacks:**
```bash
sudo python3 demo.py portscan
sudo python3 demo.py synflood
sudo python3 demo.py icmpflood
sudo python3 demo.py udpflood
sudo python3 demo.py stealthscan
sudo python3 demo.py dpi
```

**Run an automated continuous attack loop:**
```bash
sudo python3 demo.py continuous --interval 15
```
This will run in the background, routinely firing off every type of attack on a 15-second interval so you can monitor the dashboard reacting in real-time.

## Adding Custom Threat Signatures

Because the detection engine reads from `rules.json`, you can add custom signatures without touching the Python code. Simply open `rules.json`, add a new pattern array (e.g., detecting a new CVE payload string), and restart the application to instantly update the firewall's threat intelligence.
