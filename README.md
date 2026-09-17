# Network Intrusion Detection System (NIDS) -- Demo

A simple, local NIDS built with **Python + Scapy + Flask**. Captures live
traffic, applies threshold-based detection rules (port scan, SYN flood,
ICMP flood, suspicious ports), and shows everything on a live dashboard.
Includes a safe local traffic generator (`demo.py`) so you can trigger every
alert on demand without any real attack traffic.

## Project structure

```
app.py          Flask server + JSON API
sniffer.py      Background packet capture (Scapy AsyncSniffer, own thread)
detector.py     Threshold-based detection rules
database.py     SQLite alert storage
config.py       Thresholds / suspicious ports
demo.py         Safe local traffic generator (portscan / synflood / icmpflood)
templates/      dashboard.html
static/         style.css, script.js
```

## One-time setup (do this first, it's the only fiddly part)

1. **Install Npcap** (required for Scapy to capture packets on Windows):
   https://npcap.com/#download
   - During install, check **"Install Npcap in WinPcap API-compatible Mode"**.
   - Leave loopback support enabled (default) -- this lets the sniffer see
     traffic sent to `127.0.0.1`.

2. **Install Python dependencies:**
   ```
   pip install -r requirements.txt
   ```

3. **Run everything as Administrator.** Both `app.py` and `demo.py` need
   raw packet access, which Windows only grants to elevated processes.
   Open PowerShell **as Administrator**, `cd` into this folder, and use
   that terminal for both commands below.

## Running the demo

**Terminal 1 (Administrator):**
```
python app.py
```
Open http://127.0.0.1:5000 in your browser. Click **Start Monitoring**.
- If you see a red error banner about Npcap/Administrator, that step above
  wasn't done -- fix it and restart `app.py`.

**Terminal 2 (Administrator), while monitoring is running:**
```
python demo.py portscan
python demo.py synflood
python demo.py icmpflood
python demo.py all
```
Each command prints `[DEMO/TEST TRAFFIC]` lines and only targets your own
machine (`127.0.0.1` by default). Watch the dashboard -- alerts should
appear within a few seconds of each run.

## What to show your professor

1. Start monitoring -> status pill turns green (RUNNING), packet counters climb.
2. Run `python demo.py portscan` -> a **Port Scan** alert (and a couple of
   **Suspicious Port Activity** alerts for ports like 22/3389) appear.
3. Run `python demo.py synflood` -> a **SYN Flood** alert appears.
4. Run `python demo.py icmpflood` -> an **ICMP Flood** alert appears.
5. Point out the protocol/severity charts and the alert table (source IP,
   destination IP, protocol, detection type, severity, description, time).
6. Stop monitoring to show the start/stop control works.

## How detection works (for the report/viva)

All rules are simple sliding-window counters per source IP, tuned in
`config.py`:

- **Port Scan**: >= 15 distinct destination ports from one source IP within 5s.
- **SYN Flood**: >= 40 TCP SYN packets (SYN set, ACK clear) from one source IP within 5s.
- **ICMP Flood**: >= 30 ICMP echo requests from one source IP within 5s.
- **Suspicious Port Activity**: any traffic to ports 21/22/23/445/3389 --
  flagged as suspicious, not auto-labeled a confirmed attack.

Each source IP + detection type has an 8-second alert cooldown so one
sustained attack doesn't spam duplicate rows.

## Troubleshooting

- **Packet count stuck at 0 after Start Monitoring**: you're not running as
  Administrator, or Npcap isn't installed. Check the red banner on the
  dashboard for the exact message.
- **`demo.py` throws `PermissionError`**: same cause -- re-run in an
  Administrator terminal.
- **No alerts from `demo.py` targeting `127.0.0.1`**: some environments
  don't route loopback traffic through the interfaces Scapy sniffs. As a
  fallback, find your machine's LAN IP (`ipconfig`) and target that instead:
  `python demo.py portscan --target <your-lan-ip>`.
- **Port already in use**: another process is on port 5000. Change the port
  in the last line of `app.py`.
