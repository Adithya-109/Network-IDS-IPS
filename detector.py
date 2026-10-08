"""Threshold-based detection rules. Pure logic, no Scapy/network code here --
this makes it easy to reason about and to unit-test independently of packet
capture. sniffer.py feeds it one parsed packet's fields at a time."""

import time
from collections import defaultdict, deque

import config

try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


class DetectionEngine:
    def __init__(self):
        # src_ip -> deque[(timestamp, dst_port)]
        self.port_scan_map = defaultdict(deque)
        # src_ip -> deque[timestamp]  (TCP SYN packets)
        self.syn_map = defaultdict(deque)
        # src_ip -> deque[timestamp]  (ICMP echo requests)
        self.icmp_map = defaultdict(deque)
        # src_ip -> deque[timestamp]  (UDP packets)
        self.udp_map = defaultdict(deque)
        # (src_ip, detection_type) -> last alert timestamp
        self._last_alert = {}

        self.ml_enabled = ML_AVAILABLE
        if self.ml_enabled:
            # Using 'auto' contamination prevents forcing a fixed % of normal traffic to be flagged
            self.iso_forest = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
            self.baseline_data = []
            self.is_trained = False
            self.TRAINING_SAMPLES = 300 # Learn from the first 300 packets
            self.last_seen = defaultdict(float)
            self.smoothed_iat = defaultdict(lambda: 1.0) # Default to 1 second start

    def _cooldown_ok(self, key, now):
        last = self._last_alert.get(key, 0)
        if now - last >= config.ALERT_COOLDOWN:
            self._last_alert[key] = now
            return True
        return False

    @staticmethod
    def _trim(dq, now, window):
        while dq and now - dq[0][0] > window:
            dq.popleft()

    @staticmethod
    def _trim_flat(dq, now, window):
        while dq and now - dq[0] > window:
            dq.popleft()

    def check_port_scan(self, src_ip, dport, now):
        dq = self.port_scan_map[src_ip]
        dq.append((now, dport))
        self._trim(dq, now, config.PORT_SCAN_WINDOW)
        distinct_ports = {p for _, p in dq}
        if len(distinct_ports) >= config.PORT_SCAN_THRESHOLD:
            if self._cooldown_ok((src_ip, "PORT_SCAN"), now):
                return {
                    "detection_type": "Port Scan",
                    "severity": "High",
                    "description": (
                        f"{src_ip} contacted {len(distinct_ports)} distinct ports "
                        f"within {config.PORT_SCAN_WINDOW}s (threshold: "
                        f"{config.PORT_SCAN_THRESHOLD})"
                    ),
                }
        return None

    def check_syn_flood(self, src_ip, now):
        dq = self.syn_map[src_ip]
        dq.append(now)
        self._trim_flat(dq, now, config.SYN_FLOOD_WINDOW)
        if len(dq) >= config.SYN_FLOOD_THRESHOLD:
            if self._cooldown_ok((src_ip, "SYN_FLOOD"), now):
                return {
                    "detection_type": "SYN Flood",
                    "severity": "High",
                    "description": (
                        f"{src_ip} sent {len(dq)} TCP SYN packets within "
                        f"{config.SYN_FLOOD_WINDOW}s (threshold: "
                        f"{config.SYN_FLOOD_THRESHOLD})"
                    ),
                }
        return None

    def check_icmp_flood(self, src_ip, now):
        dq = self.icmp_map[src_ip]
        dq.append(now)
        self._trim_flat(dq, now, config.ICMP_FLOOD_WINDOW)
        if len(dq) >= config.ICMP_FLOOD_THRESHOLD:
            if self._cooldown_ok((src_ip, "ICMP_FLOOD"), now):
                return {
                    "detection_type": "ICMP Flood",
                    "severity": "Medium",
                    "description": (
                        f"{src_ip} sent {len(dq)} ICMP echo requests within "
                        f"{config.ICMP_FLOOD_WINDOW}s (threshold: "
                        f"{config.ICMP_FLOOD_THRESHOLD})"
                    ),
                }
        return None

    def check_udp_flood(self, src_ip, now):
        dq = self.udp_map[src_ip]
        dq.append(now)
        self._trim_flat(dq, now, config.UDP_FLOOD_WINDOW)
        if len(dq) >= config.UDP_FLOOD_THRESHOLD:
            if self._cooldown_ok((src_ip, "UDP_FLOOD"), now):
                return {
                    "detection_type": "UDP Flood",
                    "severity": "Medium",
                    "description": (
                        f"{src_ip} sent {len(dq)} UDP packets within "
                        f"{config.UDP_FLOOD_WINDOW}s (threshold: {config.UDP_FLOOD_THRESHOLD})"
                    ),
                }
        return None

    def check_stealth_scan(self, src_ip, dport, flags, now):
        # TCP Flags byte: FIN(0x01), SYN(0x02), RST(0x04), PSH(0x08), ACK(0x10), URG(0x20)
        scan_type = None
        if flags == 0:
            scan_type = "NULL Scan"
        elif flags == 0x29: # FIN | PSH | URG
            scan_type = "XMAS Scan"
        elif flags == 0x01: # FIN only
            scan_type = "FIN Scan"
            
        if scan_type:
            key = (src_ip, f"STEALTH_{scan_type}")
            if self._cooldown_ok(key, now):
                return {
                    "detection_type": f"TCP Stealth Scan ({scan_type})",
                    "severity": "High",
                    "description": f"{src_ip} sent a suspicious TCP packet with irregular flags ({scan_type}) to port {dport}."
                }
        return None

    def check_suspicious_port(self, src_ip, dport, now):
        if dport in config.SUSPICIOUS_PORTS:
            key = (src_ip, f"SUSPICIOUS_PORT_{dport}")
            if self._cooldown_ok(key, now):
                service = config.SUSPICIOUS_PORTS[dport]
                return {
                    "detection_type": "Suspicious Port Activity",
                    "severity": "Low",
                    "description": (
                        f"{src_ip} sent traffic to port {dport} ({service}) -- "
                        "commonly targeted service, not automatically a confirmed attack"
                    ),
                }
        return None

    def check_dpi_payload(self, src_ip, dport, payload, now):
        try:
            # Attempt to decode raw bytes to string
            payload_str = payload.decode('utf-8', errors='ignore').lower()
        except Exception:
            return None
        
        signature = None
        if "union select" in payload_str or "1'='1" in payload_str or "select * from" in payload_str:
            signature = "SQL Injection (SQLi)"
        elif "<script>" in payload_str or "alert(" in payload_str or "onerror=" in payload_str:
            signature = "Cross-Site Scripting (XSS)"
        elif "cmd.exe" in payload_str or "/bin/sh" in payload_str or "eval(" in payload_str:
            signature = "Command Injection / Shellcode"
        elif "../" in payload_str or "..\\\\" in payload_str or "%2e%2e%2f" in payload_str:
            signature = "Directory Traversal (Path Injection)"
        elif "wget " in payload_str or "curl " in payload_str or "nc -e" in payload_str:
            signature = "Malware/Botnet Command Execution"

        if signature:
            key = (src_ip, f"DPI_{signature}")
            if self._cooldown_ok(key, now):
                return {
                    "detection_type": "Deep Packet Inspection (L7)",
                    "severity": "High",
                    "description": f"{src_ip} sent malicious payload targeting port {dport}: {signature} signature matched."
                }
        return None

    def check_ml_anomaly(self, src_ip, proto_name, packet_len, now):
        if not self.ml_enabled:
            return None
            
        last_t = self.last_seen.get(src_ip, now)
        current_iat = now - last_t if last_t else 1.0
        self.last_seen[src_ip] = now
        
        # Exponential Moving Average (EMA) to smooth out random network jitter
        prev_iat = self.smoothed_iat[src_ip]
        ema_iat = 0.8 * prev_iat + 0.2 * current_iat
        self.smoothed_iat[src_ip] = ema_iat
        
        is_tcp = 1 if proto_name == "TCP" else 0
        is_udp = 1 if proto_name == "UDP" else 0
        is_icmp = 1 if proto_name == "ICMP" else 0
        
        features = [packet_len, ema_iat, is_tcp, is_udp, is_icmp]
        
        if not self.is_trained:
            self.baseline_data.append(features)
            if len(self.baseline_data) >= self.TRAINING_SAMPLES:
                self.iso_forest.fit(self.baseline_data)
                self.is_trained = True
                print("\n[ML Engine] Isolation Forest trained on baseline traffic! AI Detection Active.\n")
            return None
            
        prediction = self.iso_forest.predict([features])[0]
        
        if prediction == -1:
            key = (src_ip, "ML_ANOMALY")
            if self._cooldown_ok(key, now):
                return {
                    "detection_type": "AI Anomaly (Isolation Forest)",
                    "severity": "Low",
                    "description": f"Abnormal traffic pattern from {src_ip} (Avg IAT shifted to {ema_iat:.4f}s)."
                }
        return None
