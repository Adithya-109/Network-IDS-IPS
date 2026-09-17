"""Threshold-based detection rules. Pure logic, no Scapy/network code here --
this makes it easy to reason about and to unit-test independently of packet
capture. sniffer.py feeds it one parsed packet's fields at a time."""

import time
from collections import defaultdict, deque

import config


class DetectionEngine:
    def __init__(self):
        # src_ip -> deque[(timestamp, dst_port)]
        self.port_scan_map = defaultdict(deque)
        # src_ip -> deque[timestamp]  (TCP SYN packets)
        self.syn_map = defaultdict(deque)
        # src_ip -> deque[timestamp]  (ICMP echo requests)
        self.icmp_map = defaultdict(deque)
        # (src_ip, detection_type) -> last alert timestamp
        self._last_alert = {}

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
