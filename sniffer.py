"""Background packet capture. Runs Scapy's AsyncSniffer on its own thread so
the Flask dashboard never blocks on packet capture. Exposes a small
thread-safe API (start/stop/get_stats) that app.py calls from request
handlers."""

import threading
import time
from collections import deque

import config
import database
from detector import DetectionEngine

# Imported lazily-ish at module load; Scapy prints a runtime warning on some
# systems if certain optional dependencies are missing, which is harmless.
from scapy.all import AsyncSniffer, get_if_list, conf, IP, TCP, UDP, ICMP, Raw


class SnifferService:
    def __init__(self):
        self._lock = threading.Lock()
        self._sniffer = None
        self._draining_sniffer = None
        self.detector = DetectionEngine()

        self.stats = {
            "running": False,
            "packet_count": 0,
            "web_count": 0,
            "tcp_count": 0,
            "udp_count": 0,
            "icmp_count": 0,
            "other_count": 0,
            "start_time": None,
            "stop_time": None,
            "error": None,
        }
        # timestamps of recently seen packets, used to compute packets/sec
        self._recent_ts = deque(maxlen=20000)

    # -- packet handling ---------------------------------------------------

    def _handle_packet(self, pkt):
        now = time.time()

        with self._lock:
            self.stats["packet_count"] += 1
            self._recent_ts.append(now)

        if IP not in pkt:
            with self._lock:
                self.stats["other_count"] += 1
            return

        ip_layer = pkt[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst

        proto_name = "OTHER"
        dport = None
        is_syn = False

        is_web = False

        if TCP in pkt:
            proto_name = "TCP"
            dport = int(pkt[TCP].dport)
            sport = int(pkt[TCP].sport)
            flags = pkt[TCP].flags
            is_syn = bool(flags & 0x02) and not bool(flags & 0x10)  # SYN set, ACK clear
            if sport == 5001 or dport == 5001:
                is_web = True
        elif UDP in pkt:
            proto_name = "UDP"
            dport = int(pkt[UDP].dport)
        elif ICMP in pkt:
            proto_name = "ICMP"

        with self._lock:
            count_key = f"{proto_name.lower()}_count"
            if count_key in self.stats:
                self.stats[count_key] += 1
            else:
                self.stats["other_count"] += 1
            if is_web:
                self.stats["web_count"] += 1

        alerts = []
        payload_data = None
        if Raw in pkt:
            payload_data = pkt[Raw].load

        if proto_name == "TCP" and dport is not None:
            a = self.detector.check_stealth_scan(src_ip, dport, flags, now)
            if a:
                alerts.append(a)
                
            if is_syn:
                a = self.detector.check_port_scan(src_ip, dport, now)
                if a:
                    alerts.append(a)
                a = self.detector.check_syn_flood(src_ip, now)
                if a:
                    alerts.append(a)
            a = self.detector.check_suspicious_port(src_ip, dport, now)
            if a:
                alerts.append(a)
            if payload_data:
                a = self.detector.check_dpi_payload(src_ip, dport, payload_data, now)
                if a:
                    alerts.append(a)
        elif proto_name == "ICMP":
            a = self.detector.check_icmp_flood(src_ip, now)
            if a:
                alerts.append(a)
        elif proto_name == "UDP":
            a = self.detector.check_udp_flood(src_ip, now)
            if a:
                alerts.append(a)
                
        # Machine Learning Anomaly Detection (All packets)
        a = self.detector.check_ml_anomaly(src_ip, proto_name, len(pkt), now)
        if a:
            alerts.append(a)

        for a in alerts:
            a["timestamp"] = now
            a["src_ip"] = src_ip
            a["dst_ip"] = dst_ip
            a["protocol"] = proto_name
            database.insert_alert(a)

    # -- lifecycle -----------------------------------------------------

    def start(self):
        with self._lock:
            if self.stats["running"]:
                return False, "already running"

            # A prior stop() intentionally returned without waiting for the
            # old AsyncSniffer's per-interface capture threads to release
            # their Npcap handles (see stop()'s comment). If we open new
            # handles on the same interfaces while the old ones are still
            # closing, Npcap can split delivery of incoming packets between
            # the stale and the new reader, so the live detector silently
            # only sees a fraction of the traffic. Give the old threads a
            # bounded window to actually finish before reopening.
            if self._draining_sniffer is not None:
                try:
                    self._draining_sniffer.join(timeout=2)
                except Exception:
                    pass
                self._draining_sniffer = None

            if not (conf.use_pcap or getattr(conf, "use_bpf", False)):
                message = (
                    "No packet capture backend found (Npcap/libpcap/bpf is missing, or "
                    "this app is not running with Administrator/root privileges). "
                    "On Windows, install Npcap. On Mac/Linux, run with sudo."
                )
                self.stats["error"] = message
                return False, message

            try:
                ifaces = get_if_list()
            except Exception:
                ifaces = None

            self.stats.update(
                {
                    "packet_count": 0,
                    "web_count": 0,
                    "tcp_count": 0,
                    "udp_count": 0,
                    "icmp_count": 0,
                    "other_count": 0,
                    "start_time": time.time(),
                    "stop_time": None,
                    "error": None,
                }
            )
            self._recent_ts.clear()
            # Fresh detection state each session so sliding-window counters and
            # alert cooldowns from a previous run can't suppress or skew alerts
            # in this one (matters when re-running a demo shortly after restart).
            self.detector = DetectionEngine()

            try:
                self._sniffer = AsyncSniffer(
                    prn=self._handle_packet,
                    store=False,
                    iface="lo0",
                )
                self._sniffer.start()
            except Exception as exc:
                self.stats["error"] = str(exc)
                self.stats["running"] = False
                return False, str(exc)

            self.stats["running"] = True
            return True, "started"

    def stop(self):
        with self._lock:
            if not self.stats["running"] or not self._sniffer:
                return False, "not running"
            try:
                # join=False: on Windows, AsyncSniffer.stop() can block
                # indefinitely joining per-interface capture threads for
                # idle/virtual adapters (WAN miniports, Bluetooth PAN, etc.)
                # that never receive a packet. That join would happen while
                # holding self._lock, freezing every other endpoint (status,
                # stats, start) along with it. Signal the sniffer to stop and
                # return immediately instead of waiting for the threads to
                # fully unwind.
                self._sniffer.stop(join=False)
            except Exception:
                pass
            self._draining_sniffer = self._sniffer
            self._sniffer = None
            self.stats["running"] = False
            self.stats["stop_time"] = time.time()
            return True, "stopped"

    def get_stats(self):
        now = time.time()
        with self._lock:
            data = dict(self.stats)
            cutoff = now - 1.0
            pps = sum(1 for t in self._recent_ts if t >= cutoff)

        if not data["start_time"]:
            data["uptime"] = 0
        elif data["running"]:
            data["uptime"] = now - data["start_time"]
        else:
            # Stopped: freeze uptime at the moment stop() was called instead
            # of letting it keep counting up off the wall clock.
            data["uptime"] = (data["stop_time"] or now) - data["start_time"]

        # Packets/sec should read 0 once stopped rather than trailing off
        # over the last second of stale timestamps.
        data["pps"] = pps if data["running"] else 0
        return data


sniffer_service = SnifferService()
