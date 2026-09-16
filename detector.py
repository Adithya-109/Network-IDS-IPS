import time
from collections import defaultdict
from database import add_event


# =========================
# PORT SCAN DETECTION
# =========================

port_activity = defaultdict(list)

PORT_SCAN_THRESHOLD = 10
PORT_SCAN_TIME_WINDOW = 10


def detect_port_scan(packet):

    if not packet.haslayer("IP"):
        return

    if not packet.haslayer("TCP"):
        return

    source_ip = packet["IP"].src
    destination_ip = packet["IP"].dst
    destination_port = packet["TCP"].dport

    current_time = time.time()

    key = (source_ip, destination_ip)

    port_activity[key].append(
        (current_time, destination_port)
    )

    # Remove old entries
    port_activity[key] = [
        item for item in port_activity[key]
        if current_time - item[0] <= PORT_SCAN_TIME_WINDOW
    ]

    unique_ports = set(
        port for _, port in port_activity[key]
    )

    if len(unique_ports) >= PORT_SCAN_THRESHOLD:

        add_event(
            source_ip,
            destination_ip,
            "Port Scan",
            "High",
            f"Multiple ports scanned: {sorted(unique_ports)}"
        )

        # Reset after detection
        port_activity[key].clear()


# =========================
# SYN FLOOD DETECTION
# =========================

syn_activity = defaultdict(list)

SYN_THRESHOLD = 50
SYN_TIME_WINDOW = 5


def detect_syn_flood(packet):

    if not packet.haslayer("IP"):
        return

    if not packet.haslayer("TCP"):
        return

    tcp_flags = packet["TCP"].flags

    # SYN packet without ACK
    if tcp_flags == "S":

        source_ip = packet["IP"].src
        destination_ip = packet["IP"].dst

        current_time = time.time()

        key = (source_ip, destination_ip)

        syn_activity[key].append(current_time)

        # Remove old entries
        syn_activity[key] = [
            t for t in syn_activity[key]
            if current_time - t <= SYN_TIME_WINDOW
        ]

        if len(syn_activity[key]) >= SYN_THRESHOLD:

            add_event(
                source_ip,
                destination_ip,
                "SYN Flood",
                "Critical",
                f"Detected {len(syn_activity[key])} SYN packets "
                f"within {SYN_TIME_WINDOW} seconds"
            )

            syn_activity[key].clear()


# =========================
# MAIN DETECTOR
# =========================

def analyze_packet(packet):

    detect_port_scan(packet)

    detect_syn_flood(packet)