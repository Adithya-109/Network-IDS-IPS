import time
import logging
from collections import defaultdict, deque

import config
from rules_loader import RulesLoader
from baselines import AdaptiveThresholds
from model import MLAnomalyEngine
from reputation import ReputationManager

class DetectionEngine:
    def __init__(self):
        # Time buckets for rate calculations (simple 1-second buckets)
        self._last_bucket = defaultdict(int) # src_ip -> bucket_ts
        self._packet_count = defaultdict(int) # src_ip -> count_in_bucket
        
        # Keep basic structures for sliding windows (bounded to avoid memory leaks)
        self.port_scan_map = defaultdict(deque)
        self.syn_map = defaultdict(deque)
        self.icmp_map = defaultdict(deque)
        self.udp_map = defaultdict(deque)
        
        self._last_alert = {}
        
        self.rules_loader = RulesLoader()
        self.rules_loader.start()
        
        # Load initial config to set up dynamic modules
        rules = self.rules_loader.get_rules()
        dyn_cfg = rules.get("dynamic", {})
        
        self.baselines = AdaptiveThresholds()
        
        ml_cfg = dyn_cfg.get("model_learning", {})
        self.ml_engine = MLAnomalyEngine(
            retrain_interval_seconds=ml_cfg.get("retrain_interval_seconds", 60),
            window_size=ml_cfg.get("window_size", 5000),
            contamination=ml_cfg.get("contamination", "auto")
        )
        self.ml_engine.start()
        
        rep_cfg = dyn_cfg.get("reputation", {})
        self.reputation = ReputationManager(
            block_ttl_seconds=rep_cfg.get("block_ttl_seconds", 300),
            dry_run=rep_cfg.get("dry_run", True),
            allowlist=rep_cfg.get("allowlist", [])
        )

        self.last_seen = defaultdict(float)
        self.smoothed_iat = defaultdict(lambda: 1.0)
        
    def stop(self):
        self.rules_loader.stop()
        self.ml_engine.stop()
        self.reputation.stop()

    def _get_dynamic_config(self):
        rules = self.rules_loader.get_rules()
        return rules.get("dynamic", {})

    def _is_dynamic_enabled(self):
        return self._get_dynamic_config().get("enabled", False)

    def _cooldown_ok(self, key, now):
        last = self._last_alert.get(key, 0)
        if now - last >= config.ALERT_COOLDOWN:
            self._last_alert[key] = now
            
            # Prune old _last_alert entries to prevent memory leak
            if len(self._last_alert) > 5000:
                keys_to_delete = [k for k, ts in self._last_alert.items() if now - ts > config.ALERT_COOLDOWN * 2]
                for k in keys_to_delete:
                    del self._last_alert[k]
                    
            return True
        return False

    @staticmethod
    def _trim(dq, now, window):
        while dq and now - dq[0][0] > window:
            dq.popleft()
        if len(dq) > 1000: # hard limit to prevent OOM
            while len(dq) > 1000:
                dq.popleft()

    @staticmethod
    def _trim_flat(dq, now, window):
        while dq and now - dq[0] > window:
            dq.popleft()
        if len(dq) > 1000: # hard limit
            while len(dq) > 1000:
                dq.popleft()
                
    def _get_adaptive_threshold(self, src_ip, metric_name, current_val, fallback_static):
        if not self._is_dynamic_enabled():
            return fallback_static, False
            
        dyn_cfg = self._get_dynamic_config()
        th_cfg = dyn_cfg.get("adaptive_thresholds", {})
        k_sigma = th_cfg.get("k_sigma", 3.0)
        warmup = th_cfg.get("warmup_samples", 50)
        
        floors = th_cfg.get("floor_limits", {})
        ceilings = th_cfg.get("ceiling_limits", {})
        
        floor = floors.get(metric_name, fallback_static // 2)
        ceiling = ceilings.get(metric_name, fallback_static * 2)
        
        tracker = self.baselines.get_tracker(src_ip, metric_name)
        
        is_warm = tracker.samples >= warmup
        thresh = tracker.get_threshold(k_sigma, floor, ceiling, is_warm=is_warm)
        
        return thresh, True
        
    def update_baseline_if_normal(self, src_ip, metric_name, current_val, is_alert):
        if not is_alert and self._is_dynamic_enabled():
            self.baselines.update_baseline(src_ip, metric_name, current_val)

    def _process_alert(self, src_ip, detection_type, severity, description, baseline_info=None, method="static", rule_id=None, category=None):
        now = time.time()
        score, is_blocked = self.reputation.add_alert(src_ip, severity, detection_type, now)
        
        alert = {
            "detection_type": detection_type,
            "severity": severity,
            "description": description,
            "score": score,
            "method": method
        }
        
        if rule_id:
            alert["rule_id"] = rule_id
        if category:
            alert["category"] = category
        if baseline_info:
            alert["baseline"] = baseline_info
        if is_blocked:
            alert["action"] = "BLOCKED"
            
        return alert

    def check_port_scan(self, src_ip, dport, now):
        dq = self.port_scan_map[src_ip]
        dq.append((now, dport))
        self._trim(dq, now, config.PORT_SCAN_WINDOW)
        distinct_ports = {p for _, p in dq}
        current_val = len(distinct_ports)
        
        thresh, is_dynamic = self._get_adaptive_threshold(src_ip, "PORT_SCAN", current_val, config.PORT_SCAN_THRESHOLD)
        is_alert = current_val >= thresh
        
        self.update_baseline_if_normal(src_ip, "PORT_SCAN", current_val, is_alert)
        
        if is_alert:
            if self._cooldown_ok((src_ip, "PORT_SCAN"), now):
                desc = f"{src_ip} contacted {current_val} distinct ports within {config.PORT_SCAN_WINDOW}s (threshold: {thresh:.1f})"
                return self._process_alert(src_ip, "Port Scan", "High", desc, 
                                           baseline_info=f"thresh={thresh:.1f}", 
                                           method="adaptive" if is_dynamic else "static")
        return None

    def check_syn_flood(self, src_ip, now):
        dq = self.syn_map[src_ip]
        dq.append(now)
        self._trim_flat(dq, now, config.SYN_FLOOD_WINDOW)
        current_val = len(dq)
        
        thresh, is_dynamic = self._get_adaptive_threshold(src_ip, "SYN_FLOOD", current_val, config.SYN_FLOOD_THRESHOLD)
        is_alert = current_val >= thresh
        
        self.update_baseline_if_normal(src_ip, "SYN_FLOOD", current_val, is_alert)
        
        if is_alert:
            if self._cooldown_ok((src_ip, "SYN_FLOOD"), now):
                desc = f"{src_ip} sent {current_val} TCP SYN packets within {config.SYN_FLOOD_WINDOW}s (threshold: {thresh:.1f})"
                return self._process_alert(src_ip, "SYN Flood", "High", desc,
                                           baseline_info=f"thresh={thresh:.1f}",
                                           method="adaptive" if is_dynamic else "static")
        return None

    def check_icmp_flood(self, src_ip, now):
        dq = self.icmp_map[src_ip]
        dq.append(now)
        self._trim_flat(dq, now, config.ICMP_FLOOD_WINDOW)
        current_val = len(dq)
        
        thresh, is_dynamic = self._get_adaptive_threshold(src_ip, "ICMP_FLOOD", current_val, config.ICMP_FLOOD_THRESHOLD)
        is_alert = current_val >= thresh
        
        self.update_baseline_if_normal(src_ip, "ICMP_FLOOD", current_val, is_alert)
        
        if is_alert:
            if self._cooldown_ok((src_ip, "ICMP_FLOOD"), now):
                desc = f"{src_ip} sent {current_val} ICMP echo requests within {config.ICMP_FLOOD_WINDOW}s (threshold: {thresh:.1f})"
                return self._process_alert(src_ip, "ICMP Flood", "Medium", desc,
                                           baseline_info=f"thresh={thresh:.1f}",
                                           method="adaptive" if is_dynamic else "static")
        return None

    def check_udp_flood(self, src_ip, now):
        dq = self.udp_map[src_ip]
        dq.append(now)
        self._trim_flat(dq, now, config.UDP_FLOOD_WINDOW)
        current_val = len(dq)
        
        thresh, is_dynamic = self._get_adaptive_threshold(src_ip, "UDP_FLOOD", current_val, config.UDP_FLOOD_THRESHOLD)
        is_alert = current_val >= thresh
        
        self.update_baseline_if_normal(src_ip, "UDP_FLOOD", current_val, is_alert)
        
        if is_alert:
            if self._cooldown_ok((src_ip, "UDP_FLOOD"), now):
                desc = f"{src_ip} sent {current_val} UDP packets within {config.UDP_FLOOD_WINDOW}s (threshold: {thresh:.1f})"
                return self._process_alert(src_ip, "UDP Flood", "Medium", desc,
                                           baseline_info=f"thresh={thresh:.1f}",
                                           method="adaptive" if is_dynamic else "static")
        return None

    def check_stealth_scan(self, src_ip, dport, flags, now):
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
                desc = f"{src_ip} sent a suspicious TCP packet with irregular flags ({scan_type}) to port {dport}."
                return self._process_alert(src_ip, f"TCP Stealth Scan ({scan_type})", "High", desc, method="static")
        return None

    def check_suspicious_port(self, src_ip, dport, now):
        rules = self.rules_loader.get_rules()
        suspicious = rules.get("suspicious_ports", config.SUSPICIOUS_PORTS)
        
        if str(dport) in suspicious or dport in suspicious:
            key = (src_ip, f"SUSPICIOUS_PORT_{dport}")
            if self._cooldown_ok(key, now):
                service = suspicious.get(str(dport), suspicious.get(dport, "Unknown"))
                desc = f"{src_ip} accessed {service} port {dport} (often targeted by scanners)."
                return self._process_alert(src_ip, "Suspicious Port Activity", "Low", desc, method="static")
        return None

    def check_dpi_payload(self, src_ip, dport, payload, now):
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
        except Exception:
            return None
            
        rules = self.rules_loader.get_rules()
        matched_rule = None
        
        for rule in rules.get("dpi_signatures", []):
            if not rule.get("enabled", True):
                continue
                
            compiled_patterns = rule.get("compiled_patterns", [])
            for pattern in compiled_patterns:
                if pattern.search(payload_str):
                    matched_rule = rule
                    break
            
            if matched_rule:
                break
                
        if matched_rule:
            sig_name = matched_rule["name"]
            severity = matched_rule.get("severity", "High")
            sig_id = matched_rule.get("id")
            category = matched_rule.get("category")
            
            key = (src_ip, f"DPI_{sig_name}")
            if self._cooldown_ok(key, now):
                desc = f"{src_ip} sent malicious payload targeting port {dport}: {sig_name} signature matched."
                return self._process_alert(src_ip, "Deep Packet Inspection (L7)", severity, desc, 
                                           method="static", rule_id=sig_id, category=category)
        return None

    def check_ml_anomaly(self, src_ip, dst_ip, proto_name, packet_len, now, flags=None, dport=None):
        if not self.ml_engine.ml_enabled:
            return None
            
        # Ignore noisy local broadcast/multicast traffic (like mDNS 224.0.0.251)
        if dst_ip and (dst_ip.startswith("224.") or dst_ip.startswith("239.") or dst_ip.endswith(".255")):
            return None
            
        # Per-IP packets per second tracker
        bucket = int(now)
        if self._last_bucket[src_ip] != bucket:
            self._last_bucket[src_ip] = bucket
            self._packet_count[src_ip] = 1
        else:
            self._packet_count[src_ip] += 1
            
        pps = self._packet_count[src_ip]
            
        last_t = self.last_seen.get(src_ip, now)
        current_iat = now - last_t if last_t else 1.0
        self.last_seen[src_ip] = now
        
        prev_iat = self.smoothed_iat[src_ip]
        ema_iat = 0.8 * prev_iat + 0.2 * current_iat
        self.smoothed_iat[src_ip] = ema_iat
        
        features = self.ml_engine.extract_features(packet_len, proto_name, ema_iat, flags, dport, pps)
        
        if self._is_dynamic_enabled():
            prediction = self.ml_engine.predict(features)
            
            # Require at least 10 packets per second to trigger an ML anomaly
            # This prevents the AI from flagging random idle OS background noise
            if prediction == -1 and pps >= 10:
                key = (src_ip, "ML_ANOMALY")
                if self._cooldown_ok(key, now):
                    desc = f"Abnormal traffic pattern from {src_ip} (Avg IAT: {ema_iat:.4f}s, PPS: {pps})."
                    return self._process_alert(src_ip, "AI Anomaly (Isolation Forest)", "Low", desc, method="ML")
            else:
                self.ml_engine.add_clean_sample(features)
                
        return None
