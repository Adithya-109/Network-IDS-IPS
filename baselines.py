import time
import math
import threading
from collections import OrderedDict

class LRUTTLCache:
    """A simple thread-safe LRU cache with TTL eviction."""
    def __init__(self, maxsize=10000, ttl=300):
        self.maxsize = maxsize
        self.ttl = ttl
        self.cache = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            if key in self.cache:
                val, timestamp = self.cache[key]
                if time.time() - timestamp > self.ttl:
                    del self.cache[key]
                    return None
                self.cache.move_to_end(key)
                self.cache[key] = (val, time.time()) # Update timestamp
                return val
            return None

    def set(self, key, value):
        with self._lock:
            self.cache[key] = (value, time.time())
            self.cache.move_to_end(key)
            if len(self.cache) > self.maxsize:
                self.cache.popitem(last=False)

    def prune(self):
        now = time.time()
        with self._lock:
            keys_to_delete = []
            for k, (v, ts) in self.cache.items():
                if now - ts > self.ttl:
                    keys_to_delete.append(k)
            for k in keys_to_delete:
                del self.cache[k]


class BaselineTracker:
    """Tracks EMA mean and variance for a specific metric over time."""
    def __init__(self, alpha=0.1):
        self.alpha = alpha
        self.mean = None
        self.var = 0.0
        self.samples = 0

    def update(self, value):
        self.samples += 1
        if self.mean is None:
            self.mean = float(value)
            self.var = 0.0
        else:
            diff = value - self.mean
            self.mean += self.alpha * diff
            self.var = (1 - self.alpha) * (self.var + self.alpha * diff * diff)

    def get_threshold(self, k_sigma, floor, ceiling, is_warm=True):
        if not is_warm or self.mean is None:
            return ceiling # Fall back to static threshold (ceiling) when warming up

        std_dev = math.sqrt(self.var)
        thresh = self.mean + k_sigma * std_dev
        
        if thresh < floor:
            return floor
        if thresh > ceiling:
            return ceiling
        return thresh


class AdaptiveThresholds:
    """Manages baselines for multiple IPs and metrics."""
    def __init__(self, max_ips=10000, ttl=600):
        self.cache = LRUTTLCache(maxsize=max_ips, ttl=ttl)
        # We need to periodically compute rates. Since detector is per-packet,
        # we can track rates by keeping counts in time buckets (e.g. 1 sec buckets).
        
    def get_tracker(self, src_ip, metric_name):
        key = f"{src_ip}_{metric_name}"
        tracker = self.cache.get(key)
        if not tracker:
            tracker = BaselineTracker()
            self.cache.set(key, tracker)
        return tracker

    def update_baseline(self, src_ip, metric_name, value):
        """Updates the baseline with a *normal* (non-malicious) measurement."""
        tracker = self.get_tracker(src_ip, metric_name)
        tracker.update(value)
        self.cache.set(f"{src_ip}_{metric_name}", tracker) # refresh TTL
