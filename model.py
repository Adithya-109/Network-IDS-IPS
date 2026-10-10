import time
import threading
import logging
import os
import joblib
from collections import deque
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

class MLAnomalyEngine:
    def __init__(self, retrain_interval_seconds=60, window_size=5000, contamination="auto", persist_dir="."):
        self.retrain_interval_seconds = retrain_interval_seconds
        self.window_size = window_size
        self.contamination = contamination
        self.persist_dir = persist_dir
        
        self.ml_enabled = ML_AVAILABLE
        self.model = None
        self.is_trained = False
        self._lock = threading.Lock()
        
        # Buffer of recent clean features
        self.training_buffer = deque(maxlen=self.window_size)
        
        self.running = False
        self._thread = None
        
        self.model_path = os.path.join(persist_dir, "model.joblib")
        self.load_model()
        
    def load_model(self):
        if not self.ml_enabled:
            return
        try:
            if os.path.exists(self.model_path):
                with self._lock:
                    self.model = joblib.load(self.model_path)
                    self.is_trained = True
                logging.info("[MLEngine] Loaded existing model from disk.")
        except Exception as e:
            logging.error(f"[MLEngine] Failed to load model: {e}")

    def save_model(self):
        try:
            with self._lock:
                if self.model:
                    # Write to a temp file then rename for atomic save
                    temp_path = self.model_path + ".tmp"
                    joblib.dump(self.model, temp_path)
                    os.replace(temp_path, self.model_path)
        except Exception as e:
            logging.error(f"[MLEngine] Failed to save model: {e}")

    def add_clean_sample(self, features):
        if not self.ml_enabled:
            return
        with self._lock:
            self.training_buffer.append(features)

    def extract_features(self, pkt_len, proto_name, ema_iat, flags, dport, pps):
        is_tcp = 1 if proto_name == "TCP" else 0
        is_udp = 1 if proto_name == "UDP" else 0
        is_icmp = 1 if proto_name == "ICMP" else 0
        
        # Bucketize port
        port_bucket = 0
        if dport is not None:
            if dport < 1024:
                port_bucket = 1
            elif dport < 10000:
                port_bucket = 2
            else:
                port_bucket = 3
                
        # Return list of features
        flags_int = int(flags) if flags is not None else 0
        return [pkt_len, ema_iat, is_tcp, is_udp, is_icmp, flags_int, port_bucket, pps]

    def predict(self, features):
        if not self.ml_enabled or not self.is_trained:
            return 1 # 1 means normal
        
        with self._lock:
            if not self.model:
                return 1
            try:
                # model.predict expects a 2D array
                return self.model.predict([features])[0]
            except Exception as e:
                logging.error(f"[MLEngine] Prediction error: {e}")
                return 1

    def _retrain_loop(self):
        while self.running:
            time.sleep(self.retrain_interval_seconds)
            if not self.ml_enabled:
                continue
                
            with self._lock:
                buffer_copy = list(self.training_buffer)
                
            if len(buffer_copy) < min(100, self.window_size // 10):
                # Not enough data to retrain
                continue
                
            try:
                new_model = IsolationForest(
                    n_estimators=100, 
                    contamination=self.contamination, 
                    random_state=42
                )
                new_model.fit(buffer_copy)
                
                with self._lock:
                    self.model = new_model
                    self.is_trained = True
                
                self.save_model()
                logging.info(f"[MLEngine] Retrained model on {len(buffer_copy)} samples.")
            except Exception as e:
                logging.error(f"[MLEngine] Retraining failed: {e}")

    def start(self):
        if not self.ml_enabled or self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._retrain_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)
            
    def update_config(self, interval, window, contamination):
        with self._lock:
            self.retrain_interval_seconds = interval
            self.window_size = window
            self.contamination = contamination
            # Note: The deque maxlen cannot be easily changed in place without recreating
            if self.training_buffer.maxlen != window:
                old_items = list(self.training_buffer)[-window:]
                self.training_buffer = deque(old_items, maxlen=window)
