import os
import numpy as np
from joblib import dump
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_files')

def train_model():
    print("🚀 Training Robust Network Anomaly Model...")

    # 1. Generate Broader "Normal" Data (Baseline)
    # We mix different types of normal traffic (browsing, streaming, idle)
    X_train = []
    
    for _ in range(1000):
        # Type A: Idle/Background (Low traffic)
        if np.random.rand() > 0.5:
            duration = np.random.uniform(1, 60)      # 1s to 60s
            packets = np.random.uniform(0, 100)      # 0 to 100 packets
            bytes_in = np.random.uniform(0, 5000)    # 0 to 5 KB
            bytes_out = np.random.uniform(0, 1000)
        # Type B: Active Browsing (Medium traffic)
        else:
            duration = np.random.uniform(10, 300)    # 10s to 5 mins
            packets = np.random.uniform(100, 2000)   # 100 to 2000 packets
            bytes_in = np.random.uniform(5000, 1000000) # 5 KB to 1 MB
            bytes_out = np.random.uniform(1000, 50000)

        X_train.append([duration, packets, bytes_in, bytes_out])

    X_train = np.array(X_train)

    # 2. Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    # 3. Train Isolation Forest
    # contamination=0.01 means "expect very few anomalies in training data"
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X_scaled)

    # 4. Save
    if not os.path.exists(MODEL_DIR): os.makedirs(MODEL_DIR)
    dump(model, os.path.join(MODEL_DIR, 'network_anomaly_model.joblib'))
    dump(scaler, os.path.join(MODEL_DIR, 'network_scaler.joblib'))
    
    print("✅ Robust Network Model Saved!")

if __name__ == "__main__":
    train_model()