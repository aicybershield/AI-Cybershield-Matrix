import os
import numpy as np
from joblib import dump
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans

# --- CONFIGURATION ---
# Define where to save the model
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_files')

def train_model():
    print("🚀 Starting UEBA Model Training...")

    # 1. Create Synthetic Training Data (Normal User Behavior)
    # Features: [Login Hour (0-23), Files Accessed, Data Downloaded (MB), Unusual Location (0/1)]
    
    # "Normal" behavior: 9am-5pm, low file access, low download, 0 unusual location
    X_normal = []
    for _ in range(500):
        hour = int(np.random.normal(14, 2)) # Center around 2 PM
        files = int(np.random.normal(10, 5))
        data = int(np.random.normal(50, 20))
        loc = 0
        X_normal.append([hour, files, data, loc])

    X_train = np.array(X_normal)

    # 2. Preprocess (Scale Data)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    # 3. Train K-Means Clustering (The "Normal" Baseline)
    kmeans = KMeans(n_clusters=3, random_state=42)
    kmeans.fit(X_scaled)

    # 4. Save the Model
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)
        
    dump(kmeans, os.path.join(MODEL_DIR, 'ueba_kmeans_model.joblib'))
    dump(scaler, os.path.join(MODEL_DIR, 'ueba_scaler.joblib'))
    
    print(f"✅ Model trained and saved to: {MODEL_DIR}")

if __name__ == "__main__":
    train_model()