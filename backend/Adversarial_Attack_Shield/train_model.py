import sys
import os
import numpy as np
from joblib import dump
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

# --- CONFIGURATION ---
TOOL_NAME = "Adversarial Attack Shield"
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_files')
MODEL_SAVE_PATH = os.path.join(MODEL_DIR, 'aas_noise_classifier.joblib')

os.makedirs(MODEL_DIR, exist_ok=True)

print(f"--- Starting {TOOL_NAME} Adversarial Noise Classifier Training ---")

# --- SIMULATED DATA (Representing input pixel features and noise) ---
# Features:
# 1. Feature_Variance (High variance suggests clean image)
# 2. L-inf_Norm_Change (High L-inf norm suggests adversarial perturbation)
# 3. Frequency_Domain_Artifacts (High artifacts suggest attack noise)
# Target: 0 (Clean), 1 (Adversarial/Noisy)
data = np.array([
    [0.9, 0.05, 0.1],   # Clean Image 1
    [0.85, 0.08, 0.15], # Clean Image 2
    [0.1, 0.95, 0.8],   # Adversarial Attack (High Noise Metrics)
    [0.15, 0.85, 0.75], # Adversarial Attack
    [0.6, 0.3, 0.4],    # Ambiguous
    [0.9, 0.1, 0.12],   # Clean Image 3
])
labels = np.array([0, 0, 1, 1, 0, 0]) 

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(data)

# Train a classifier (Simulating a sophisticated noise detector)
print("Training Adversarial Noise Classifier (SVC Sim)...")
model = SVC(kernel='rbf', probability=True, random_state=42)
model.fit(X_scaled, labels)

# Persistence
try:
    dump(model, MODEL_SAVE_PATH)
    dump(scaler, os.path.join(MODEL_DIR, 'aas_scaler.joblib')) 
    print(f"\nSUCCESS: Adversarial Noise Classifier Model Saved to {MODEL_DIR}")
    
except Exception as e:
    print(f"FATAL ERROR: Could not save model file. Error: {e}")
    sys.exit(1)

print("\n--- Model Setup Finished ---")