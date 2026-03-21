import numpy as np
from sklearn.ensemble import IsolationForest
from joblib import dump, load
import os
import sys

# --- CONFIGURATION ---
# Define the base directory of the current script (CRITICAL FIX)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Construct the full, absolute path for saving the model file
MODEL_PATH = os.path.join(BASE_DIR, 'data_poisoning_model.joblib')

# Contamination is the expected proportion of anomalies/poisoned data in the dataset.
CONTAMINATION_RATE = 0.1 

# --- SIMULATION FUNCTION: Creates a fake dataset and injects outliers ---
def generate_simulated_data(num_samples=1000, num_features=5, poisoning_rate=CONTAMINATION_RATE):
    """Generates clean data and injects obvious anomalies (poisoned data)."""
    np.random.seed(42)
    
    # 1. Generate normal, clean data (mean 10, std 2)
    clean_data = np.random.normal(loc=10.0, scale=2.0, size=(num_samples, num_features))
    
    # 2. Generate poisoned (outlier) data (maliciously high values)
    num_poisoned = int(num_samples * poisoning_rate)
    # Simulate poisoning by injecting data far outside the normal distribution
    poisoned_data = np.random.uniform(low=50.0, high=100.0, size=(num_poisoned, num_features))
    
    # 3. Combine and shuffle
    full_data = np.vstack([clean_data, poisoned_data])
    np.random.shuffle(full_data)
    
    print(f"Generated {num_samples} clean samples and {num_poisoned} poisoned samples.")
    return full_data

# --- CORE TRAINING FUNCTION ---
def train_data_poisoning_model():
    """Trains and saves the Isolation Forest model."""
    print("--- Starting Data Poisoning Monitor Model Training ---")
    
    # 1. Generate the training data
    training_data = generate_simulated_data()
    
    # 2. Define and Train the Isolation Forest Model
    # Isolation Forest is used for detecting anomalies/outliers, making it suitable for 
    # unsupervised data poisoning detection.
    model = IsolationForest(
        contamination=CONTAMINATION_RATE, 
        random_state=42,
        n_estimators=100
    )
    model.fit(training_data)
    
    # 3. Save the Model
    dump(model, MODEL_PATH)
    
    print(f"\n✅ Isolation Forest Model (Contamination: {CONTAMINATION_RATE}) successfully trained and saved to {MODEL_PATH}")

# --- EXECUTION ENTRY POINT ---
if __name__ == "__main__":
    # Ensure the directory exists before training (FIXED LOGIC)
    # This now uses BASE_DIR which is guaranteed to be correct.
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR, exist_ok=True)
        
    train_data_poisoning_model()

    # Optional: Display anomaly scores on the training data for verification
    try:
        model = load(MODEL_PATH)
        scores = model.decision_function(generate_simulated_data(num_samples=100, poisoning_rate=0.1))
        print(f"Sample Anomaly Scores (Lower is more anomalous): Min Score: {scores.min():.4f}, Max Score: {scores.max():.4f}")
    except Exception as e:
        print(f"Could not load and test model: {e}")