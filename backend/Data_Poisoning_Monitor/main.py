import sys
import json
import os
import numpy as np
from sklearn.ensemble import IsolationForest
from joblib import dump, load
from datetime import datetime

# --- CONFIGURATION ---
MODEL_PATH = 'data_poisoning_model.joblib'
SCALER_PATH = 'data_poisoning_scaler.joblib'
DATASET_PATH = 'simulated_dataset.csv' # Placeholder for a real dataset

# --- SIMULATION FUNCTION: Creates a fake dataset and injects outliers ---
def generate_simulated_data(num_samples=100, num_features=5, poisoning_rate=0.05):
    # 1. Generate normal, clean data
    np.random.seed(42)
    clean_data = np.random.normal(loc=10.0, scale=2.0, size=(num_samples, num_features))
    
    # 2. Generate poisoned (outlier) data
    num_poisoned = int(num_samples * poisoning_rate)
    # Inject large, easily detectable values as poisoning
    poisoned_data = np.random.uniform(low=50.0, high=100.0, size=(num_poisoned, num_features))
    
    # 3. Combine and shuffle
    full_data = np.vstack([clean_data, poisoned_data])
    np.random.shuffle(full_data)
    
    return full_data

# --- MODEL TRAINING (Simulated Setup) ---
def train_and_save_model(data):
    # Isolation Forest is effective for anomaly detection
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(data)
    
    # Note: We don't actually need a scaler for this simple IF model, but we keep 
    # the structure consistent for complex ML pipelines.
    
    dump(model, MODEL_PATH)
    print(f"Simulated Isolation Forest model saved to {MODEL_PATH}")
    return model

# --- CORE ANALYSIS FUNCTION ---
def run_poisoning_analysis(raw_input_data):
    # The 'raw_input_data' will be the name of the dataset or model being checked.
    
    # Check if the model exists, if not, generate and train a new one (for demo purposes)
    if not os.path.exists(MODEL_PATH):
        print("Model not found. Training a simulated model...")
        data = generate_simulated_data()
        train_and_save_model(data)
    
    try:
        model = load(MODEL_PATH)
    except Exception as e:
        return {
            "ok": False,
            "tool": "Data Poisoning Monitor",
            "risk_level": "FATAL ERROR",
            "main_finding": f"Failed to load Isolation Forest model: {e}",
            "timestamp": datetime.now().isoformat()
        }

    # Simulate checking an input data batch (We reuse the generated data for simplicity)
    test_data = generate_simulated_data(num_samples=50, poisoning_rate=0.1) 
    
    # Predict anomalies: -1 for outlier/poisoned, 1 for normal/clean
    anomalies = model.predict(test_data)
    
    # Calculate key metrics
    num_total = len(anomalies)
    num_anomalies = np.sum(anomalies == -1)
    poison_percentage = (num_anomalies / num_total) * 100
    
    # --- INTERPRETATION ---
    if poison_percentage > 10.0:
        risk = "CRITICAL"
        label = "High Poisoning Risk"
        finding = f"Data contamination detected: {num_anomalies} abnormal points found ({poison_percentage:.1f}%)."
    elif poison_percentage > 3.0:
        risk = "HIGH"
        label = "Moderate Contamination Risk"
        finding = f"Suspicious activity: {num_anomalies} outliers detected ({poisoning_percentage:.1f}%). Requires manual review."
    else:
        risk = "LOW"
        label = "Integrity Verified"
        finding = f"Dataset integrity appears sound. Only {num_anomalies} benign outliers found."

    # --- REPORT GENERATION ---
    return {
        "ok": True,
        "tool": "Data Poisoning Monitor",
        "risk_level": risk,
        "tool_prediction": label,
        "main_finding": finding,
        "timestamp": datetime.now().isoformat(),
        "advanced_report_details": {
            "total_samples_checked": num_total,
            "anomalies_detected": int(num_anomalies),
            "poison_rate_metric": f"{poison_percentage:.1f}%",
            "algorithm": "Isolation Forest (Unsupervised Anomaly Detection)"
        }
    }


# --- EXECUTION ENTRY POINT ---
if __name__ == "__main__":
    if len(sys.argv) > 1:
        # In a real tool, sys.argv[1] would be the dataset path to analyze
        input_data = sys.argv[1]
    else:
        # Use a default placeholder for demonstration
        input_data = "simulated_training_data_batch"
        
    report = run_poisoning_analysis(input_data)
    print(json.dumps(report, indent=2))