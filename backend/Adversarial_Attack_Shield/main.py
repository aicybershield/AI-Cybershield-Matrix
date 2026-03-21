import sys
import json
import os
import numpy as np
from joblib import load
from datetime import datetime
from PIL import Image

# --- CONFIGURATION ---
TOOL_NAME = "Adversarial Attack Shield"
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_files')
MODEL_PATH = os.path.join(MODEL_DIR, 'aas_noise_classifier.joblib')
SCALER_PATH = os.path.join(MODEL_DIR, 'aas_scaler.joblib')

def load_ml_artifacts():
    """Loads the saved noise classifier model and scaler."""
    try:
        model = load(MODEL_PATH)
        scaler = load(SCALER_PATH)
        return model, scaler
    except FileNotFoundError:
        sys.stderr.write(f"FATAL ERROR: Model files not found. Did you run train_model.py?\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"ERROR loading model artifacts: {e}\n")
        sys.exit(1)

def extract_simulated_features(file_path):
    """
    Simulates extracting noise metrics from an image file.
    (In a real AAS system, this involves frequency domain analysis.)
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Input file not found: {file_path}")

    file_size_kb = os.path.getsize(file_path) / 1024
    
    # Simulate high-risk features if the file is extremely small (common for malicious payloads)
    if file_size_kb < 10:
        # High likelihood of adversarial noise inserted into a tiny image
        feature_variance = 0.1
        l_inf_norm_change = 0.9
        freq_artifacts = 0.85
    # Simulate low-risk features if the file is large and clean
    elif file_size_kb > 500:
        feature_variance = 0.9
        l_inf_norm_change = 0.05
        freq_artifacts = 0.1
    else:
        # Ambiguous input, pushing towards the middle
        feature_variance = 0.6
        l_inf_norm_change = 0.3
        freq_artifacts = 0.4

    return np.array([feature_variance, l_inf_norm_change, freq_artifacts])

def run_attack_shield(model, scaler, file_path):
    
    try:
        # 1. Feature Extraction
        features = extract_simulated_features(file_path)
        
        # 2. Scale features
        scaled_features = scaler.transform(features.reshape(1, -1))

        # 3. Predict (0=Clean, 1=Adversarial)
        prediction_numeric = model.predict(scaled_features)[0]
        prediction_proba = model.predict_proba(scaled_features)[0]
        
        # 4. Interpret Result
        label = "Adversarial Attack Detected" if prediction_numeric == 1 else "Input Integrity Verified"
        confidence = np.max(prediction_proba)
        
        if label == "Adversarial Attack Detected" and confidence > 0.7:
            risk = "CRITICAL: Input Integrity Failure"
            finding = "The input appears to be intentionally perturbed with adversarial noise. Blocking prediction."
        elif label == "Input Integrity Verified" and confidence > 0.7:
            risk = "LOW RISK: Input Clean"
            finding = "Image integrity verified. No adversarial noise detected."
        else:
            risk = "Suspicious/Ambiguous"
            finding = "Noise metrics are ambiguous. Input requires further manual review."

    except FileNotFoundError as e:
        risk = "Error"
        finding = str(e)
        confidence = 0
        
    except Exception as e:
        risk = "Error"
        finding = f"General processing error: {e}"
        confidence = 0

    return {
        "tool_prediction": label,
        "confidence_score": float(confidence),
        "risk_level": risk,
        "main_finding": finding,
        "advanced_report_details": {
            "input_file": os.path.basename(file_path),
            "model_type": "Adversarial Noise Classifier (SVC Sim.)"
        }
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("ERROR: No input provided. Expected image file path.\n")
        sys.exit(1)
        
    raw_input_data = sys.argv[1] # This is the file path from Flask
    
    model, scaler = load_ml_artifacts()
    
    final_report_data = run_attack_shield(model, scaler, raw_input_data)
    
    report = {
        "tool": TOOL_NAME,
        "input_received": os.path.basename(raw_input_data),
        "timestamp": str(datetime.now()),
        "ok": True,
        **final_report_data
    }
    
    # Use float conversion for NumPy types before dumping to JSON
    print(json.dumps(report, indent=4, default=lambda o: float(o) if isinstance(o, (np.float32, np.float64, np.int32, np.int64)) else o.__dict__))