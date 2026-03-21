import sys
import json
import os
import re
from joblib import load
from datetime import datetime
import pandas as pd
import numpy as np
import math

# --- CONFIGURATION ---
TOOL_NAME = "Password Strength Analyzer"
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_files')
MODEL_PATH = os.path.join(MODEL_DIR, 'password_model.joblib')
FEATURES_LIST_PATH = os.path.join(MODEL_DIR, 'password_features.joblib')
# Define the labels that match the numerical scores (0, 1, 2...) predicted by the model
STRENGTH_LABELS = ["Very Weak", "Weak", "Medium", "Strong"] 
# Assuming the training mapped 0, 1, 2, 3 to these labels. Adjust if your model outputs more/fewer classes.

def load_ml_artifacts():
    """Loads the trained ML model and the list of expected feature columns."""
    try:
        model = load(MODEL_PATH)
        feature_columns = load(FEATURES_LIST_PATH)
        return model, feature_columns
    except FileNotFoundError:
        # If model files are missing, the tool cannot run.
        sys.stderr.write(f"FATAL ERROR: Model files not found for {TOOL_NAME}. Did you run train_model.py?\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"ERROR loading model artifacts: {e}\n")
        sys.exit(1)

def extract_password_features(password):
    """Calculates the exact numerical features from the raw password input."""
    
    # 1. Shannon Entropy calculation
    def calculate_entropy(s):
        if not s: return 0
        counts = {}
        for char in s:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0
        for count in counts.values():
            p = count / len(s)
            entropy += p * math.log2(p)
        return -entropy
    
    # 2. Calculate the features that must match the columns used during training
    features = {
        'entropy': calculate_entropy(password), # Existing feature in CSV
        'length': len(password),               # Derived feature
        'upper_count': sum(1 for c in password if c.isupper()), # Derived feature
        'symbol_count': sum(1 for c in password if not c.isalnum()), # Derived feature
        'digit_count': sum(1 for c in password if c.isdigit()) # Derived feature
        # NOTE: This list MUST match the columns saved in 'password_features.joblib'
    }
    return features

def run_ml_analysis(model, feature_columns, raw_password):
    """Runs the prediction on the loaded model."""
    
    # Handle empty input case to prevent errors
    if not raw_password:
        return {
            "tool_prediction": "Very Weak",
            "confidence_score": 1.0,
            "risk_level": "Very Weak",
            "main_finding": "Input empty. Predicted strength: Very Weak (100% confidence).",
            "advanced_report_details": {"model_type": "Random Forest Classifier", "input_valid": False}
        }
        
    # 1. Extract features
    feature_dict = extract_password_features(raw_password)
    
    # 2. CRITICAL: Convert the feature dictionary into a DataFrame
    # Column order is maintained using the loaded feature_columns list
    X_predict = pd.DataFrame([feature_dict], columns=feature_columns)
    
    # 3. Run Prediction
    prediction_index = model.predict(X_predict)[0]
    confidence = model.predict_proba(X_predict).max()
    
    # 4. Map numerical prediction (0, 1, 2...) to a human-readable label
    # Clamp the index to prevent errors if the model outputs an unexpected class number
    safe_index = int(np.clip(prediction_index, 0, len(STRENGTH_LABELS) - 1))
    prediction_label = STRENGTH_LABELS[safe_index]

    return {
        "tool_prediction": prediction_label,
        "confidence_score": float(confidence),
        "risk_level": prediction_label,
        "main_finding": f"Predicted strength: {prediction_label} (Confidence: {confidence*100:.2f}%)",
        "advanced_report_details": {
            "prediction_index": int(prediction_index),
            "features_analyzed": feature_dict,
            "model_type": "Random Forest Classifier"
        }
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("ERROR: No password input provided.\n")
        sys.exit(1)
        
    raw_input_password = sys.argv[1]
    
    model, feature_columns = load_ml_artifacts()
    
    final_report_data = run_ml_analysis(model, feature_columns, raw_input_password)
    
    report = {
        "tool": TOOL_NAME,
        "input_received": raw_input_password,
        "timestamp": str(datetime.now()),
        "ok": True,
        **final_report_data
    }
    
    # Print the full JSON report to stdout for Flask to capture
    print(json.dumps(report, indent=4))