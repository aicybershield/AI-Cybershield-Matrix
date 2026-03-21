import sys
import json
import os
import random
from joblib import load
from datetime import datetime
import pandas as pd
import numpy as np

# --- CONFIGURATION ---
TOOL_NAME = "AI Phishing Detector"
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_files')
MODEL_PATH = os.path.join(MODEL_DIR, 'phishing_model.joblib')
FEATURES_LIST_PATH = os.path.join(MODEL_DIR, 'phishing_features.joblib')

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

def run_ml_analysis(model, feature_columns, raw_url):
    """
    Simulates the preprocessing and runs the prediction on the loaded model.
    
    NOTE: In a production tool, the complex feature extraction logic 
    (calculating NumDots, UrlLength, etc., from raw_url) MUST happen here.
    """
    
    # --- STEP 1: Feature Extraction/Generation (SIMULATED PLACEHOLDER) ---
    # This is the single most complex step in a real Phishing Detector tool.
    # It must analyze the 'raw_url' and generate a dictionary of 50+ numerical features.
    
    # We create a placeholder DataFrame (DF) that mirrors the structure used during training.
    # The values here are randomized just for testing the deployment structure.
    
    feature_data = {}
    for feature in feature_columns:
        # Simulate generating a plausible numerical value for each feature
        if 'level' in feature.lower() or 'num' in feature.lower():
            feature_data[feature] = random.randint(0, 10)
        elif 'length' in feature.lower():
            feature_data[feature] = random.randint(30, 200)
        else: # Assuming boolean or float features
            feature_data[feature] = random.choice([0.0, 1.0])

    # CRITICAL: Convert the feature dictionary into a Pandas DataFrame in the exact order
    # This ensures the model receives the features in the same sequence as training.
    X_predict = pd.DataFrame([feature_data], columns=feature_columns)
    
    # --- STEP 2: Prediction ---
    prediction_array = model.predict(X_predict)
    prediction = prediction_array[0] # Get the class label (0 or 1)
    
    # Get probability/confidence score
    confidence = model.predict_proba(X_predict).max()
    
    # --- STEP 3: Report Generation ---
    # Assuming 1 = Phishing (Malicious), 0 = Legitimate (Benign)
    is_phishing = (prediction == 1)
    
    risk = "HIGH RISK (Phishing)" if is_phishing else "CLEAN (Legitimate)"
    
    finding = f"Predicted as {risk} with {confidence*100:.2f}% confidence."

    return {
        "tool_prediction": risk,
        "confidence_score": float(confidence),
        "risk_level": risk,
        "main_finding": finding,
        "advanced_report_details": {
            "model_type": "Random Forest Classifier",
            "feature_count": len(feature_columns),
            "simulated_features_used": True
        }
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("ERROR: No URL input provided.\n")
        sys.exit(1)
        
    raw_input_url = sys.argv[1]
    
    # Load the model and feature columns
    model, feature_columns = load_ml_artifacts()
    
    # Run the analysis
    final_report_data = run_ml_analysis(model, feature_columns, raw_input_url)
    
    # 3. Print the final JSON report to stdout for app.py to capture
    report = {
        "tool": TOOL_NAME,
        "input_received": raw_input_url,
        "timestamp": str(datetime.now()),
        **final_report_data
    }
    
    # Print the full JSON report to stdout
    print(json.dumps(report, indent=4))