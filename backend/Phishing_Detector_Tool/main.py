import sys
import json
import re
import traceback
from datetime import datetime
import joblib
import os

TOOL_NAME = "AI Phishing Detector"

def extract_features(url):
    """
    Extracts the EXACT 12 features used during model training in the EXACT same order.
    """
    url_length = len(url)
    num_dots = url.count('.')
    num_dash = url.count('-')
    at_symbol = 1 if '@' in url else 0
    tilde_symbol = 1 if '~' in url else 0
    num_underscore = url.count('_')
    num_percent = url.count('%')
    num_ampersand = url.count('&')
    num_hash = url.count('#')
    num_numeric_chars = sum(c.isdigit() for c in url)
    no_https = 0 if url.startswith('https://') else 1
    ip_address = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    
    return [[
        url_length, num_dots, num_dash, at_symbol, tilde_symbol, 
        num_underscore, num_percent, num_ampersand, num_hash, 
        num_numeric_chars, no_https, ip_address
    ]]

if __name__ == "__main__":
    # 1. Check if input was provided
    if len(sys.argv) < 2:
        print(json.dumps({
            "tool": TOOL_NAME,
            "timestamp": str(datetime.now()),
            "risk_level": "Error",
            "main_finding": "No URL provided to the script.",
            "output": "System Error"
        }))
        sys.exit(1)

    raw_url = sys.argv[1]

    try:
        # 2. Extract Features
        feature_values = extract_features(raw_url)
        
        # 3. Load Model
        # Note: Adjust this path if main.py is inside a 'tools' directory (e.g., '../models/phishing_rf_model.pkl')
        model_path = 'models/phishing_rf_model.pkl' 
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found at '{model_path}'. Please run train_model.py first.")
            
        rf_model = joblib.load(model_path)
        
        # 4. Predict
        # CLASS_LABEL 1 = Phishing, 0 = Legitimate
        prediction = rf_model.predict(feature_values)[0]
        
        # Get probability/confidence
        confidence = rf_model.predict_proba(feature_values)[0][prediction] * 100
        is_phishing = bool(prediction == 1)
        
        # 5. Build Success Report
        report = {
            "tool": TOOL_NAME,
            "input_received": raw_url,
            "timestamp": str(datetime.now()),
            "risk_level": "High Risk (Phishing)" if is_phishing else "Safe (Benign)",
            "main_finding": f"Analyzed URL structure. Model confidence: {confidence:.2f}%",
            "output": "Phishing Detected" if is_phishing else "Authentic Link"
        }
        print(json.dumps(report, indent=4))

    except Exception as e:
        # Catch ANY error and print the exact reason back to the dashboard
        error_report = {
            "tool": TOOL_NAME,
            "input_received": raw_url,
            "timestamp": str(datetime.now()),
            "risk_level": "System Error",
            "main_finding": f"Python Error: {str(e)}",
            "output": str(traceback.format_exc())
        }
        print(json.dumps(error_report, indent=4))