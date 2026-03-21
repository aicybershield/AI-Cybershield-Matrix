import sys
import json
import os
import hashlib
from datetime import datetime
from PIL import Image # NEW IMPORT
import numpy as np

# --- CONFIGURATION ---
TOOL_NAME = "File & URL Scanner"

def run_scanner(input_data):
    
    # 1. Check if the input is a file path (for image uploads)
    if os.path.exists(input_data):
        return analyze_image_file(input_data)
        
    # 2. Assume input is a URL or text (original behavior)
    return analyze_text_url(input_data)

def analyze_image_file(file_path):
    
    # Simulate malicious detection based on file properties
    risk = "Suspicious (Image)"
    finding = "File analyzed successfully."
    
    try:
        # Check if it's a known allowed image type
        if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
            # Simulate ML Analysis: Load image, resize, analyze
            img = Image.open(file_path)
            
            # Simulated check: High risk if resolution is unusual (e.g., extremely large or 1x1 size for steganography)
            if img.width > 4000 or img.height > 4000:
                 risk = "High Risk (Oversized Image)"
                 finding = "Image integrity check flagged an extremely high-resolution file. Potential resource exhaustion or steganography target."
            
            # Simple check for a specific known malicious hash (e.g., a hash known to contain a hidden payload)
            file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
            if file_hash.startswith('a1b2c3d4e5f6'): # Simulated malicious hash prefix
                risk = "Malicious (Image Payload)"
                finding = "Image hash matches known malicious payload fingerprint."

        else:
             risk = "High Risk (Unsupported File)"
             finding = f"File type not supported for deep analysis. Only images are supported."
             
    except Exception as e:
        risk = "Error"
        finding = f"Failed to process image file: {str(e)}"

    return {
        "tool_prediction": risk,
        "risk_level": risk,
        "main_finding": finding,
        "advanced_report_details": {
            "input_type": "Image File",
            "file_path": file_path,
            "simulated_analysis": True
        }
    }
    
def analyze_text_url(input_data):
    # --- ORIGINAL TEXT/URL SCANNING LOGIC ---
    if "malicious_script" in input_data.lower() or "bit.ly/malware" in input_data.lower():
        risk = "Malicious"
        finding = "Text/URL contains keywords associated with known malware distribution."
    elif "password_reset_urgent" in input_data.lower() or "fake-login-page.com" in input_data.lower():
        risk = "Suspicious"
        finding = "URL or text suggests a phishing attempt."
    else:
        risk = "Clean"
        finding = "No immediate threats found in the provided text or URL."

    return {
        "tool_prediction": risk,
        "risk_level": risk,
        "main_finding": finding,
        "advanced_report_details": {
            "input_type": "Text/URL",
            "input_summary": input_data[:50],
            "simulated_analysis": True
        }
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("ERROR: No input provided. Expected file path or text/URL string.\n")
        sys.exit(1)
        
    raw_input_data = sys.argv[1]
    
    final_report_data = run_scanner(raw_input_data)
    
    report = {
        "tool": TOOL_NAME,
        "input_received": raw_input_data,
        "timestamp": str(datetime.now()),
        "ok": True,
        **final_report_data
    }
    
    # Use float conversion for NumPy types before dumping to JSON
    print(json.dumps(report, indent=4, default=lambda o: float(o) if isinstance(o, (np.float32, np.float64, np.int32, np.int64)) else o.__dict__))