import sys
import json
import re
from datetime import datetime
import os
import random

# --- SIMULATION LOGIC ---

def analyze_url_features(url):
    """Simulates checking URL structure features commonly used by phishing detectors."""
    
    # Feature 1: IP address in domain (Highly suspicious)
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        return 0.95, "IP address found in URL. CRITICAL risk factor."
        
    # Feature 2: High number of subdomains (e.g., 'login.secure.bank.com.phish.com')
    if url.count('.') > 5:
        return 0.85, "Excessive subdomains used, often to conceal the true domain."
        
    # Feature 3: Long URL length
    if len(url) > 75:
        return 0.70, "URL length is unusually long, possibly to hide domain details."

    # Feature 4: Contains sensitive keywords (e.g., 'login', 'secure', 'verify')
    keywords = ['login', 'secure', 'verify', 'account']
    if any(k in url.lower() for k in keywords):
        # Only flagged if combined with other suspicious factors, simulated randomly here
        if random.random() < 0.3:
             return 0.60, "URL contains sensitive keywords, increasing suspicion."

    # Default: Not immediately obvious phishing features
    return 0.15, "URL structure appears normal."

def run_fake_login_analysis(url):
    """Simulates the comprehensive analysis of a login page URL."""
    
    if not url or not url.startswith(('http://', 'https://')):
        risk = "ERROR"
        return {
            "ok": False,
            "risk_level": risk,
            "tool_prediction": "Invalid Input",
            "main_finding": "Input must be a valid URL starting with http:// or https://",
            "confidence_score": 0.0,
        }

    # 1. Simulate structural and code analysis
    # NOTE: The actual deep code analysis is simulated via the risk_factor below.
    
    # 2. Analyze simple URL features
    url_risk_factor, url_finding = analyze_url_features(url)

    # Simulate deep HTML code analysis result (e.g., checking form action)
    # If the URL looks suspicious, increase the simulated code risk factor.
    code_risk_factor = url_risk_factor + random.uniform(0.05, 0.2)
    
    # Determine overall risk
    max_risk = max(url_risk_factor, code_risk_factor)
    
    if max_risk >= 0.75:
        risk_level = "CRITICAL: Phishing Attempt"
        prediction = "Malicious/Phishing Page Detected"
        finding = f"CRITICAL: Form action is likely external or {url_finding}."
    elif max_risk >= 0.50:
        risk_level = "HIGH RISK: Structural Anomalies"
        prediction = "Suspicious Page Detected"
        finding = f"HIGH RISK: Page structure contains multiple anomalies. {url_finding}"
    else:
        risk_level = "LOW RISK: Verified"
        prediction = "Authentic Login Page"
        finding = f"Page structure verified clean. {url_finding}"

    return {
        "ok": True,
        "risk_level": risk_level,
        "tool_prediction": prediction,
        "main_finding": finding,
        "confidence_score": float(max_risk),
        "advanced_report_details": {
            "url_analyzed": url,
            "url_feature_risk": f"{url_risk_factor:.2f}",
            "simulated_code_analysis_risk": f"{code_risk_factor:.2f}"
        }
    }


# --- EXECUTION ENTRY POINT ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        report = {
            "ok": False,
            "risk_level": "ERROR",
            "tool_prediction": "Missing Input",
            "main_finding": "No URL provided for analysis.",
            "confidence_score": 0.0
        }
    else:
        # sys.argv[1] is the URL string passed from Flask
        url_input = sys.argv[1]
        report = run_fake_login_analysis(url_input)
    
    report["tool"] = "AI Fake Login Detector"
    report["timestamp"] = datetime.now().isoformat()
    
    print(json.dumps(report, indent=4))