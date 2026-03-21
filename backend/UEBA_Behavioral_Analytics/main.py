import sys
import json

def analyze_ueba(data):
    # 1. Parse Inputs
    role = data.get('role', 'Employee')
    action = data.get('action', 'Login')
    time = data.get('time', '09:00')
    location = data.get('location', 'Office')
    
    score = 0
    reasons = []

    # --- RULE 1: Time Anomalies ---
    # Late night activity is suspicious for everyone except maybe admins patching
    if time == "03:00":
        score += 30
        reasons.append(f"Activity at {time} (Late Night) is unusual.")
        if action == "DataExport":
            score += 40
            reasons.append("Data Export during late hours is highly indicative of data theft.")

    # --- RULE 2: Location Anomalies ---
    if location == "Foreign":
        score += 50
        reasons.append("Login from Foreign Country (Geo-velocity violation).")
    elif location == "Tor":
        score += 80
        reasons.append("Access via Tor Network detected (Anonymizer).")

    # --- RULE 3: Action & Role Mismatch ---
    # Standard Employees shouldn't be deleting logs or exporting bulk data
    if role == "Employee" and action == "DeleteLogs":
        score += 100
        reasons.append("CRITICAL: Standard Employee attempted to delete system logs.")
    
    if role == "Contractor" and action == "DataExport":
        score += 70
        reasons.append("Contractor performing Bulk Data Export (Potential IP Theft).")

    if role == "HR" and action == "DeleteLogs":
        score += 60
        reasons.append("HR Role attempting system log deletion is anomalous.")

    # --- SCORING ---
    if score >= 80:
        risk = "Critical"
        finding = "Insider Threat / Compromised Account Detected."
    elif score >= 40:
        risk = "Warning"
        finding = "Suspicious behavioral pattern detected."
    else:
        risk = "Normal"
        finding = "User behavior matches standard baseline."
        reasons = ["Activity is within normal parameters."]

    return {
        "ok": True,
        "tool": "UEBA Analyzer",
        "risk_level": risk,
        "main_finding": finding,
        "data": {
            "anomaly_score": score,
            "anomaly_reason": " + ".join(reasons)
        }
    }

# --- CLI HANDLER ---
if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            raw_arg = " ".join(sys.argv[1:]).strip()
            
            # Clean Quotes
            if raw_arg.startswith("'") and raw_arg.endswith("'"): raw_arg = raw_arg[1:-1]
            if raw_arg.startswith('"') and raw_arg.endswith('"'): raw_arg = raw_arg[1:-1]

            parsed_data = {}
            try:
                parsed_data = json.loads(raw_arg)
                if isinstance(parsed_data, str): 
                    try: parsed_data = json.loads(parsed_data)
                    except: pass
                elif 'input' in parsed_data:
                    try: 
                        inner = json.loads(parsed_data['input'])
                        if isinstance(inner, dict): parsed_data = inner
                    except: pass
            except:
                pass 

            result = analyze_ueba(parsed_data)
            print(json.dumps(result))
        else:
            print(json.dumps({"ok": False, "error": "No input provided"}))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))