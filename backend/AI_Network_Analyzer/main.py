import sys
import json

# --- DETERMINISTIC LOGIC (No Randomness) ---
def analyze_packet_data(data):
    # 1. Parse Inputs (with defaults)
    protocol = data.get('protocol', 'TCP').upper()
    service = data.get('service', 'OTHER').upper()
    
    # Handle numbers safely
    try:
        length = int(data.get('packet_len', 0))
    except:
        length = 0
        
    try:
        duration = int(data.get('duration', 0))
    except:
        duration = 0
        
    flags = data.get('flags', {})
    
    score = 0
    reasons = []

    # --- RULE 1: Protocol/Service Anomalies ---
    # SSH is almost always TCP. UDP on Port 22 is suspicious.
    if protocol == 'UDP' and service == 'SSH':
        score += 50
        reasons.append("UDP protocol used on SSH service (Suspicious)")

    # HTTP is TCP. UDP on Port 80 is rare (QUIC uses UDP but on 443 usually).
    if protocol == 'UDP' and service == 'HTTP':
        score += 30
        reasons.append("UDP protocol used on HTTP service (Unusual)")

    # --- RULE 2: Anomalous Packet Sizes ---
    # Ping of Death (Large ICMP)
    if protocol == 'ICMP' and length > 1000:
        score += 60
        reasons.append(f"ICMP packet too large ({length} bytes) - Potential DoS")
    
    # Tiny TCP packets (often used for scanning)
    if protocol == 'TCP' and length < 20 and not flags.get('SYN') and not flags.get('FIN'):
        score += 20
        reasons.append("Abnormally small TCP packet (Potential Scan)")

    # Jumbo packets on standard DNS
    if service == 'DNS' and length > 1500:
        score += 40
        reasons.append("Large DNS packet (Potential Data Exfiltration/Tunneling)")

    # --- RULE 3: Flag Anomalies (TCP Only) ---
    if protocol == 'TCP':
        # URG flag is rarely used legitimately in modern web traffic
        if flags.get('URG'):
            score += 40
            reasons.append("URG flag set (High Evasion Potential)")
            
        # SYN-FIN combination is illegal (Christmas Tree Attack)
        if flags.get('SYN') and flags.get('FIN'):
            score += 80
            reasons.append("Illegal TCP Flag Combo: SYN+FIN (Xmas Scan)")

    # --- RULE 4: Duration Anomalies ---
    # Long duration on non-persistent protocols
    if service == 'DNS' and duration > 2000: # 2 seconds
        score += 30
        reasons.append("Long duration DNS query (Suspicious)")

    # --- FINAL CLASSIFICATION ---
    # Deterministic Scoring (0-100)
    
    if score >= 60:
        risk = "Malicious"
        finding = f"CRITICAL: {reasons[0]}"
    elif score >= 30:
        risk = "Suspicious"
        finding = f"WARNING: {reasons[0]}"
    else:
        risk = "Benign"
        finding = "Traffic appears normal."
        score = 0 # Clean baseline

    return {
        "ok": True,
        "tool": "AI Network Analyzer",
        "risk_level": risk,
        "main_finding": finding,
        "data": {
            "anomaly_score": f"{min(score, 100)}%",
            "detection_factors": reasons if reasons else ["Matches baseline traffic profile"]
        }
    }

# --- CLI HANDLER ---
if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            raw_arg = " ".join(sys.argv[1:]).strip()
            
            # Clean quotes
            if raw_arg.startswith("'") and raw_arg.endswith("'"): raw_arg = raw_arg[1:-1]
            if raw_arg.startswith('"') and raw_arg.endswith('"'): raw_arg = raw_arg[1:-1]

            parsed_data = {}

            # Attempt 1: JSON
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
                # Attempt 2: Plain Text "Protocol Service Length"
                parts = raw_arg.split()
                if len(parts) >= 1: parsed_data['protocol'] = parts[0]
                if len(parts) >= 2: parsed_data['service'] = parts[1]
                if len(parts) >= 3: parsed_data['packet_len'] = parts[2]

            result = analyze_packet_data(parsed_data)
            print(json.dumps(result))
        else:
            print(json.dumps({"ok": False, "error": "No input provided"}))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))