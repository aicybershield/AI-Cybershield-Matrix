import sys
import json
import base64
import hashlib
from datetime import datetime

TOOL_NAME = "Text Encryptor/Hasher"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No input provided"}))
        sys.exit(1)
        
    raw_input = sys.argv[1]
    
    # Default values
    output = ""
    mode = "unknown"
    ok = False
    
    # Safely split the input to separate the command from the actual text
    # Example: "hash:myPassword" splits into command="hash", text="myPassword"
    if ":" in raw_input:
        parts = raw_input.split(":", 1)
        command = parts[0].strip().lower()
        text = parts[1]
    else:
        # Fallback: If no prefix is sent, assume basic Base64 encode
        command = "encode"
        text = raw_input

    # Process based on the exact command prefix sent by app.py
    try:
        if command in ["decrypt", "decode"]:
            mode = "Decode (Base64)"
            output = base64.b64decode(text.encode('utf-8')).decode('utf-8')
            ok = True
            
        elif command in ["encrypt", "encode"]:
            mode = "Encode (Base64)"
            output = base64.b64encode(text.encode('utf-8')).decode('utf-8')
            ok = True
            
        elif command in ["hash", "sha256"]:
            mode = "Hash (SHA-256)"
            output = hashlib.sha256(text.encode('utf-8')).hexdigest()
            ok = True
            
        elif command == "hex":
            mode = "Encode (Hex)"
            output = text.encode('utf-8').hex()
            ok = True
            
        else:
            mode = "Error"
            output = f"Unknown command prefix: '{command}'"
            ok = False
            
    except Exception as e:
        output = "Operation failed: Invalid input format (e.g., trying to decode non-Base64 text)."
        ok = False

    # Generate the standardized JSON report for your dashboard
    report = {
        "tool": TOOL_NAME,
        "input_received": text,  # Shows only the payload, not the command prefix
        "timestamp": str(datetime.now()),
        "risk_level": "N/A",
        "main_finding": f"Operation '{mode}' was successful." if ok else "Operation failed.",
        "output": output
    }
    
    print(json.dumps(report, indent=4))