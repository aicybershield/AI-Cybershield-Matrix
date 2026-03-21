import sys
import json
import base64
from datetime import datetime

TOOL_NAME = "Text Encryptor"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
        
    raw_input = sys.argv[1]
    
    # Replicate the logic from app.py but in the external tool for consistency
    if raw_input.startswith("decrypt:"):
        text = raw_input.replace("decrypt:", "", 1)
        try:
            output = base64.b64decode(text.encode()).decode()
            mode = "decrypt"
            ok = True
        except Exception:
            output = "Invalid base64 string"
            mode = "decrypt"
            ok = False
    else:
        output = base64.b64encode(raw_input.encode()).decode()
        mode = "encrypt"
        ok = True

    report = {
        "tool": TOOL_NAME,
        "input_received": raw_input,
        "timestamp": str(datetime.now()),
        "risk_level": "N/A",
        "main_finding": f"Operation {mode} was successful." if ok else "Operation failed.",
        "output": output
    }
    print(json.dumps(report, indent=4))