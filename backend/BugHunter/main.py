import sys
import json
import re

def scan_code(data):
    # 1. Parse Inputs
    code = data.get('code', '')
    language = data.get('language', 'python')
    checks = data.get('checks', {})
    
    issues = []
    
    # --- CHECK 1: Unsafe Functions (eval/exec) ---
    if checks.get('unsafe'):
        if language == 'python':
            if 'eval(' in code: issues.append("Python: Use of 'eval()' detected (High Risk).")
            if 'exec(' in code: issues.append("Python: Use of 'exec()' detected (High Risk).")
            if 'pickle.load' in code: issues.append("Python: Insecure deserialization 'pickle.load' detected.")
        elif language == 'javascript':
            if 'eval(' in code: issues.append("JS: Use of 'eval()' is dangerous.")
            if 'document.write(' in code: issues.append("JS: 'document.write' can lead to XSS.")
        elif language == 'php':
            if 'shell_exec' in code: issues.append("PHP: 'shell_exec' allows command execution.")

    # --- CHECK 2: Injection Patterns (SQL/Command) ---
    if checks.get('injection'):
        # Generic SQLi pattern (concatenation)
        if re.search(r'SELECT.*WHERE.*=.*[\'"]\s*\+', code, re.IGNORECASE):
            issues.append("SQL Injection: Unsafe string concatenation in SQL query.")
        if language == 'python' and 'os.system(' in code:
            issues.append("Cmd Injection: 'os.system' called. Use 'subprocess' with lists instead.")

    # --- CHECK 3: Hardcoded Secrets ---
    if checks.get('secrets'):
        # Regex for generic API keys or passwords
        if re.search(r'(api_key|password|secret)\s*=\s*[\'"][A-Za-z0-9]{8,}[\'"]', code, re.IGNORECASE):
            issues.append("Hardcoded Secret: Potential password or API key found in source.")
        if 'BEGIN PRIVATE KEY' in code:
            issues.append("Cryptography: Private Key block found in code.")

    # --- CHECK 4: Debug Leftovers ---
    if checks.get('debug'):
        if 'print(' in code or 'console.log(' in code:
            issues.append("Quality: Debug print statements found (Info Leak Risk).")

    # --- RESULTS ---
    count = len(issues)
    
    if count > 0:
        risk = "High" if "High Risk" in str(issues) else "Medium"
        finding = f"Audit Failed: {count} issues found."
    else:
        risk = "Low"
        finding = "Audit Passed: Clean code snippet."

    return {
        "ok": True,
        "tool": "BugHunter",
        "risk_level": risk,
        "main_finding": finding,
        "data": {
            "issues": issues,
            "scan_meta": f"Scanned {len(code.splitlines())} lines of {language}."
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
                # Fallback for raw code paste
                parsed_data = {"code": raw_arg, "language": "python", "checks": {"unsafe": True, "secrets": True}}

            result = scan_code(parsed_data)
            print(json.dumps(result))
        else:
            print(json.dumps({"ok": False, "error": "No input provided"}))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))