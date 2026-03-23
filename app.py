from flask import Flask, render_template, request, jsonify, redirect, url_for, session, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename 
from datetime import datetime
from functools import wraps
from flask_mail import Mail, Message
from random import randint
from pymongo import MongoClient
from bson.objectid import ObjectId
import subprocess
import os
import shlex
import re
import base64
import logging
import json 
import hashlib 
import numpy as np 

# Set logging level for visibility
logging.basicConfig(level=logging.INFO)

# --- CONFIGURATION & INITIALIZATION ---
app = Flask(__name__, template_folder='templates', static_folder='static')

# --- EMAIL CONFIGURATION ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'Aicybershield.verify@gmail.com'
app.config['MAIL_PASSWORD'] = 'egku qsai lulg ugdu'
mail = Mail(app)

# --- FILE UPLOAD CONFIGURATION ---
UPLOAD_FOLDER = 'uploads/' 
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov', 'webm', 'tiff'} 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 128 * 1024 * 1024 

# SECURITY CRITICAL: CHANGE THIS KEY LATER! 
app.config['SECRET_KEY'] = 'your_long_and_complex_secret_key_1234567890'

# --- MONGODB DATABASE CONFIGURATION ---
# Fetches your secure URL from Render, or falls back to localhost if running locally
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client["aicybershield_db"]
users_collection = db["users"]
reports_collection = db["reports"]

login_manager = LoginManager(app)
login_manager.login_view = 'login' 
login_manager.login_message_category = "info" 

# --- FLASK-LOGIN CUSTOM USER CLASS (Replaces SQLAlchemy Model) ---
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data.get('_id'))
        self.username = user_data.get('username')
        self.email = user_data.get('email')
        self.password_hash = user_data.get('password_hash')
        self.role = user_data.get('role', 'user')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def get_by_id(user_id):
        user_data = users_collection.find_one({"_id": ObjectId(user_id)})
        if user_data:
            return User(user_data)
        return None

# --- FILE UPLOAD HELPER ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- FLASK-LOGIN USER LOADER ---
@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

# --- AUTHENTICATION ROUTES ---
@app.route('/')
def welcome_gate():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        # Search MongoDB for the email
        user_data = users_collection.find_one({"email": request.form.get('email')})
        if user_data:
            user = User(user_data)
            if user.check_password(request.form.get('password')):
                login_user(user, remember=True)
                return redirect(url_for('dashboard')) 
        
        error_message = 'Invalid email or password.'
        return render_template('login.html', error=error_message)
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if user already exists in MongoDB
        existing_user = users_collection.find_one({"username": username})
        if existing_user:
            return render_template('register.html', error="Username already exists.")

        otp = randint(100000, 999999)

        try:
            msg = Message('Verify Your Account - AI CyberShield', 
                          sender=app.config['MAIL_USERNAME'], 
                          recipients=[email])
            msg.body = f"Hello {username},\n\nWelcome to AI CyberShield Matrix!\n\nYour OTP for registration is: {otp}\n\nPlease enter this code to complete your signup.\n\nRegards,\nAI CyberShield Team"
            mail.send(msg)
        except Exception as e:
            return render_template('register.html', error=f"Email sending failed: {str(e)}")

        session['temp_user'] = {
            'username': username,
            'email': email,
            'password': generate_password_hash(password), 
            'otp': otp
        }
        return redirect(url_for('verify_otp'))
    return render_template('register.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'temp_user' not in session:
        return redirect(url_for('register'))

    if request.method == 'POST':
        user_otp = request.form.get('otp')
        
        if not user_otp:
            return render_template('otp_verify.html', error="Please enter the OTP.")

        stored_data = session['temp_user']

        try:
            if int(user_otp.strip()) == int(stored_data['otp']):
                
                # --- SUCCESS: SAVE TO MONGODB ---
                users_collection.insert_one({
                    "username": stored_data['username'],
                    "email": stored_data['email'],
                    "password_hash": stored_data['password'],
                    "role": "user"
                })
                
                session.pop('temp_user', None)
                return redirect(url_for('login'))
            else:
                return render_template('otp_verify.html', error="Wrong Code. Please check your email again.")

        except ValueError:
            return render_template('otp_verify.html', error="Invalid format. Please enter numbers only.")

    return render_template('otp_verify.html')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return render_template('403.html'), 403 
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/monitor')
@login_required
@admin_required
def admin_monitor():
    # Fetch all reports and sort by date descending
    all_reports = list(reports_collection.find().sort("scan_date", -1))
    for r in all_reports:
        r['id'] = str(r['_id']) # Format ID for Jinja template
        author = users_collection.find_one({"_id": ObjectId(r['user_id'])})
        r['author'] = {'username': author['username'] if author else 'Unknown'}

    all_users = list(users_collection.find())
    for u in all_users:
        u['id'] = str(u['_id'])
        
    return render_template('admin_monitor.html', reports=all_reports, users=all_users)

@app.route('/admin/promote/<user_id>')
@login_required
@admin_required
def promote_user(user_id):
    users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": "admin"}})
    return redirect(url_for('admin_monitor'))

@app.route('/admin/delete_user/<user_id>')
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        return "Error: You cannot delete your own admin account.", 400
    
    # Delete user and their associated reports
    users_collection.delete_one({"_id": ObjectId(user_id)})
    reports_collection.delete_many({"user_id": user_id})
    return redirect(url_for('admin_monitor'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('ai_core_access', None)
    return redirect(url_for('welcome_gate'))

@app.route('/history')
@login_required
def history():
    reports = list(reports_collection.find({"user_id": current_user.id}).sort("scan_date", -1))
    for r in reports:
        r['id'] = str(r['_id'])
    return render_template('history.html', reports=reports)

@app.route('/report/<report_id>')
@login_required
def view_report(report_id):
    report = reports_collection.find_one({"_id": ObjectId(report_id), "user_id": current_user.id})
    if not report:
        abort(404)
        
    report['id'] = str(report['_id'])
    try:
        report['report_data_json'] = json.loads(report['report_data']) 
    except json.JSONDecodeError:
        report['report_data_json'] = {"error": "Corrupt report data."}
    return render_template('full_report_viewer.html', report=report) 

# --- CORE APP ROUTES ---
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html')

@app.route('/ai-core-doc')
@login_required
@admin_required
def ai_core_page():
    return render_template('ai-core.html')

# Helper function to run backend scripts
def run_tool(command_list, cwd=None):
    try:
        completed = subprocess.run(
            command_list, cwd=cwd, capture_output=True, text=True, timeout=120, check=True
        )
        return {"ok": True, "stdout": completed.stdout.strip(), "stderr": completed.stderr.strip(), "returncode": completed.returncode}
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.strip() or e.stdout.strip() or 'Unknown backend error.'
        return {"ok": False, "error": f"Tool failed: {error_output}", "raw_stderr": e.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Tool timed out after 120s. Try a smaller file."}
    except FileNotFoundError:
        return {"ok": False, "error": "Backend script or Python interpreter not found."}
    except Exception as e:
        return {"ok": False, "error": f"OS Error: {str(e)}"}

pages = {
    'phishing-detector': 'phishing-detector.html', 
    'dark-web-checker': 'dark-web-checker.html',
    'password-analyzer': 'password-analyzer.html', 
    'fake-login-detector': 'fake-login-detector.html',
    'bughunter': 'bughunter.html',
    'file-url-scanner': 'file-url-scanner.html', 
    'text-encryptor': 'text-encryptor.html',
    'network-analyzer': 'network-analyzer.html', 
    'ueba-analyzer': 'ueba-analyzer.html', 
    'forensics-nlp': 'forensics-nlp.html', 
    'deepfake-analyzer': 'deepfake-analyzer.html', 
    'adversarial-attack-shield': 'adversarial-attack-shield.html', 
    'data-poisoning-monitor': 'data-poisoning-monitor.html',
    'metadata-extractor': 'metadata-extractor.html', 
}

def make_tool_route(template_name):
    @login_required
    def route():
        return render_template(template_name)
    return route

for route, template in pages.items():
    app.add_url_rule(f'/{route}', view_func=make_tool_route(template), endpoint=route)

tool_map = {
    'phishing-detector': ('Phishing_Detector_Tool', 'python main.py'),
    'dark-web-checker': ('Dark_Web_Checker', 'python main.py'),
    'password-analyzer': ('internal', 'password'), 
    'fake-login-detector': ('Fake_Login_Detector', 'python main.py'),
    'bughunter': ('BugHunter', 'python main.py'), 
    'file-url-scanner': ('File_URL_Scanner', 'python main.py'), 
    'text-encryptor': ('internal', 'encryptor'),
    'network-analyzer': ('AI_Network_Analyzer', 'python main.py'),
    'ueba-analyzer': ('UEBA_Behavioral_Analytics', 'python main.py'), 
    'forensics-nlp': ('NLP_Campaign_Forensics', 'python main.py'),
    'deepfake-analyzer': ('Deepfake_Analyzer', 'python main.py'),
    'adversarial-attack-shield': ('Adversarial_Attack_Shield', 'python main.py'),
    'data-poisoning-monitor': ('Data_Poisoning_Monitor', 'python main.py'),
    'metadata-extractor': ('Metadata_Extractor', 'python main.py'),
}

# --- 1. API ROUTE FOR FILE UPLOADS ---
@app.route('/api/upload_file/<tool>', methods=['POST'])
@login_required
def api_file_upload(tool):
    if 'file' not in request.files:
        return jsonify({"ok": False, "error": "No file part in the request."}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"ok": False, "error": "No file selected for uploading."}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        try:
            file.save(filepath)
        except Exception as e:
            return jsonify({"ok": False, "error": f"Failed to save file: {str(e)}"}), 500
        
        absolute_filepath = os.path.abspath(filepath)
        folder, command = tool_map.get(tool, (None, None))
        final_report_json = None
        
        if folder and folder != 'internal': 
            backend_base = os.path.join(os.path.dirname(__file__), 'backend')
            PYTHON_EXECUTABLE = 'python' 
            cwd = os.path.join(backend_base, folder)
            parts = shlex.split(command) 
            
            command_list = [PYTHON_EXECUTABLE] + parts[1:]
            command_list.append(absolute_filepath) 
            
            result_dict = run_tool(command_list, cwd=cwd)

            try:
                os.remove(absolute_filepath) 
            except OSError as e:
                logging.error(f"Error deleting file {absolute_filepath}: {e}")

            if result_dict.get('ok') and result_dict.get('stdout'):
                try:
                    final_report_json = json.loads(result_dict['stdout'])
                except json.JSONDecodeError:
                    return jsonify({"ok": False, "error": "Backend script returned invalid JSON.", "raw_output": result_dict.get('stdout')}), 500
            else:
                 return jsonify({"ok": False, "error": result_dict.get('error', 'Execution failed.'), "raw_stderr": result_dict.get('raw_stderr', '')}), 500
        
        elif folder == 'internal':
             return jsonify({"ok": False, "error": "This file tool is not configured correctly."}), 400

        # --- DATABASE PERSISTENCE FOR FILES ---
        if final_report_json and final_report_json.get('ok') and current_user.is_authenticated:
            try:
                report_data_str = json.dumps(final_report_json, default=lambda o: float(o) if isinstance(o, (np.float32, np.float64, np.int32, np.int64)) else o.__dict__)
                reports_collection.insert_one({
                    "user_id": current_user.id,
                    "tool_name": final_report_json.get('tool', tool),
                    "input_data_summary": f"File: {filename}",
                    "risk_level": final_report_json.get('risk_level', 'N/A'),
                    "main_finding": final_report_json.get('main_finding', 'Analysis saved, finding unavailable.'),
                    "report_data": report_data_str,
                    "scan_date": datetime.utcnow()
                })
            except Exception as e:
                logging.error(f"FATAL DB LOGGING ERROR for file tool {tool}: {e}")

        if final_report_json:
            return jsonify(final_report_json)
        else:
             return jsonify({"ok": False, "error": "Unknown processing error."}), 500

    return jsonify({"ok": False, "error": "File type not allowed."}), 400

# --- 2. EXISTING API ROUTE FOR TEXT/JSON INPUTS ---
@app.post('/api/<tool>')
@login_required
def api_tool(tool):
    data = request.get_json() or {}
    user_input = data.get('input', '')
    user_mode = data.get('mode', '') 
    
    final_report_json = None
    folder, command = tool_map.get(tool, (None, None))
    backend_base = os.path.join(os.path.dirname(__file__), 'backend')
    
    if folder == 'internal':
        if command == 'password':
            if not user_input:
                final_report_json = {
                    "tool": "Password Analyzer (Rule)", "ok": False, "risk_level": "ERROR", 
                    "main_finding": "Input password cannot be empty.", "confidence_score": 0.0, "input_received": user_input
                }
            else:
                score = 0
                features = {}
                if len(user_input) >= 8: score += 1; features['length_check'] = 'PASS'
                else: features['length_check'] = 'FAIL'
                if re.search(r'[A-Z]', user_input): score += 1; features['uppercase_check'] = 'PASS'
                else: features['uppercase_check'] = 'FAIL'
                if re.search(r'[0-9]', user_input): score += 1; features['digit_check'] = 'PASS'
                else: features['digit_check'] = 'FAIL'
                if re.search(r'[^A-Za-z0-9]', user_input): score += 1; features['special_char_check'] = 'PASS'
                else: features['special_char_check'] = 'FAIL'

                strength_levels = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
                strength = strength_levels[score]
                
                final_report_json = {
                    "tool": "Password Analyzer (Rule)", "ok": True, "risk_level": strength, 
                    "tool_prediction": strength, "main_finding": f"Strength assessed as {strength} based on 4 security rules.",
                    "confidence_score": float(score / 4.0), "input_received": user_input,
                    "advanced_report_details": {"features_analyzed": features}
                }

        elif command == 'bughunter':
            issues = []
            if "eval(" in user_input: issues.append("Use of eval() is dangerous.")
            if "os.system" in user_input: issues.append("os.system call found — potential command injection risk.")
            if re.search(r'password\s*=\s*["\'].*["\']', user_input): issues.append("Hardcoded password detected.")
            risk = "Suspicious" if issues else "Clean"
            final_report_json = {"tool": "BugHunter", "issues_found": issues or ["No critical issues found."], "ok": True, "risk_level": risk, "main_finding": f"{len(issues)} critical issue(s) found."}

        elif command == 'encryptor':
            mode = user_mode 
            ok = False
            output = ""
            action = "Error"
            try:
                data_bytes = user_input.encode('utf-8')
                if mode == 'base64_encode': output = base64.b64encode(data_bytes).decode('utf-8'); action = "Encode (Base64)"; ok = True
                elif mode == 'base64_decode': output = base64.b64decode(data_bytes).decode('utf-8'); action = "Decode (Base64)"; ok = True
                elif mode == 'sha256_hash': output = hashlib.sha256(data_bytes).hexdigest(); action = "Hash (SHA-256)"; ok = True
                else: action = "Invalid Mode Selected"; output = "Please select a valid operation mode from the list."; ok = False
            except Exception as e:
                output = f"Error: {str(e)}"; ok = False
            
            final_report_json = {"tool": "Text Encryptor/Hasher", "mode": action, "output": output, "ok": ok, "risk_level": "N/A", "main_finding": f"Operation '{action}' was successful." if ok else f"Operation '{action}' failed."}
        
        if final_report_json and not final_report_json.get('ok'):
             return jsonify(final_report_json), 400
        
    elif folder and command:
        PYTHON_EXECUTABLE = 'python' 
        cwd = os.path.join(backend_base, folder)
        parts = shlex.split(command) 
        command_list = [PYTHON_EXECUTABLE] + parts[1:]
        
        if user_input:
            command_list.append(shlex.quote(user_input))
            
        result_dict = run_tool(command_list, cwd=cwd)

        if result_dict.get('ok') and result_dict.get('stdout'):
            try:
                final_report_json = json.loads(result_dict['stdout'])
            except json.JSONDecodeError:
                return jsonify({"ok": False, "error": "Backend script returned invalid JSON.", "raw_output": result_dict.get('stdout')}), 500
        else:
             return jsonify({"ok": False, "error": result_dict.get('error', 'Execution failed.'), "raw_stderr": result_dict.get('raw_stderr', '')}), 500
    else:
        final_report_json = {"ok": True, "tool": tool, "main_finding": "No server-side processing required for this tool."}

    # --- DATABASE PERSISTENCE FOR TEXT INPUTS ---
    if final_report_json and final_report_json.get('ok') and current_user.is_authenticated:
        try:
            report_data_str = json.dumps(final_report_json, default=lambda o: float(o) if isinstance(o, (np.float32, np.float64, np.int32, np.int64)) else o.__dict__)
            reports_collection.insert_one({
                "user_id": current_user.id,
                "tool_name": final_report_json.get('tool', tool),
                "input_data_summary": user_input[:100] if user_input else "N/A",
                "risk_level": final_report_json.get('risk_level', 'N/A'),
                "main_finding": final_report_json.get('main_finding', 'Analysis saved, finding unavailable.'),
                "report_data": report_data_str,
                "scan_date": datetime.utcnow()
            })
        except Exception as e:
            logging.error(f"FATAL DB LOGGING ERROR for tool {tool}: {e}")

    return jsonify(final_report_json)

# --- RUN BLOCK ---
if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
        
    app.run(host='0.0.0.0', port=5000, debug=True)