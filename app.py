from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename 
from datetime import datetime
from functools import wraps
from flask import abort
from flask_mail import Mail, Message
from random import randint
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
app.config['MAIL_USERNAME'] = 'Aicybershield.verify@gmail.com'  # Your Project Email
app.config['MAIL_PASSWORD'] = 'egku qsai lulg ugdu'             # Your App Password
mail = Mail(app)

# --- FILE UPLOAD CONFIGURATION ---
UPLOAD_FOLDER = 'uploads/' 
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov', 'webm', 'tiff'} 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 128 * 1024 * 1024 # 128MB max upload

# SECURITY CRITICAL: CHANGE THIS KEY! 
app.config['SECRET_KEY'] = 'your_long_and_complex_secret_key_1234567890'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' 
login_manager.login_message_category = "info" 

# --- DATABASE MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')
    reports = db.relationship('ScanReport', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_id(self):
        return str(self.id)

class ScanReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tool_name = db.Column(db.String(50), nullable=False)
    input_data_summary = db.Column(db.Text, nullable=False)
    risk_level = db.Column(db.String(20), nullable=True) 
    main_finding = db.Column(db.String(255), nullable=True)
    report_data = db.Column(db.Text, nullable=False) 
    scan_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- FILE UPLOAD HELPER ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- FLASK-LOGIN USER LOADER ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user, remember=True)
            return redirect(url_for('dashboard')) 
        else:
            error_message = 'Invalid email or password.'
            return render_template('login.html', error=error_message)
    return render_template('login.html')

# --- 1. REGISTRATION ROUTE (Step 1: Send OTP) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error="Username already exists.")

        # Generate 6-digit OTP
        otp = randint(100000, 999999)

        # Send Email
        try:
            msg = Message('Verify Your Account - AI CyberShield', 
                          sender=app.config['MAIL_USERNAME'], 
                          recipients=[email])
            msg.body = f"Hello {username},\n\nWelcome to AI CyberShield Matrix!\n\nYour OTP for registration is: {otp}\n\nPlease enter this code to complete your signup.\n\nRegards,\nAI CyberShield Team"
            mail.send(msg)
        except Exception as e:
            # If email fails, show error on page
            return render_template('register.html', error=f"Email sending failed: {str(e)}")

        # Store data in Session (Temporary storage until verified)
        session['temp_user'] = {
            'username': username,
            'email': email,
            # FIXED: Removed method='sha256' to prevent ValueError in newer Flask versions
            'password': generate_password_hash(password), 
            'otp': otp
        }

        return redirect(url_for('verify_otp'))

    return render_template('register.html')


# --- 2. OTP VERIFICATION ROUTE (Step 2: Save to DB) ---
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    # Security: If no registration data is in session, kick them back to register
    if 'temp_user' not in session:
        return redirect(url_for('register'))

    if request.method == 'POST':
        # Get the OTP from the form safely
        user_otp = request.form.get('otp')
        
        # DEBUGGING: Print what was received to your terminal
        print(f"DEBUG: User entered OTP: '{user_otp}'")

        # Check 1: Did they enter nothing?
        if not user_otp:
            return render_template('otp_verify.html', error="Please enter the OTP.")

        stored_data = session['temp_user']

        try:
            # Check 2: Convert to integer and compare
            # .strip() removes accidental spaces like " 123456 "
            if int(user_otp.strip()) == int(stored_data['otp']):
                
                # --- SUCCESS: SAVE TO DB ---
                new_user = User(
                    username=stored_data['username'], 
                    email=stored_data['email'], 
                    password_hash=stored_data['password'] # Already hashed
                )
                db.session.add(new_user)
                db.session.commit()
                
                # Clear session and login
                session.pop('temp_user', None)
                return redirect(url_for('login'))
            
            else:
                return render_template('otp_verify.html', error="Wrong Code. Please check your email again.")

        except ValueError:
            # This catches "abc", symbols, or weird formats
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
    all_reports = ScanReport.query.order_by(ScanReport.scan_date.desc()).all()
    all_users = User.query.all()
    return render_template('admin_monitor.html', reports=all_reports, users=all_users)

@app.route('/admin/promote/<int:user_id>')
@login_required
@admin_required
def promote_user(user_id):
    user = User.query.get_or_404(user_id)
    user.role = 'admin'
    db.session.commit()
    return redirect(url_for('admin_monitor'))

@app.route('/admin/delete_user/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return "Error: You cannot delete your own admin account.", 400
    
    ScanReport.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
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
    reports = ScanReport.query.filter_by(user_id=current_user.id).order_by(ScanReport.scan_date.desc()).all()
    return render_template('history.html', reports=reports)

@app.route('/report/<int:report_id>')
@login_required
def view_report(report_id):
    report = ScanReport.query.filter_by(id=report_id, user_id=current_user.id).first_or_404()
    try:
        report.report_data_json = json.loads(report.report_data) 
    except json.JSONDecodeError:
        report.report_data_json = {"error": "Corrupt report data."}
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
            command_list,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=120, 
            check=True
        )
        return {
            "ok": True,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
            "returncode": completed.returncode
        }
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.strip() or e.stdout.strip() or 'Unknown backend error. Check stdout/stderr for clues.'
        return {"ok": False, "error": f"Tool failed: {error_output}", "raw_stderr": e.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Tool timed out after 120s. Try a smaller file."}
    except FileNotFoundError:
        return {"ok": False, "error": "Backend script or Python interpreter not found. Check virtual environment path."}
    except Exception as e:
        logging.error(f"Error running tool: {e}")
        return {"ok": False, "error": f"OS Error: {str(e)}"}


# Tool page routes (dynamically generated)
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

# Define tool mappings for external scripts
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
        
        # --- LOGIC FOR EXTERNAL SCRIPT TOOLS ---
        if folder and folder != 'internal': 
            backend_base = os.path.join(os.path.dirname(__file__), 'backend')
            PYTHON_EXECUTABLE = 'python' 
            cwd = os.path.join(backend_base, folder)
            parts = shlex.split(command) 
            
            command_list = [PYTHON_EXECUTABLE] + parts[1:]
            command_list.append(absolute_filepath) # Pass the absolute path
            
            result_dict = run_tool(command_list, cwd=cwd)

            # Cleanup
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

        # --- DATABASE PERSISTENCE ---
        if final_report_json and final_report_json.get('ok') and current_user.is_authenticated:
            try:
                report_data_str = json.dumps(final_report_json, default=lambda o: float(o) if isinstance(o, (np.float32, np.float64, np.int32, np.int64)) else o.__dict__)
                new_report = ScanReport(
                    user_id=current_user.id,
                    tool_name=final_report_json.get('tool', tool),
                    input_data_summary=f"File: {filename}",
                    risk_level=final_report_json.get('risk_level', 'N/A'),
                    main_finding=final_report_json.get('main_finding', 'Analysis saved, finding unavailable.'),
                    report_data=report_data_str
                )
                db.session.add(new_report)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
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
    
    # --- Execute Tool (Internal or External) ---
    if folder == 'internal':
        # --- Internal logic for Password, BugHunter, Encryptor/Hasher ---
        if command == 'password':
            # --- START PASSWORD ANALYZER LOGIC ---
            if not user_input:
                final_report_json = {
                    "tool": "Password Analyzer (Rule)", 
                    "ok": False, 
                    "risk_level": "ERROR", 
                    "main_finding": "Input password cannot be empty.",
                    "confidence_score": 0.0,
                    "input_received": user_input,
                }
            else:
                score = 0
                features = {}
                
                # Rule 1: Length >= 8
                if len(user_input) >= 8: 
                    score += 1
                    features['length_check'] = 'PASS'
                else: features['length_check'] = 'FAIL'

                # Rule 2: Uppercase
                if re.search(r'[A-Z]', user_input): 
                    score += 1
                    features['uppercase_check'] = 'PASS'
                else: features['uppercase_check'] = 'FAIL'
                
                # Rule 3: Digits
                if re.search(r'[0-9]', user_input): 
                    score += 1
                    features['digit_check'] = 'PASS'
                else: features['digit_check'] = 'FAIL'

                # Rule 4: Special Characters
                if re.search(r'[^A-Za-z0-9]', user_input): 
                    score += 1
                    features['special_char_check'] = 'PASS'
                else: features['special_char_check'] = 'FAIL'

                strength_levels = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
                strength = strength_levels[score]
                
                confidence = float(score / 4.0) 
                
                final_report_json = {
                    "tool": "Password Analyzer (Rule)", 
                    "ok": True, 
                    "risk_level": strength, 
                    "tool_prediction": strength,
                    "main_finding": f"Strength assessed as {strength} based on 4 security rules.",
                    "confidence_score": confidence,
                    "input_received": user_input,
                    "advanced_report_details": {
                        "features_analyzed": features
                    }
                }
            # --- END PASSWORD ANALYZER LOGIC ---

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
            
            risk = "N/A"
            main_finding = f"Operation '{action}' was successful." if ok else f"Operation '{action}' failed."
            final_report_json = {"tool": "Text Encryptor/Hasher", "mode": action, "output": output, "ok": ok, "risk_level": risk, "main_finding": main_finding}
        
        if final_report_json and not final_report_json.get('ok'):
             return jsonify(final_report_json), 400
        
    elif folder and command:
        PYTHON_EXECUTABLE = 'python' 
        cwd = os.path.join(backend_base, folder)
        parts = shlex.split(command) 
        command_list = [PYTHON_EXECUTABLE] + parts[1:]
        
        if user_input:
            quoted_input = shlex.quote(user_input)
            command_list.append(quoted_input)
            
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

    # --- Database Persistence (Logging) ---
    if final_report_json and final_report_json.get('ok') and current_user.is_authenticated:
        try:
            report_data_str = json.dumps(final_report_json, default=lambda o: float(o) if isinstance(o, (np.float32, np.float64, np.int32, np.int64)) else o.__dict__)
            new_report = ScanReport(
                user_id=current_user.id,
                tool_name=final_report_json.get('tool', tool),
                input_data_summary=user_input[:100] if user_input else "N/A",
                risk_level=final_report_json.get('risk_level', 'N/A'),
                main_finding=final_report_json.get('main_finding', 'Analysis saved, finding unavailable.'),
                report_data=report_data_str
            )
            db.session.add(new_report)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.error(f"FATAL DB LOGGING ERROR for tool {tool}: {e}")

    return jsonify(final_report_json)


# --- RUN BLOCK ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
        
    # host='0.0.0.0' is the key to multi-device access
    app.run(host='0.0.0.0', port=5000, debug=True)