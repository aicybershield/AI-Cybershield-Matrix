import sys
import pandas as pd
import os
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from joblib import dump

# --- CONFIGURATION ---
TOOL_NAME = "AI Fake Login Detector"
DATA_FILE_PATH = os.path.join(os.path.dirname(__file__), 'data', 'url_html_vulnerability_dataset.csv')
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_files')
MODEL_SAVE_PATH = os.path.join(MODEL_DIR, 'login_detector_model.joblib')
FEATURES_LIST_SAVE_PATH = os.path.join(MODEL_DIR, 'login_features.joblib')

TARGET_COLUMN = 'target_label' 

# Define all 10 feature columns explicitly based on the CSV inspection
FEATURE_COLUMNS = [
    'url_length', 'num_dots', 'has_ip_address', 'https', 'suspicious_words',
    'num_input_fields', 'num_password_fields', 'contains_keywords_secure',
    'has_inline_js', 'external_scripts'
]

# Ensure the model_files directory and data folder exist
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), 'data'), exist_ok=True)


print(f"--- Starting {TOOL_NAME} Model Training ---")

# --- Step 1: Data Acquisition and Loading ---
try:
    # NOTE: You must place url_html_vulnerability_dataset.csv inside backend/Fake_Login_Detector/data/
    df = pd.read_csv(DATA_FILE_PATH)
    print(f"Dataset loaded successfully. Rows: {len(df)}")
    
except FileNotFoundError:
    print(f"FATAL ERROR: Dataset not found at {DATA_FILE_PATH}. Please check the path.")
    sys.exit(1)

# --- Step 2: Preprocessing ---
print("Preparing numerical features for training...")

try:
    X_features = df[FEATURE_COLUMNS] # X uses the 10 numerical columns
    y_labels = df[TARGET_COLUMN]      # y is the target label (0 or 1)

    # Split Data: 80% training, 20% testing
    X_train, X_test, y_train, y_test = train_test_split(
        X_features, y_labels, test_size=0.2, random_state=42
    )

except KeyError as e:
    print(f"FATAL ERROR: Missing critical column {e}. Check FEATURE_COLUMNS list.")
    sys.exit(1)
except Exception as e:
    print(f"ERROR during preprocessing: {e}")
    sys.exit(1)


# --- Step 3: Model Selection and Training ---
print("Training RandomForestClassifier for fake login detection...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# --- Step 4: Evaluation ---
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"\nModel Accuracy on Test Set: {accuracy * 100:.2f}%")
print("Classification Report:")
print(classification_report(y_test, y_pred))

# --- Step 5: Persistence (Saving the Model Files) ---
try:
    dump(model, MODEL_SAVE_PATH)
    dump(FEATURE_COLUMNS, FEATURES_LIST_SAVE_PATH) # CRITICAL: Save the list of 10 feature names

    print(f"\nSUCCESS: Model and feature list saved to {MODEL_DIR}")
    
except Exception as e:
    print(f"FATAL ERROR: Could not save model files. Error: {e}")
    sys.exit(1)

print("\n--- Training Process Finished ---")