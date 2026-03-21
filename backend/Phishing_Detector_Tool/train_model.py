import sys
import pandas as pd
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from joblib import dump, load 

# --- CONFIGURATION ---
# IMPORTANT: This script uses the numerical features already extracted in your CSV.
DATA_FILE_PATH = os.path.join(os.path.dirname(__file__), 'data', 'Phishing_Legitimate_full.csv')
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_files')
MODEL_SAVE_PATH = os.path.join(MODEL_DIR, 'phishing_model.joblib')
FEATURES_LIST_SAVE_PATH = os.path.join(MODEL_DIR, 'phishing_features.joblib') # To save column names
TARGET_COLUMN = 'CLASS_LABEL' 
ID_COLUMN = 'id' # Column to exclude

# Ensure the model_files directory exists before saving
os.makedirs(MODEL_DIR, exist_ok=True)

print("--- Starting Phishing Detector Model Training ---")

# --- Step 1: Data Acquisition and Loading ---
try:
    df = pd.read_csv(DATA_FILE_PATH)
    print(f"Dataset loaded successfully. Rows: {len(df)}")
    print(f"Columns: {list(df.columns)}")
    
except FileNotFoundError:
    print(f"FATAL ERROR: Dataset not found at {DATA_FILE_PATH}. Please check the path and file name.")
    sys.exit(1)
except KeyError as e:
    print(f"FATAL ERROR: Missing required column {e} in the CSV file.")
    sys.exit(1)

# --- Step 2: Preprocessing and Feature Engineering ---
try:
    # 1. Define Feature Columns (X) by excluding ID and the target label
    FEATURE_COLUMNS = [col for col in df.columns if col not in [ID_COLUMN, TARGET_COLUMN]]
    
    X_features = df[FEATURE_COLUMNS]  # X is now your numerical feature DataFrame
    y_labels = df[TARGET_COLUMN]      # y is the target label

    # 2. Split Data: 80% for training, 20% for testing
    X_train, X_test, y_train, y_test = train_test_split(
        X_features, y_labels, test_size=0.2, random_state=42
    )
    print(f"Data split: Training samples={len(X_train)}, Testing samples={len(X_test)}")
    
except Exception as e:
    print(f"ERROR during preprocessing: {e}")
    sys.exit(1)

# --- Step 3: Model Selection and Training ---
print("Training Random Forest Classifier...")
# n_jobs=-1 uses all available processors for faster training
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# --- Step 4: Evaluation (Testing) ---
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print("\n--- Evaluation Results ---")
print(f"Model Accuracy on Test Set: {accuracy * 100:.2f}%")
print("Classification Report:")
print(classification_report(y_test, y_pred))

# --- Step 5: Persistence (Saving the Model Files) ---
try:
    # 1. Save the trained ML model
    dump(model, MODEL_SAVE_PATH)

    # 2. Save the list of feature column names (CRITICAL for main.py to maintain feature order)
    dump(FEATURE_COLUMNS, FEATURES_LIST_SAVE_PATH)

    print(f"\nSUCCESS: Model and feature list saved to {MODEL_DIR}")
    
except Exception as e:
    print(f"FATAL ERROR: Could not save model files. Error: {e}")
    sys.exit(1)

print("\n--- Training Process Finished ---")