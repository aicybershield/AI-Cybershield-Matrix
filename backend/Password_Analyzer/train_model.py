import sys
import pandas as pd
import os
import numpy as np
import re
import math
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from joblib import dump

# --- CONFIGURATION ---
TOOL_NAME = "Password Analyzer"
DATA_FILE_PATH = os.path.join(os.path.dirname(__file__), 'data', 'password_dataset.csv')
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_files')
MODEL_SAVE_PATH = os.path.join(MODEL_DIR, 'password_model.joblib')
FEATURES_LIST_SAVE_PATH = os.path.join(MODEL_DIR, 'password_features.joblib')
TARGET_COLUMN = 'strength_score'
RAW_INPUT_COLUMN = 'password' 
# Exclude crack_time_seconds as it's correlated with the score and not needed for prediction
COLUMNS_TO_DROP = ['crack_time_seconds'] 

# Ensure the model_files directory exists before saving
os.makedirs(MODEL_DIR, exist_ok=True)

print(f"--- Starting {TOOL_NAME} Model Training ---")

# --- Step 1: Data Acquisition and Loading ---
try:
    df = pd.read_csv(DATA_FILE_PATH)
    print(f"Dataset loaded successfully. Rows: {len(df)}")
    
except FileNotFoundError:
    print(f"FATAL ERROR: Dataset not found at {DATA_FILE_PATH}. Please check the path.")
    sys.exit(1)

# --- Step 2: Feature Derivation and Preprocessing ---

# 1. Feature Engineering: Derive standard features from the raw password string
print("Deriving features from raw password column...")

# Length
df['length'] = df[RAW_INPUT_COLUMN].apply(len)
# Uppercase count
df['upper_count'] = df[RAW_INPUT_COLUMN].apply(lambda s: sum(1 for c in s if c.isupper()))
# Symbol count (assuming anything not alphanumeric is a symbol)
df['symbol_count'] = df[RAW_INPUT_COLUMN].apply(lambda s: sum(1 for c in s if not c.isalnum()))
# Digit count
df['digit_count'] = df[RAW_INPUT_COLUMN].apply(lambda s: sum(1 for c in s if c.isdigit()))

# 2. Define Final Features (X) and Target (y)
# The final features list combines the new derived features and the existing 'entropy'
FEATURE_COLUMNS = [
    'entropy', 'length', 'upper_count', 'symbol_count', 'digit_count'
]

X_features = df[FEATURE_COLUMNS] 
y_labels = df[TARGET_COLUMN] 

# 3. Split Data: 80% for training, 20% for testing
X_train, X_test, y_train, y_test = train_test_split(
    X_features, y_labels, test_size=0.2, random_state=42
)
print(f"Data split: Training samples={len(X_train)}, Testing samples={len(X_test)}")

# --- Step 3: Model Selection and Training ---
print("Training RandomForestClassifier for strength prediction...")
model = RandomForestClassifier(n_estimators=150, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# --- Step 4: Evaluation ---
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\nModel Accuracy on Test Set: {accuracy * 100:.2f}%")
print("Classification Report:")
print(classification_report(y_test, y_pred))

# --- Step 5: Persistence (Saving the Model Files) ---
try:
    # 1. Save the trained ML model
    dump(model, MODEL_SAVE_PATH)

    # 2. Save the list of feature column names (CRITICAL for main.py)
    dump(FEATURE_COLUMNS, FEATURES_LIST_SAVE_PATH)

    print(f"\nSUCCESS: Model and feature list saved to {MODEL_DIR}")
    
except Exception as e:
    print(f"FATAL ERROR: Could not save model files. Error: {e}")
    sys.exit(1)

print("\n--- Training Process Finished ---")