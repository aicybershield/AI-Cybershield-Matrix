import sys
import pandas as pd
import os
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from joblib import dump

# --- CONFIGURATION ---
TOOL_NAME = "AI BugHunter"
DATA_FILE_PATH = os.path.join(os.path.dirname(__file__), 'data', 'code_vulnerability_dataset.csv')
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_files')
MODEL_SAVE_PATH = os.path.join(MODEL_DIR, 'bughunter_model.joblib')
VECTORIZER_SAVE_PATH = os.path.join(MODEL_DIR, 'bughunter_vectorizer.joblib')
TARGET_COLUMN = 'target_label' 
RAW_CODE_COLUMN = 'code_snippet' 

# Ensure the model_files directory exists
os.makedirs(MODEL_DIR, exist_ok=True)

print(f"--- Starting {TOOL_NAME} Model Training (NLP Classification) ---")

# --- Step 1: Data Acquisition and Loading ---
try:
    # NOTE: You must place code_vulnerability_dataset.csv inside backend/BugHunter/data/
    df = pd.read_csv(DATA_FILE_PATH)
    print(f"Dataset loaded successfully. Rows: {len(df)}")
    
except FileNotFoundError:
    print(f"FATAL ERROR: Dataset not found at {DATA_FILE_PATH}. Please check the path.")
    sys.exit(1)

# --- Step 2: Preprocessing (Code Tokenization) ---
print("Tokenizing code snippets using TF-IDF...")

X_raw = df[RAW_CODE_COLUMN]
y_labels = df[TARGET_COLUMN]

# TF-IDF Vectorizer converts code text into numerical features
# Using a custom token pattern to treat words/identifiers as tokens
vectorizer = TfidfVectorizer(max_features=2000, token_pattern=r'\b\w+\b', stop_words=None) 
X_features = vectorizer.fit_transform(X_raw)

# Split Data: 80% training, 20% testing
X_train, X_test, y_train, y_test = train_test_split(
    X_features, y_labels, test_size=0.2, random_state=42
)

# --- Step 3: Model Selection and Training ---
print("Training RandomForestClassifier...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# --- Step 4: Evaluation (Testing) ---
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f"\nModel Accuracy on Test Set: {accuracy * 100:.2f}%")
print("Classification Report:")
print(classification_report(y_test, y_pred))

# --- Step 5: Persistence (Saving the Model Files) ---
try:
    dump(model, MODEL_SAVE_PATH)
    dump(vectorizer, VECTORIZER_SAVE_PATH) 

    print(f"\nSUCCESS: Model and vectorizer saved to {MODEL_DIR}")
    
except Exception as e:
    print(f"FATAL ERROR: Could not save model files. Error: {e}")
    sys.exit(1)

print("\n--- Training Process Finished ---")