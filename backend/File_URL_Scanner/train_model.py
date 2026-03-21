import sys
import os
from joblib import dump
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.metrics import classification_report
import pandas as pd

# --- CONFIGURATION ---
TOOL_NAME = "AI File & URL Scanner"
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_files')
MODEL_SAVE_PATH = os.path.join(MODEL_DIR, 'url_scanner_pipeline.joblib')

os.makedirs(MODEL_DIR, exist_ok=True)

print(f"--- Starting {TOOL_NAME} Model Training (NLP Classifier) ---")

# --- SIMULATED DATA ---
# Training data: text features and corresponding labels
data = {
    'text': [
        "https://google.com/search?q=safe", # Clean
        "https://mybank.com/login", # Clean
        "https://free-money-now.xyz/login.php", # Suspicious
        "d41d8c... known zero byte file", # Malicious
        "http://click-here.net/verify-account", # Suspicious
        "URL contains known malware distribution domain", # Malicious
        "The file hash is clean and digitally signed by Microsoft", # Clean
        "The URL is associated with a phishing campaign", # Malicious
        "https://app.slack.com/files", # Clean
        "shortened link from bitly that redirects to login", # Suspicious
    ],
    'label': ['Clean', 'Clean', 'Suspicious', 'Malicious', 'Suspicious', 'Malicious', 'Clean', 'Malicious', 'Clean', 'Suspicious']
}

df = pd.DataFrame(data)

# --- Training Pipeline ---
# Use a simple pipeline: TF-IDF for vectorization and Naive Bayes for classification
model_pipeline = make_pipeline(TfidfVectorizer(), MultinomialNB())

X_train, X_test, y_train, y_test = train_test_split(
    df['text'], df['label'], test_size=0.3, random_state=42
)

print("Training Naive Bayes Classifier...")
model_pipeline.fit(X_train, y_train)

# Evaluation (optional, but good practice)
y_pred = model_pipeline.predict(X_test)
print("\nEvaluation Report:")
print(classification_report(y_test, y_pred, zero_division=0))


# --- Persistence ---
try:
    dump(model_pipeline, MODEL_SAVE_PATH)
    print(f"\nSUCCESS: NLP Classification pipeline saved to {MODEL_DIR}")
    
except Exception as e:
    print(f"FATAL ERROR: Could not save model file. Error: {e}")
    sys.exit(1)

print("\n--- Training Process Finished ---")