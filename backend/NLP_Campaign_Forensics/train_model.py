import sys
import os
import numpy as np
import pandas as pd
from joblib import dump
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans

# --- CONFIGURATION ---
TOOL_NAME = "Phishing Campaign Forensics"
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_files')
VECTORIZER_SAVE_PATH = os.path.join(MODEL_DIR, 'tfidf_vectorizer.joblib')
CLUSTER_MODEL_SAVE_PATH = os.path.join(MODEL_DIR, 'kmeans_campaign_model.joblib')

os.makedirs(MODEL_DIR, exist_ok=True)

print(f"--- Starting {TOOL_NAME} Model Training (NLP Topic Modeling Sim.) ---")

# --- SIMULATED PHISHING EMAIL DATA ---
# Goal: The model should cluster these into distinct campaigns.
phishing_emails = [
    "Your Amazon account is locked due to unusual activity. Click here to verify now.",  # Campaign A
    "We noticed an unrecognized login to your PayPal account. Please update your security details immediately.", # Campaign B
    "URGENT: Your parcel delivery is delayed. Confirm your address via this link to schedule redelivery.", # Campaign C
    "Access to your Amazon account is restricted. Re-enter your password on the following link.", # Campaign A
    "A large payment was sent from your PayPal account. If this was not you, click here to cancel.", # Campaign B
    "Your shipping details are missing. Click to resolve before 24 hours expires.", # Campaign C
    "Immediate action required to avoid PayPal account suspension. Follow the instructions.", # Campaign B
    "Verify your identity to unlock your Amazon services now.", # Campaign A
]

# 1. Vectorize Text Data (Convert words into numerical features)
vectorizer = TfidfVectorizer(stop_words='english')
X = vectorizer.fit_transform(phishing_emails)

# 2. Train Clustering Model (K=3 clusters/topics)
print("Training K-Means Clustering for Campaign Topics...")
kmeans = KMeans(n_clusters=3, random_state=42, n_init=10)
kmeans.fit(X)

# 3. Persistence
try:
    dump(vectorizer, VECTORIZER_SAVE_PATH)
    dump(kmeans, CLUSTER_MODEL_SAVE_PATH)
    
    print(f"\nSUCCESS: NLP Vectorizer and Clustering Model Saved to {MODEL_DIR}")
    
except Exception as e:
    print(f"FATAL ERROR: Could not save model files. Error: {e}")
    sys.exit(1)

print("\n--- Topic Modeling Finished ---")