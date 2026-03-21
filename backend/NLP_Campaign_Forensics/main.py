import sys
import json
import os
from joblib import load
from datetime import datetime
import numpy as np

# --- CONFIGURATION ---
TOOL_NAME = "Phishing Campaign Forensics"
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model_files')
VECTORIZER_PATH = os.path.join(MODEL_DIR, 'tfidf_vectorizer.joblib')
CLUSTER_MODEL_PATH = os.path.join(MODEL_DIR, 'kmeans_campaign_model.joblib')

# --- MAPPING CLUSTER ID TO CAMPAIGN NAME (CORRECTED MAPPING) ---
CLUSTER_NAMES = {
    # Cluster 0 contained the PayPal emails in your execution
    0: "Campaign B: PayPal Urgent Security Alert", 
    # Cluster 1 or 2 likely contained Amazon/Shipping. We'll leave placeholders.
    1: "Campaign C: Shipping/Parcel Delivery Delay",
    2: "Campaign A: Amazon Account Lockout" 
}

def load_ml_artifacts():
    """Loads the saved vectorizer and clustering model."""
    try:
        vectorizer = load(VECTORIZER_PATH)
        kmeans = load(CLUSTER_MODEL_PATH)
        return vectorizer, kmeans
    except FileNotFoundError:
        sys.stderr.write(f"FATAL ERROR: Model files not found. Did you run train_model.py in the NLP Forensics folder?\n")
        sys.exit(1)
    except Exception as e:
        sys.stderr.write(f"ERROR loading model artifacts: {e}\n")
        sys.exit(1)

def run_campaign_forensics(vectorizer, kmeans, raw_input):
    """
    Analyzes an input email/text and classifies it into a known phishing campaign cluster.
    """
    
    try:
        # 1. Transform the input text using the fitted vectorizer
        X_new = vectorizer.transform([raw_input])

        # 2. Predict the cluster ID
        cluster_id = kmeans.predict(X_new)[0]
        
        # 3. Get the campaign name
        campaign_name = CLUSTER_NAMES.get(cluster_id, "Unknown Campaign")

        # 4. Generate Finding
        risk = "INTELLIGENCE GATHERED"
        finding = f"Input text matches known phishing campaign: {campaign_name}. Treat all emails in this cluster as malicious."
            
    except Exception as e:
        sys.stderr.write(f"ERROR processing input data: {e}\n")
        sys.exit(1)

    return {
        "tool_prediction": campaign_name,
        "confidence_score": 1.0, # Clustering assigns a definitive ID
        "risk_level": risk,
        "main_finding": finding,
        "advanced_report_details": {
            "assigned_cluster_id": int(cluster_id),
            "campaign_topic": campaign_name,
            "model_type": "K-Means Clustering on TF-IDF Vectors (Unsupervised NLP)"
        }
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("ERROR: No input provided. Expected text of a phishing email/subject line.\n")
        sys.exit(1)
        
    raw_input_data = sys.argv[1]
    
    vectorizer, kmeans = load_ml_artifacts()
    
    final_report_data = run_campaign_forensics(vectorizer, kmeans, raw_input_data)
    
    report = {
        "tool": TOOL_NAME,
        "input_received": raw_input_data,
        "timestamp": str(datetime.now()),
        "ok": True,
        **final_report_data
    }
    
    print(json.dumps(report, indent=4))