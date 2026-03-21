import sys
import json
import os
import pickle
import random
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

# --- CONFIGURATION ---
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_PATH, 'darkweb_model.pkl')
VEC_PATH = os.path.join(BASE_PATH, 'vectorizer.pkl')

# --- 1. TRAINING LOGIC (Auto-Runs if model is missing) ---
def train_and_save_model():
    # Synthetic Dataset (1 = Dark Web/Threat, 0 = Safe)
    data = [
        ("buying credit card dumps fullz", 1), ("selling hacked database access", 1),
        ("fresh rdp access admin rights", 1), ("passports and id cards anonymous", 1),
        ("sql injection tools download", 1), ("bitcoin laundering service mixer", 1),
        ("bank logs for sale chase", 1), ("ssn dob fullz info usa", 1),
        ("how to bake a cake", 0), ("weather forecast london", 0),
        ("best restaurants nyc", 0), ("python programming tutorial", 0),
        ("contact support password reset", 0), ("my email is test@gmail.com", 0)
    ]
    
    df = pd.DataFrame(data, columns=['text', 'label'])
    tfidf = TfidfVectorizer(stop_words='english', lowercase=True)
    X = tfidf.fit_transform(df['text'])
    
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, df['label'])
    
    with open(MODEL_PATH, 'wb') as f: pickle.dump(model, f)
    with open(VEC_PATH, 'wb') as f: pickle.dump(tfidf, f)
    
    return model, tfidf

# --- 2. LOAD MODEL ---
def load_model():
    try:
        if not os.path.exists(MODEL_PATH) or not os.path.exists(VEC_PATH):
            return train_and_save_model() # Auto-train if missing
            
        with open(MODEL_PATH, 'rb') as f: model = pickle.load(f)
        with open(VEC_PATH, 'rb') as f: vectorizer = pickle.load(f)
        return model, vectorizer
    except Exception:
        return train_and_save_model() # Fallback to retrain if corrupt

# --- 3. SIMULATED DATABASE ---
def check_breach_db(query):
    query = query.lower().strip()
    simulated_breaches = {
        "admin@example.com": ["Adobe Leak 2013", "LinkedIn Scrape"],
        "user@test.com": ["Collection #1"],
        "varun@gmail.com": ["Domino's Leak", "BigBasket Breach"],
        "test@demo.com": ["000Webhost Dump"]
    }
    return simulated_breaches.get(query, [])

# --- 4. MAIN ANALYSIS ---
def scan_dark_web(input_text):
    if not input_text:
        return {"ok": False, "error": "Empty input"}

    model, vectorizer = load_model()
    
    # Check Database
    breaches = check_breach_db(input_text)
    
    # Check AI Context
    try:
        vectorized_input = vectorizer.transform([input_text])
        prediction = model.predict(vectorized_input)[0]
        prob = model.predict_proba(vectorized_input)[0][1]
    except:
        prediction = 0
        prob = 0.0

    # Determine Risk
    risk_level = "Safe"
    main_finding = "No significant exposure found."
    
    if breaches:
        risk_level = "CRITICAL"
        main_finding = f"Identity found in {len(breaches)} known breaches."
    elif prediction == 1 or prob > 0.65:
        risk_level = "High"
        main_finding = "Input matches illicit Dark Web marketplace patterns."
    
    return {
        "tool": "Dark Web Checker",
        "ok": True,
        "risk_level": risk_level,
        "main_finding": main_finding,
        "data": {
            "ai_threat_score": f"{prob*100:.1f}%",
            "context_classification": "Illicit" if prediction == 1 else "Safe",
            "breaches_found": breaches
        }
    }

if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            user_input = " ".join(sys.argv[1:])
            print(json.dumps(scan_dark_web(user_input)))
        else:
            print(json.dumps({"ok": False, "error": "No input provided"}))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))