import pandas as pd
import pickle
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

# --- 1. Synthetic Dataset ---
# 1 = Dark Web / Threat Context
# 0 = Normal / Safe Context
data = [
    # Dark Web / Illicit Patterns
    ("buying credit card dumps fullz", 1),
    ("selling hacked database access 2024", 1),
    ("fresh rdp access for sale admin rights", 1),
    ("passports and id cards cheap anonymous", 1),
    ("confidential company data leak download", 1),
    ("sql injection tools download private", 1),
    ("root access server buy bitcoin", 1),
    ("anonymous bitcoin laundering service mixer", 1),
    ("zero day exploit windows remote code", 1),
    ("ransomware as a service affiliate program", 1),
    ("bank logs for sale chase boa", 1),
    ("ssn dob fullz info usa", 1),
    
    # Normal / Safe Patterns
    ("how to bake a chocolate cake", 0),
    ("weather forecast for tomorrow london", 0),
    ("best restaurants in new york city", 0),
    ("python programming tutorials for beginners", 0),
    ("latest football match results premier league", 0),
    ("buy groceries online delivery", 0),
    ("funny cat videos compilation youtube", 0),
    ("top travel destinations 2025", 0),
    ("how to tie a tie simple knot", 0),
    ("learn spanish online free course", 0),
    ("my email is john.doe@example.com", 0),
    ("contact support for password reset", 0)
]

# --- 2. Train the Model ---
def train():
    print("Training Dark Web Chatter Detection Model...")
    
    df = pd.DataFrame(data, columns=['text', 'label'])

    # Convert text to numbers (TF-IDF)
    tfidf = TfidfVectorizer(stop_words='english', lowercase=True)
    X = tfidf.fit_transform(df['text'])
    y = df['label']

    # Random Forest Classifier
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)

    # --- 3. Save Artifacts ---
    base_path = os.path.dirname(os.path.abspath(__file__))
    
    with open(os.path.join(base_path, 'darkweb_model.pkl'), 'wb') as f:
        pickle.dump(model, f)
        
    with open(os.path.join(base_path, 'vectorizer.pkl'), 'wb') as f:
        pickle.dump(tfidf, f)

    print(f"Success! Model saved to {base_path}")

if __name__ == "__main__":
    train()