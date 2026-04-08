import pandas as pd
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

def train():
    print("Loading dataset: Phishing_Legitimate_full.csv...")
    df = pd.read_csv('Phishing_Legitimate_full.csv')
    
    # 1. Select exactly 12 lexical features we can extract from a raw URL
    features = [
        'UrlLength', 'NumDots', 'NumDash', 'AtSymbol', 'TildeSymbol', 
        'NumUnderscore', 'NumPercent', 'NumAmpersand', 'NumHash', 
        'NumNumericChars', 'NoHttps', 'IpAddress'
    ]
    
    X = df[features]
    y = df['CLASS_LABEL']
    
    print("Splitting dataset into training and testing sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest model (this may take a moment)...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)
    
    accuracy = rf_model.score(X_test, y_test)
    print(f"Model trained successfully! Accuracy: {accuracy * 100:.2f}%")
    
    # 2. Save the model
    if not os.path.exists('models'):
        os.makedirs('models')
        
    model_path = 'models/phishing_rf_model.pkl'
    joblib.dump(rf_model, model_path)
    print(f"Model successfully saved to: {model_path}")

if __name__ == "__main__":
    train()