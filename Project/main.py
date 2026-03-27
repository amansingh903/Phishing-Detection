import os
import pandas as pd
import numpy as np
import joblib
import re
import datetime
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="PhishGuard AI v1.7")

# --- CORS SETTINGS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 🛡️ INITIALIZE GLOBALS ---
model = None
feature_names = [] 

# Trusted and High-Risk constants
TRUSTED_DOMAINS = {"google.com", "facebook.com", "leetcode.com", "github.com", "microsoft.com", "apple.com", "youtube.com"}
DANGER_KEYWORDS = ['paypal', 'login', 'verify', 'update', 'banking', 'secure', 'account', 'signin']

# --- ABSOLUTE PATH FIX ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'phishing_model_v3.pkl')
FEATURE_PATH = os.path.join(BASE_DIR, 'feature_names_v3.pkl')

# --- LOAD MODELS ---
# We use a startup event to properly load and assign the global variables
@app.on_event("startup")
def load_ml_assets():
    global model, feature_names
    try:
        model = joblib.load(MODEL_PATH)
        # Often feature lists are saved as standard pickles, but joblib works if you saved it with joblib
        feature_names = joblib.load(FEATURE_PATH) 
        print(f"✅ [{datetime.datetime.now().strftime('%H:%M:%S')}] Engine ready with {len(feature_names)} features.")
    except Exception as e:
        print(f"❌ CRITICAL ERROR: Could not load .pkl files from {BASE_DIR}. {e}")

class URLData(BaseModel):
    url: str

def extract_all_112_features(url):
    """
    Simulates the extraction for a numeric dataset.
    This logic maps your URL string to the numeric columns the model expects.
    """
    global feature_names
    
    # If feature names failed to load, return an empty DataFrame
    if not isinstance(feature_names, (list, np.ndarray, pd.Series)) or len(feature_names) == 0:
        return pd.DataFrame()

    feat_dict = {name: 0 for name in feature_names}
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # Fill numeric features based on common dataset headers
    for name in feature_names:
        n = name.lower()
        # Lexical Features
        if 'url_len' in n: feat_dict[name] = len(url)
        if 'dot' in n: feat_dict[name] = url.count('.')
        if 'hyphen' in n: feat_dict[name] = url.count('-')
        if 'at_symbol' in n or 'at_sign' in n: feat_dict[name] = 1 if '@' in url else 0
        if 'slash' in n: feat_dict[name] = url.count('/')
        if 'digit' in n: feat_dict[name] = sum(c.isdigit() for c in url)
        if 'https' in n: feat_dict[name] = 1 if url.startswith('https') else 0
        
        # Domain/Path Features
        if 'subdomain' in n: feat_dict[name] = domain.count('.') - 1
        if 'path_len' in n: feat_dict[name] = len(path)
        if 'ip_address' in n: feat_dict[name] = 1 if re.search(r'\d{1,3}\.\d{1,3}', domain) else 0

    # Ensure the dataframe columns exactly match the feature_names order
    return pd.DataFrame([feat_dict], columns=feature_names)

@app.post("/analyze")
async def analyze(data: URLData):
    try:
        url_raw = data.url.lower()
        domain = urlparse(url_raw).netloc.replace("www.", "")
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')

        # 1. 🛡️ WHITELIST CHECK
        if any(trusted in domain for trusted in TRUSTED_DOMAINS):
            print(f"🟢 [{timestamp}] TRUSTED | 100.0% | URL: {data.url}")
            return {
                "status": "safe",
                "label": "Trusted Domain",
                "confidence": "100", # Changed from "100%" to "100" to match popup.js expectations
                "url": data.url
            }

        # SAFETY CHECK: Ensure the model actually loaded before predicting
        if model is None:
            print(f"❌ [{timestamp}] ERROR: Attempted prediction but model is not loaded.")
            raise HTTPException(status_code=500, detail="AI Model failed to load on the server.")

        # 2. 🧠 AI ANALYSIS
        features = extract_all_112_features(data.url)
        
        # Guard clause in case feature extraction fails
        if features.empty:
             print(f"❌ [{timestamp}] ERROR: Feature extraction failed (empty dataframe).")
             raise HTTPException(status_code=500, detail="Feature extraction failed.")

        probs = model.predict_proba(features)[0]
        
        phish_score = probs[1]
        safe_score = probs[0]

        # 3. THRESHOLD LOGIC
        has_danger_word = any(word in url_raw for word in DANGER_KEYWORDS)
        threshold = 0.40 if has_danger_word else 0.80
        is_phishing = phish_score > threshold
        
        # Calculate display confidence based on the result
        final_conf_value = phish_score if is_phishing else safe_score
        display_confidence = round(final_conf_value * 100, 2)

        # --- 📟 TERMINAL LOGGING ---
        if is_phishing:
            print(f"🚨 [{timestamp}] DANGER  | {display_confidence}% | URL: {data.url}")
        else:
            print(f"✅ [{timestamp}] SAFE    | {display_confidence}% | URL: {data.url}")

        return {
            "status": "danger" if is_phishing else "safe",
            "label": "Phishing" if is_phishing else "Benign",
            "confidence": str(display_confidence), # Ensure it sends just the number, popup.js adds the %
            "url": data.url
        }

    except Exception as e:
        print(f"❌ [{datetime.datetime.now().strftime('%H:%M:%S')}] ERROR: {e}")
        return {"status": "error", "message": "Analysis failed"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)