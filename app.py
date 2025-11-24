import streamlit as st
import pickle
import pandas as pd
import importlib.util
import os

# -------------------------------------------------------------
# 1) FORCE LOAD EXTRACTOR FILE (features_extract.py)
# -------------------------------------------------------------
extractor_path = os.path.join(os.getcwd(), "features_extract.py")

spec = importlib.util.spec_from_file_location("features_extract", extractor_path)
fe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fe)

extract_features = fe.extract_features  # now guaranteed to load


# -------------------------------------------------------------
# 2) LOAD THE NEW MODEL AND SCALER
# -------------------------------------------------------------
MODEL_FILE = "phishing_model.pkl"
SCALER_FILE = "scaler.pkl"

model = pickle.load(open(MODEL_FILE, "rb"))
scaler = pickle.load(open(SCALER_FILE, "rb"))


# -------------------------------------------------------------
# 3) FINAL FEATURE ORDER (MUST MATCH TRAINING)
# -------------------------------------------------------------
feature_order = [
    'url_length', 'is_ip', 'keyword_hits', 'domain_length',
    'path_length', 'query_length', 'subdomain_count', 'has_ip',
    'dot_count', 'hyphen_count', 'slash_count', 'question_count',
    'equal_count', 'percent_count', 'at_count', 'digit_ratio',
    'letter_ratio', 'special_char_ratio', 'path_depth', 'url_entropy',
    'domain_entropy', 'suspicious_tld', 'has_php', 'has_html',
    'has_exe', 'is_shortened', 'is_https', 'tld_grp'
]


# -------------------------------------------------------------
# 4) TLD GROUPING LOGIC
# -------------------------------------------------------------
suspicious_tlds = {"tk","ml","ga","cf","gq","xyz","zip","mov","top","live","work"}
common_tlds = {"com","org","net","edu","gov","in","co","io","info","biz"}

def make_tld_grp(tld):
    tld = str(tld).lower().strip()
    if tld in suspicious_tlds:
        return 1
    if tld in common_tlds:
        return 0
    return 2


# -------------------------------------------------------------
# 5) PREDICTION FUNCTION (final version)
# -------------------------------------------------------------
def predict_url(url):
    feats = extract_features(url)

    # patch missing features
    feats["is_ip"] = int(feats.get("has_ip", 0))
    feats["tld_grp"] = make_tld_grp(feats.get("tld", ""))

    # ensure all features exist
    for col in feature_order:
        if col not in feats:
            feats[col] = 0

    df = pd.DataFrame([feats])[feature_order]

    X_scaled = scaler.transform(df)
    pred = model.predict(X_scaled)[0]
    prob = model.predict_proba(X_scaled)[0][1]

    return pred, prob


# -------------------------------------------------------------
# 6) STREAMLIT UI
# -------------------------------------------------------------
st.title("🔐 Phishing URL Detection System")
st.write("Enter a URL to classify it as **Malicious** or **Legitimate** using the improved ML model.")

url_input = st.text_input("Enter URL:", placeholder="https://example.com")

if st.button("Analyze URL"):
    if url_input.strip() == "":
        st.warning("Please enter a URL first.")
    else:
        pred, prob = predict_url(url_input)

        if pred == 1:
            st.error(f"🚨 **Malicious URL Detected!**\n\nConfidence: {prob:.4f}")
        else:
            st.success(f"✅ **Legitimate URL**\n\nConfidence: {1 - prob:.4f}")
