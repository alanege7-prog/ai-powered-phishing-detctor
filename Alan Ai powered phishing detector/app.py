"""
app.py
------
Flask REST API for the AI-Powered Phishing Detector.

Endpoints
---------
GET  /health          – liveness check
POST /predict         – classify a text / URL submission
GET  /history         – return the last N predictions (in-memory)
DELETE /history       – clear prediction history

Running locally
---------------
    cd backend
    python app.py

The API will be available at http://localhost:5000
"""

import os
import sys
import re
import json
import uuid
from datetime import datetime, timezone

import joblib
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS

# Make sure utils are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.preprocess   import clean_text
from utils.url_features import get_url_risk_flags

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
CORS(app)  # allow requests from the frontend (different port in dev)

# ---------------------------------------------------------------------------
# Load model artefacts
# ---------------------------------------------------------------------------
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(BASE_DIR, "model", "phishing_model.pkl")
VECT_PATH   = os.path.join(BASE_DIR, "model", "vectorizer.pkl")

model_loaded = False
model        = None
vectorizer   = None

if os.path.exists(MODEL_PATH) and os.path.exists(VECT_PATH):
    try:
        model      = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECT_PATH)
        model_loaded = True
        print("✅  Model loaded successfully.")
    except Exception as e:
        print(f"⚠️   Could not load model: {e}")
else:
    print("⚠️   Model files not found. Run model/train_model.py first.")
    print("     The API will use a rule-based fallback until the model is available.")

# ---------------------------------------------------------------------------
# In-memory scan history (resets on server restart — good enough for portfolio)
# ---------------------------------------------------------------------------
scan_history: list[dict] = []
MAX_HISTORY = 50


# ---------------------------------------------------------------------------
# Helper: rule-based fallback (works without a trained model)
# ---------------------------------------------------------------------------
PHISHING_KEYWORDS = [
    "urgent", "verify", "suspend", "account", "password", "click here",
    "confirm", "login", "update", "free", "prize", "winner", "limited time",
    "act now", "immediate", "alert", "bank", "credit card", "ssn",
    "social security", "validate", "unusual activity", "24 hours",
]

def rule_based_score(text: str) -> float:
    """
    Simple keyword-matching fallback.
    Returns a float in [0, 1] representing phishing likelihood.
    """
    lower = text.lower()
    hits  = sum(1 for kw in PHISHING_KEYWORDS if kw in lower)
    # Normalise: 0 hits → 0.1, 5+ hits → 0.9
    return min(0.1 + hits * 0.15, 0.95)


# ---------------------------------------------------------------------------
# Helper: detect whether input looks like a URL
# ---------------------------------------------------------------------------
URL_RE = re.compile(
    r"(https?://|www\.)\S+|"
    r"\b[a-zA-Z0-9.-]+\.(com|org|net|io|tk|ml|xyz|top|club|biz|info)\b",
    re.IGNORECASE,
)

def is_url(text: str) -> bool:
    return bool(URL_RE.match(text.strip()))


# ---------------------------------------------------------------------------
# Helper: extract human-readable explanations from the text
# ---------------------------------------------------------------------------
EXPLANATION_PATTERNS = {
    "Urgent or threatening language": [
        r"\b(urgent|immediate|alert|warning|act now|limited time|expire)\b"
    ],
    "Suspicious action request": [
        r"\b(click here|verify|confirm|update|validate|login|log in|sign in)\b"
    ],
    "Financial / credential lure": [
        r"\b(password|credit card|ssn|social security|bank account|billing)\b"
    ],
    "Prize or reward bait": [
        r"\b(free|prize|winner|won|reward|gift|congratulations)\b"
    ],
    "Impersonation language": [
        r"\b(paypal|amazon|apple|microsoft|netflix|google|facebook|instagram)\b"
    ],
    "Too many special characters": None,  # handled separately
}

def explain_text(text: str) -> list[str]:
    """
    Scan text for known phishing patterns and return a list of
    plain-English explanations that will be shown to the user.
    """
    lower   = text.lower()
    reasons = []

    for label, patterns in EXPLANATION_PATTERNS.items():
        if patterns is None:
            # Special-character density check
            special = len(re.findall(r"[!$%^&*#@]{2,}", text))
            if special >= 2:
                reasons.append("Contains clusters of special characters (e.g. !!!, $$$)")
        else:
            for pattern in patterns:
                if re.search(pattern, lower):
                    reasons.append(label)
                    break  # one match per category is enough

    return reasons


# ---------------------------------------------------------------------------
# Helper: map probability to label
# ---------------------------------------------------------------------------
def score_to_label(prob: float) -> str:
    if prob >= 0.65:
        return "Phishing"
    elif prob >= 0.35:
        return "Suspicious"
    else:
        return "Legitimate"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    """Liveness check — useful for deployment health probes."""
    return jsonify({
        "status":       "ok",
        "model_loaded": model_loaded,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
    })


@app.route("/predict", methods=["POST"])
def predict():
    """
    Classify a submitted text or URL.

    Request body (JSON)
    -------------------
    {
        "text": "string — email body, message, or URL"
    }

    Response (JSON)
    ---------------
    {
        "id":           "uuid",
        "input":        "original text (truncated for display)",
        "input_type":   "url" | "text",
        "label":        "Phishing" | "Suspicious" | "Legitimate",
        "confidence":   0.87,           // float 0-1
        "reasons":      ["..."],        // list of plain-English explanations
        "url_flags":    ["..."],        // populated only for URL inputs
        "timestamp":    "ISO-8601",
        "disclaimer":   "string"
    }
    """

    # --- Parse request ---
    data = request.get_json(silent=True)
    if not data or "text" not in data:
        return jsonify({"error": "Request body must be JSON with a 'text' field."}), 400

    raw_text = str(data["text"]).strip()
    if not raw_text:
        return jsonify({"error": "'text' field cannot be empty."}), 400

    if len(raw_text) > 10_000:
        return jsonify({"error": "Input too long. Maximum 10,000 characters."}), 400

    # --- Determine input type ---
    input_type = "url" if is_url(raw_text) else "text"

    # --- Get phishing probability ---
    if model_loaded:
        cleaned = clean_text(raw_text)
        vec     = vectorizer.transform([cleaned])
        prob    = float(model.predict_proba(vec)[0, 1])
    else:
        # Graceful fallback: rule-based scoring
        prob = rule_based_score(raw_text)

    # Clamp to avoid floating-point edge cases
    prob = float(np.clip(prob, 0.0, 1.0))

    # --- Label ---
    label = score_to_label(prob)

    # --- Explanations ---
    text_reasons = explain_text(raw_text)
    url_flags    = get_url_risk_flags(raw_text) if input_type == "url" else []

    # Merge and de-duplicate
    all_reasons = list(dict.fromkeys(text_reasons + url_flags))

    # If the model says it's suspicious/phishing but no rule fired, add a generic note
    if label != "Legitimate" and not all_reasons:
        all_reasons = ["Statistical pattern matches known phishing content"]

    # --- Build response ---
    result = {
        "id":          str(uuid.uuid4()),
        "input":       raw_text[:200] + ("..." if len(raw_text) > 200 else ""),
        "input_type":  input_type,
        "label":       label,
        "confidence":  round(prob, 4),
        "reasons":     all_reasons,
        "url_flags":   url_flags,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "disclaimer":  (
            "This tool is for educational and informational purposes only. "
            "Predictions are not 100% accurate. Always exercise caution with "
            "unexpected emails or links, and consult your IT/security team if unsure."
        ),
    }

    # --- Store in history ---
    scan_history.insert(0, result)
    if len(scan_history) > MAX_HISTORY:
        scan_history.pop()

    return jsonify(result), 200


@app.route("/history", methods=["GET"])
def get_history():
    """Return the most recent scan results."""
    limit  = min(int(request.args.get("limit", 10)), MAX_HISTORY)
    return jsonify({"history": scan_history[:limit], "total": len(scan_history)}), 200


@app.route("/history", methods=["DELETE"])
def clear_history():
    """Clear all scan history."""
    scan_history.clear()
    return jsonify({"message": "History cleared."}), 200


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n🚀  Phishing Detector API running on http://localhost:{port}\n")
    app.run(debug=True, host="0.0.0.0", port=port)
