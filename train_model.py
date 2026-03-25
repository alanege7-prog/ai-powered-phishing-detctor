"""
train_model.py
--------------
Trains a TF-IDF + Logistic Regression phishing classifier and saves the
trained artefacts (model + vectorizer) to disk with joblib.

How to run
----------
    cd backend
    python model/train_model.py

The script expects a CSV file at:
    backend/sample_data/phishing_dataset.csv

with (at minimum) these two columns:
    text   – the email body, message, or URL string
    label  – 1 for phishing/spam, 0 for legitimate

See sample_data/dataset_instructions.md for recommended public datasets.

Model choice: TF-IDF + Logistic Regression
-------------------------------------------
- Fast to train, easy to explain in interviews
- Logistic Regression gives calibrated probability scores out of the box
- TF-IDF captures keyword patterns (urgent language, suspicious phrases)
- The pipeline is transparent — you can inspect feature weights directly
- Accuracy on public phishing datasets: typically 96-99 %
"""

import os
import sys
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection   import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model      import LogisticRegression
from sklearn.pipeline          import Pipeline
from sklearn.metrics           import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_auc_score,
)

# Make sure the utils module is importable when this script is run directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from utils.preprocess import clean_text

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATA_PATH   = os.path.join(BASE_DIR, "..", "sample_data", "phishing_dataset.csv")
MODEL_PATH  = os.path.join(BASE_DIR, "phishing_model.pkl")
VECT_PATH   = os.path.join(BASE_DIR, "vectorizer.pkl")


# ---------------------------------------------------------------------------
# 1. Load dataset
# ---------------------------------------------------------------------------
def load_data(path: str) -> pd.DataFrame:
    """
    Load and validate the phishing dataset CSV.
    Accepts both 'text/label' column names and common alternatives
    found in public datasets.
    """
    print(f"[1/5] Loading dataset from {path} ...")
    df = pd.read_csv(path)

    # Normalise column names to lowercase
    df.columns = df.columns.str.lower().str.strip()

    # Handle common alternative column names
    col_map = {
        "message": "text", "email": "text", "body": "text", "url": "text",
        "spam":    "label", "class": "label", "category": "label", "type": "label",
    }
    df.rename(columns=col_map, inplace=True)

    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError(
            "Dataset must have 'text' and 'label' columns. "
            f"Found: {list(df.columns)}"
        )

    # Normalise labels: accept 'spam'/'ham', 'phishing'/'legit', 1/0
    if df["label"].dtype == object:
        positive_words = {"spam", "phishing", "malicious", "1", "yes"}
        df["label"] = df["label"].str.lower().apply(
            lambda x: 1 if x in positive_words else 0
        )
    else:
        df["label"] = df["label"].astype(int)

    # Drop rows with missing text
    df = df.dropna(subset=["text"])
    df["text"] = df["text"].astype(str)

    print(f"    Loaded {len(df):,} samples.")
    print(f"    Label distribution:\n{df['label'].value_counts().to_string()}\n")
    return df


# ---------------------------------------------------------------------------
# 2. Preprocess
# ---------------------------------------------------------------------------
def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    print("[2/5] Cleaning text ...")
    df["clean_text"] = df["text"].apply(clean_text)
    # Drop rows that become empty after cleaning
    df = df[df["clean_text"].str.len() > 2].reset_index(drop=True)
    print(f"    {len(df):,} samples after cleaning.\n")
    return df


# ---------------------------------------------------------------------------
# 3. Train
# ---------------------------------------------------------------------------
def train(df: pd.DataFrame):
    print("[3/5] Training TF-IDF + Logistic Regression pipeline ...")

    X = df["clean_text"]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # TF-IDF vectorizer
    # - ngram_range (1,2): captures single words AND two-word phrases
    #   e.g. "click here", "verify account" are powerful phishing signals
    # - max_features=20000: keeps the vocabulary manageable
    # - sublinear_tf=True: dampens the effect of very frequent terms
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=20_000,
        sublinear_tf=True,
        strip_accents="unicode",
        analyzer="word",
        token_pattern=r"\b[a-zA-Z][a-zA-Z0-9']{1,}\b",
        min_df=2,
    )

    # Logistic Regression
    # - C=1.0: default regularisation (tune higher to reduce bias)
    # - max_iter=1000: ensures convergence on larger datasets
    # - class_weight='balanced': handles class imbalance automatically
    model = LogisticRegression(
        C=1.0,
        max_iter=1000,
        solver="lbfgs",
        class_weight="balanced",
        random_state=42,
    )

    # Fit vectorizer then model
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec  = vectorizer.transform(X_test)
    model.fit(X_train_vec, y_train)

    return vectorizer, model, X_test_vec, y_test


# ---------------------------------------------------------------------------
# 4. Evaluate
# ---------------------------------------------------------------------------
def evaluate(model, X_test_vec, y_test):
    print("[4/5] Evaluating model ...")

    y_pred = model.predict(X_test_vec)
    y_prob = model.predict_proba(X_test_vec)[:, 1]

    print(f"\n    Accuracy : {accuracy_score(y_test, y_pred):.4f}")
    print(f"    ROC-AUC  : {roc_auc_score(y_test, y_prob):.4f}")
    print(f"\n    Classification Report:\n")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))
    print(f"    Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}\n")


# ---------------------------------------------------------------------------
# 5. Save artefacts
# ---------------------------------------------------------------------------
def save(vectorizer, model):
    print("[5/5] Saving model artefacts ...")
    joblib.dump(model,      MODEL_PATH)
    joblib.dump(vectorizer, VECT_PATH)
    print(f"    Model saved      → {MODEL_PATH}")
    print(f"    Vectorizer saved → {VECT_PATH}")
    print("\n✅ Training complete.\n")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if not os.path.exists(DATA_PATH):
        print(
            f"\n❌  Dataset not found at:\n    {DATA_PATH}\n\n"
            "Please follow the instructions in backend/sample_data/dataset_instructions.md\n"
        )
        sys.exit(1)

    df                      = load_data(DATA_PATH)
    df                      = preprocess(df)
    vectorizer, model, X_t, y_t = train(df)
    evaluate(model, X_t, y_t)
    save(vectorizer, model)
