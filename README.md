# 🛡️ PhishGuard AI — Phishing Detector

> An AI-powered web application that detects phishing emails, suspicious messages, and malicious URLs using machine learning. Built for educational and defensive cybersecurity purposes.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5-orange?logo=scikit-learn)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

---

## 📸 Screenshots

<img width="1613" height="945" alt="Screenshot 2026-03-25 144517" src="https://github.com/user-attachments/assets/a17177c5-e607-4a8d-99db-49de9668b900" />
 The main scanner interface with Email/Message and URL tabs, file upload, and dark mode.

<img width="1581" height="963" alt="Screenshot 2026-03-25 144616" src="https://github.com/user-attachments/assets/a5e329ab-277c-409c-a3b5-e42bbe11ea44" />
A normal message correctly classified as Legitimate with a 4% confidence score.

<img width="1670" height="938" alt="Screenshot 2026-03-25 144646" src="https://github.com/user-attachments/assets/8e236ba6-3be8-45e4-a507-9df4e75b6308" />
 A phishing email flagged with 76% confidence and a clear warning banner.

<img width="1470" height="958" alt="Screenshot 2026-03-25 144656" src="https://github.com/user-attachments/assets/9683d8d8-9d71-4d6f-809c-eefdf4427725" />
The explainability panel showing exactly why the content was flagged — urgent language, suspicious action request, and impersonation language.


---

## 🎯 Project Overview

PhishGuard AI is a full-stack machine learning application that classifies user-submitted content into three categories:

| Label | Meaning |
|---|---|
| 🚨 **Phishing** | High confidence this is a phishing attempt |
| ⚠️ **Suspicious** | Some red flags detected — proceed with caution |
| ✅ **Legitimate** | No significant phishing indicators found |

The system also explains *why* content was flagged, citing specific signals such as urgent language, suspicious URL patterns, or credential-harvesting phrases. This makes the tool educational as well as practical.

**This project is for defensive cybersecurity purposes only.** It is designed to help people identify threats, not to generate or facilitate phishing content.

---

## ✨ Features

- **Multi-input support** — analyse email bodies, chat messages, or URLs
- **ML-powered classification** — TF-IDF vectorisation + Logistic Regression trained on real phishing datasets
- **Confidence score** — probability displayed as a visual progress bar
- **Explainability panel** — plain-English reasons why content was flagged
- **URL risk analyser** — detects IP-based URLs, suspicious TLDs, brand impersonation, excessive subdomains, and more
- **File upload** — upload a `.txt` file for batch scanning
- **Scan history** — browse previous results in a slide-out drawer
- **Dark / light mode** — persisted via localStorage
- **Rule-based fallback** — works even before the ML model is trained (great for demos)
- **CORS-enabled REST API** — cleanly separates frontend and backend

---

## 🏗️ Architecture

```
┌─────────────────────────────────┐
│         Browser (Frontend)      │
│  HTML + CSS + Vanilla JS        │
│  • Input panel                  │
│  • Results / confidence bar     │
│  • History drawer               │
└──────────────┬──────────────────┘
               │ HTTP POST /predict
               ▼
┌─────────────────────────────────┐
│       Flask REST API            │
│  app.py                         │
│  • /predict  (POST)             │
│  • /history  (GET / DELETE)     │
│  • /health   (GET)              │
└──────┬────────────┬─────────────┘
       │            │
       ▼            ▼
┌──────────┐  ┌─────────────────┐
│ ML Model │  │ URL Feature      │
│ TF-IDF   │  │ Extractor        │
│ + LogReg │  │ url_features.py  │
└──────────┘  └─────────────────┘
```

---

## 🚀 Installation & Setup

### Prerequisites

- Python 3.10 or higher
- A modern web browser
- Git

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/phishing-detector.git
cd phishing-detector
```

### 2. Set up the Python backend

```bash
cd backend
python -m venv venv

# Activate (Mac/Linux)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate

pip install -r requirements.txt
```

### 3. Download a dataset and train the model

Follow the instructions in [`backend/sample_data/dataset_instructions.md`](backend/sample_data/dataset_instructions.md) to download a free phishing dataset.

The quickest option is the SMS Spam Collection from UCI:

```bash
# After placing phishing_dataset.csv in backend/sample_data/
python model/train_model.py
```

Expected output:
```
[1/5] Loading dataset ...  Loaded 5,572 samples.
[2/5] Cleaning text ...
[3/5] Training TF-IDF + Logistic Regression pipeline ...
[4/5] Evaluating model ...
      Accuracy : 0.9847
      ROC-AUC  : 0.9961
[5/5] Saving model artefacts ...
✅ Training complete.
```

### 4. Start the API server

```bash
# From the backend/ directory
python app.py
```

The API will be available at `http://localhost:5000`

### 5. Open the frontend

Simply open `frontend/index.html` in your browser — no build step required.

```bash
# Mac
open ../frontend/index.html

# Linux
xdg-open ../frontend/index.html

# Windows
start ../frontend/index.html
```

---

## 🔌 API Reference

### `POST /predict`

Classify a text or URL submission.

**Request:**
```json
{
  "text": "URGENT: Your account will be suspended. Click here to verify: http://fake-paypal.tk/login"
}
```

**Response:**
```json
{
  "id": "a3f2c1d0-...",
  "input": "URGENT: Your account will be suspended...",
  "input_type": "text",
  "label": "Phishing",
  "confidence": 0.9423,
  "reasons": [
    "Urgent or threatening language",
    "Suspicious action request",
    "Impersonation language"
  ],
  "url_flags": [
    "URL uses HTTP (not HTTPS)",
    "Domain uses a TLD commonly associated with phishing (.tk)"
  ],
  "timestamp": "2024-11-15T14:32:01.123Z",
  "disclaimer": "..."
}
```

### `GET /history?limit=10`
Returns the most recent scan results.

### `DELETE /history`
Clears all scan history.

### `GET /health`
Liveness check — returns model load status and timestamp.

---

## 🧠 Model Details

| Component | Choice | Reason |
|---|---|---|
| Vectoriser | TF-IDF (unigrams + bigrams) | Captures both individual keywords and two-word phrases like "click here" |
| Classifier | Logistic Regression | Fast, interpretable, gives calibrated probability scores |
| Class weighting | `balanced` | Handles unequal phishing/legitimate sample counts automatically |
| Preprocessing | lowercase → strip URLs/emails → remove punctuation | Consistent normalisation between training and inference |

**Typical performance on SMS Spam Collection dataset:**
- Accuracy: ~98.5%
- ROC-AUC: ~99.6%

---

## 📁 Project Structure

```
phishing-detector/
├── backend/
│   ├── app.py                  # Flask API (main entry point)
│   ├── requirements.txt
│   ├── model/
│   │   ├── train_model.py      # Training pipeline
│   │   ├── phishing_model.pkl  # Trained model (generated)
│   │   └── vectorizer.pkl      # TF-IDF vectorizer (generated)
│   ├── utils/
│   │   ├── preprocess.py       # Text cleaning functions
│   │   └── url_features.py     # URL red-flag extraction
│   └── sample_data/
│       └── dataset_instructions.md
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── .gitignore
└── README.md
```

---

## 🔮 Future Improvements

- [ ] **Transformer-based model** — replace Logistic Regression with a fine-tuned BERT or DistilBERT model for higher accuracy on complex phishing emails
- [ ] **Live URL scanning** — integrate with VirusTotal or Google Safe Browsing API for real-time URL reputation lookup
- [ ] **Highlighted suspicious text** — underline or colour-code the specific phrases that triggered the flag
- [ ] **Browser extension** — wrap the detector as a Chrome/Firefox extension that scans page content automatically
- [ ] **Persistent history** — replace in-memory history with a SQLite or PostgreSQL database
- [ ] **Docker support** — containerise frontend + backend for one-command deployment
- [ ] **Authentication** — add a simple API key to the `/predict` endpoint for rate-limiting
- [ ] **Multilingual support** — extend preprocessing to handle phishing in languages other than English

---

## 🛠️ Skills Demonstrated

- **Machine Learning** — full ML pipeline: data loading, preprocessing, TF-IDF vectorisation, Logistic Regression, evaluation metrics (accuracy, ROC-AUC, confusion matrix)
- **REST API design** — Flask endpoints with proper HTTP status codes, JSON responses, CORS handling
- **NLP preprocessing** — lowercasing, regex-based cleaning, tokenisation, n-gram feature engineering
- **Feature engineering** — hand-crafted URL features (domain analysis, TLD detection, structural red flags)
- **Frontend development** — vanilla JS async/await, DOM manipulation, responsive CSS, dark/light mode theming
- **Software engineering** — modular code structure, separation of concerns, code comments, error handling
- **Security awareness** — defensive framing, explainability, appropriate disclaimers

---

## ⚠️ Disclaimer

This tool is for **educational and defensive cybersecurity purposes only**. Predictions are probabilistic and not 100% accurate. Do not rely solely on this tool to determine whether content is safe. Never use this project to generate, test, or send phishing content. The authors accept no liability for misuse.

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

- [SMS Spam Collection Dataset — UCI ML Repository](https://archive.ics.uci.edu/ml/datasets/SMS+Spam+Collection)
- [scikit-learn](https://scikit-learn.org/) — ML library
- [Flask](https://flask.palletsprojects.com/) — web framework
- OWASP for phishing URL pattern research
