# Dataset Instructions

The model requires a labelled CSV file saved as:

```
backend/sample_data/phishing_dataset.csv
```

## Recommended Free Datasets

### Option A — SMS Spam Collection (quickest start, ~5 min)
- **URL:** https://archive.ics.uci.edu/ml/datasets/SMS+Spam+Collection
- **Why:** 5,574 labelled SMS messages (spam / ham), clean and well-studied
- **Columns after download:** `label`, `message`
- **Rename to:** `label`, `text` (the train script handles this automatically)

### Option B — Enron Spam Dataset (email focused)
- **URL:** https://huggingface.co/datasets/SetFit/enron_spam
- **Why:** Real-world email data, ~33,000 samples, better for email classification
- Download via Hugging Face datasets library:
  ```python
  from datasets import load_dataset
  ds = load_dataset("SetFit/enron_spam", split="train")
  ds.to_csv("backend/sample_data/phishing_dataset.csv")
  ```

### Option C — Phishing URL Dataset (URL focused)
- **URL:** https://www.kaggle.com/datasets/siddharthkumar25/malicious-and-benign-urls
- **Why:** ~450,000 labelled URLs, great for URL-specific features
- **Columns:** `url`, `type` (benign / defacement / phishing / malware)
- Simplify to binary: phishing=1, benign=0

### Option D — Combined Email + Phishing Dataset
- **URL:** https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset
- **Why:** Purpose-built phishing email dataset, ~18,000 samples

---

## Minimum CSV Format

```
text,label
"Congratulations! You have won a free prize. Click here now!",1
"Hi John, attached are the meeting notes from Tuesday.",0
"URGENT: Your account will be suspended. Verify immediately.",1
```

- `text` column: the raw email body, message, or URL string
- `label` column: `1` = phishing/spam, `0` = legitimate

The training script also accepts these alternative column names automatically:
- `message`, `email`, `body`, `url` → treated as `text`
- `spam`, `class`, `category`, `type` → treated as `label`

---

## Running Training After Downloading

```bash
cd backend
python model/train_model.py
```

Expected output:
```
[1/5] Loading dataset ...
[2/5] Cleaning text ...
[3/5] Training TF-IDF + Logistic Regression pipeline ...
[4/5] Evaluating model ...
      Accuracy : 0.9847
      ROC-AUC  : 0.9961
[5/5] Saving model artefacts ...
✅ Training complete.
```

The trained model files will be saved to:
- `backend/model/phishing_model.pkl`
- `backend/model/vectorizer.pkl`
