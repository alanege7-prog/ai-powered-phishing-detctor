"""
preprocess.py
-------------
Cleans and normalises raw text before it is vectorised and fed into the model.
Used by both train_model.py (at training time) and app.py (at inference time)
so the input transformation is always consistent.
"""

import re
import string


def clean_text(text: str) -> str:
    """
    Apply a lightweight NLP cleaning pipeline to a raw text string.

    Steps
    -----
    1. Lower-case everything so 'FREE' and 'free' are treated identically.
    2. Remove URLs – the URL feature extractor handles link analysis separately.
    3. Remove email addresses (they add noise to word-based features).
    4. Remove punctuation except apostrophes (keeps "won't", "don't" intact).
    5. Collapse multiple whitespace characters into a single space.
    6. Strip leading/trailing whitespace.

    Parameters
    ----------
    text : str
        Raw user-submitted text (email body, message, or URL string).

    Returns
    -------
    str
        Cleaned text ready for TF-IDF vectorisation.
    """

    if not isinstance(text, str):
        return ""

    # 1. Lower-case
    text = text.lower()

    # 2. Remove URLs (http/https/www variants)
    text = re.sub(r"http\S+|www\.\S+", " ", text)

    # 3. Remove email addresses
    text = re.sub(r"\S+@\S+", " ", text)

    # 4. Remove punctuation (keep apostrophes)
    allowed = set(string.printable) - set(string.punctuation) | {"'"}
    text = "".join(ch if ch in allowed else " " for ch in text)

    # 5. Collapse whitespace
    text = re.sub(r"\s+", " ", text)

    # 6. Strip
    return text.strip()


# ---------------------------------------------------------------------------
# Quick sanity check – run `python preprocess.py` to verify the pipeline
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    sample = "URGENT! Click http://totally-legit.biz/win?id=123 NOW or lose your account!!!"
    print("Original :", sample)
    print("Cleaned  :", clean_text(sample))
