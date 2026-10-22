"""ML model: TF-IDF (word+char n-grams) + LogisticRegression, joblib persistence.

Train/test split BEFORE training; test split frozen (TECHNOLOGY.md §4, §7, §11).
If the model file is missing at serve time, /detect must still work (ml_score=null).
"""

from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

MODEL_DIR = Path(__file__).resolve().parents[2] / "model"
MODEL_PATH = MODEL_DIR / "model.joblib"
METRICS_PATH = MODEL_DIR / "metrics.json"


def build_pipeline() -> Pipeline:
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(2, 5),
                    sublinear_tf=True,
                    min_df=2,
                ),
            ),
            ("clf", LogisticRegression(max_iter=1000)),
        ]
    )


def train(texts: list[str], labels: list[int], test_size: float = 0.2, seed: int = 42) -> dict:
    """Split first, fit on train only, evaluate held-out test, persist model+metrics."""
    tr_x, te_x, tr_y, te_y = train_test_split(
        texts, labels, test_size=test_size, random_state=seed, stratify=labels
    )
    pipe = build_pipeline()
    # Word + char n-gram views per TECHNOLOGY.md §4; predictions averaged.
    word_pipe = Pipeline(
        steps=[
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2)),
            ("clf", LogisticRegression(max_iter=1000)),
        ]
    )
    pipe.fit(tr_x, tr_y)
    word_pipe.fit(tr_x, tr_y)

    def _predict_proba(t: str) -> float:
        return (pipe.predict_proba([t])[0][1] + word_pipe.predict_proba([t])[0][1]) / 2.0

    pred = [1 if _predict_proba(t) >= 0.5 else 0 for t in te_x]
    metrics = {
        "precision": precision_score(te_y, pred, zero_division=0),
        "recall": recall_score(te_y, pred, zero_division=0),
        "f1": f1_score(te_y, pred, zero_division=0),
        "n_train": len(tr_x),
        "n_test": len(te_x),
    }
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump({"char": pipe, "word": word_pipe}, MODEL_PATH)
    METRICS_PATH.write_text(str(metrics), encoding="utf-8")
    return metrics


def load_if_present() -> dict | None:
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    return None


def predict_score(pipes: dict, text: str) -> float:
    """Average of char- and word-ngram TF-IDF LogisticRegression probabilities."""
    p_char = pipes["char"].predict_proba([text])[0][1]
    p_word = pipes["word"].predict_proba([text])[0][1]
    return (p_char + p_word) / 2.0
