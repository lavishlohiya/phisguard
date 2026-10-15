"""Train the PhishGuard URL detector: character TF-IDF + structural features."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
from scipy.sparse import hstack
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             precision_score, recall_score, f1_score)
from sklearn.model_selection import train_test_split


def normalize(value: str) -> str:
    value = value.strip()
    return value if re.match(r"^https?://", value, re.I) else "https://" + value


def structural(url: str) -> dict[str, float]:
    parsed = urlsplit(normalize(url))
    host = (parsed.hostname or "").lower()
    labels = [part for part in host.split(".") if part]
    path = parsed.path or "/"
    return {
        "host_length": min(len(host), 200), "url_length": min(len(url), 500),
        "path_length": min(len(path), 300), "label_count": len(labels),
        "digit_count": sum(char.isdigit() for char in url),
        "hyphen_count": url.count("-"), "dot_count": url.count("."),
        "at_count": url.count("@"), "query_count": url.count("?"),
        "percent_count": url.count("%"), "slash_count": url.count("/"),
        "has_ip": float(bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))),
        "has_punycode": float("xn--" in host),
        "has_https": float(parsed.scheme.lower() == "https"),
        "has_query": float(bool(parsed.query)),
        "suspicious_word": float(bool(re.search(r"login|signin|verify|secure|account|update|payment|wallet|password|kyc", url, re.I))),
    }


def load_rows(path: Path):
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    urls = [normalize(row["url"]) for row in rows]
    labels = np.array([int(row["label"]) for row in rows])
    return urls, labels


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path("data/url_dataset.jsonl"))
    parser.add_argument("--model", type=Path, default=Path("data/url_model.joblib"))
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    urls, labels = load_rows(args.data)
    if len(set(labels)) != 2 or len(urls) < 20:
        raise SystemExit("Need at least 20 examples containing both phishing and legitimate labels.")
    train_urls, test_urls, train_y, test_y = train_test_split(urls, labels, test_size=args.test_size, random_state=args.seed, stratify=labels)
    text_vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2, sublinear_tf=True, max_features=200000)
    structural_vectorizer = DictVectorizer()
    x_train = hstack([text_vectorizer.fit_transform(train_urls), structural_vectorizer.fit_transform([structural(url) for url in train_urls])])
    x_test = hstack([text_vectorizer.transform(test_urls), structural_vectorizer.transform([structural(url) for url in test_urls])])
    classifier = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=args.seed)
    classifier.fit(x_train, train_y)
    probabilities = classifier.predict_proba(x_test)[:, list(classifier.classes_).index(1)]
    predicted = (probabilities >= 0.5).astype(int)
    metrics = {
        "samples": len(urls), "train_samples": len(train_urls), "test_samples": len(test_urls),
        "accuracy": accuracy_score(test_y, predicted), "precision": precision_score(test_y, predicted, zero_division=0),
        "recall": recall_score(test_y, predicted, zero_division=0), "f1": f1_score(test_y, predicted, zero_division=0),
        "confusion_matrix": confusion_matrix(test_y, predicted).tolist(),
        "classification_report": classification_report(test_y, predicted, zero_division=0, output_dict=True),
        "seed": args.seed,
    }
    args.model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"text_vectorizer": text_vectorizer, "structural_vectorizer": structural_vectorizer, "classifier": classifier, "metrics": metrics}, args.model)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
