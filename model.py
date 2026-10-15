"""JSON-lines worker for the trained PhishGuard URL classifier."""
import json
import re
import sys
from urllib.parse import urlsplit

MODEL_PATH = "data/url_model.joblib"

def structural(url):
    parsed = urlsplit(url if re.match(r"^https?://", url, re.I) else "https://" + url)
    host = (parsed.hostname or "").lower()
    labels = [part for part in host.split(".") if part]
    path = parsed.path or "/"
    return {"host_length": min(len(host), 200), "url_length": min(len(url), 500), "path_length": min(len(path), 300), "label_count": len(labels), "digit_count": sum(c.isdigit() for c in url), "hyphen_count": url.count("-"), "dot_count": url.count("."), "at_count": url.count("@"), "query_count": url.count("?"), "percent_count": url.count("%"), "slash_count": url.count("/"), "has_ip": float(bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))), "has_punycode": float("xn--" in host), "has_https": float(parsed.scheme.lower() == "https"), "has_query": float(bool(parsed.query)), "suspicious_word": float(bool(re.search(r"login|signin|verify|secure|account|update|payment|wallet|password|kyc", url, re.I)))}

def main():
    try:
        import joblib
        from scipy.sparse import hstack
        artifact = joblib.load(MODEL_PATH)
    except Exception as exc:
        print(f"Unable to load URL model: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1) from exc
    text_vectorizer = artifact["text_vectorizer"]
    structural_vectorizer = artifact["structural_vectorizer"]
    classifier = artifact["classifier"]
    positive_index = list(classifier.classes_).index(1)
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if request.get("type") != "url":
                raise ValueError("The scikit-learn model is trained for URLs; message analysis uses the rule fallback.")
            text = request.get("text")
            if not isinstance(text, str) or not text.strip():
                raise ValueError("text must be a non-empty string")
            url = text.strip()
            normalized = url if re.match(r"^https?://", url, re.I) else "https://" + url
            features = hstack([text_vectorizer.transform([normalized]), structural_vectorizer.transform([structural(normalized)])])
            probability = float(classifier.predict_proba(features)[0][positive_index])
            suspicious = probability >= 0.5
            print(json.dumps({"label": "phishing_url" if suspicious else "legitimate_url", "confidence": max(probability, 1 - probability), "phish_probability": probability, "suspicious": suspicious, "engine": "character TF-IDF + structural features + Logistic Regression"}), flush=True)
        except Exception as exc:
            print(json.dumps({"error": str(exc)}), flush=True)

if __name__ == "__main__": main()
