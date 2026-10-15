"""Long-lived JSON-lines worker for the PhishGuard text classifier."""
import json
import sys

def main():
    try:
        from transformers import pipeline
        classifier = pipeline("text-classification", model="cybersectony/phishing-email-detection-distilbert_v2.4.1")
    except Exception as exc:
        print(f"Unable to load phishing model: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1) from exc
    for line in sys.stdin:
        try:
            request = json.loads(line)
            text = request.get("text") if isinstance(request, dict) else None
            if not isinstance(text, str) or not text.strip(): raise ValueError("text must be a non-empty string")
            prediction = classifier(text[:10000], truncation=True, max_length=512)[0]
            label_map = {
                "LABEL_0": "legitimate_email",
                "LABEL_1": "phishing_url",
                "LABEL_2": "legitimate_url",
                "LABEL_3": "phishing_url_alt",
            }
            raw_label = str(prediction["label"])
            mapped_label = label_map.get(raw_label, raw_label)
            print(json.dumps({"label": mapped_label, "confidence": round(float(prediction["score"]), 6)}), flush=True)
        except Exception as exc:
            print(json.dumps({"error": str(exc)}), flush=True)

if __name__ == "__main__": main()
