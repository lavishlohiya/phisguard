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
            prediction = classifier(text[:10000], truncation=True, max_length=512, top_k=None)
            scores = {item["label"]: float(item["score"]) for item in prediction}
            
            # LABEL_0: legitimate_email, LABEL_1: phishing_email, LABEL_2: legitimate_url, LABEL_3: phishing_url
            p_legit_email = scores.get("LABEL_0", 0.0)
            p_phish_email = scores.get("LABEL_1", 0.0)
            p_legit_url = scores.get("LABEL_2", 0.0)
            p_phish_url = scores.get("LABEL_3", 0.0)

            # Determine whether input is primarily URL or email/message
            req_type = request.get("type", "")
            is_url = req_type == "url" or (not req_type and text.strip().startswith(("http://", "https://", "www.")))

            if is_url:
                # URL classification: compare phishing_url vs legitimate_url
                total_url = p_phish_url + p_legit_url
                if total_url > 0:
                    phish_ratio = p_phish_url / total_url
                else:
                    phish_ratio = p_phish_url
                
                label = "phishing_url" if phish_ratio >= 0.5 else "legitimate_url"
                confidence = phish_ratio if label == "phishing_url" else (1.0 - phish_ratio)
                suspicious = phish_ratio >= 0.5
                phish_prob = phish_ratio
            else:
                # Email / message classification: compare phishing_email vs legitimate_email
                total_email = p_phish_email + p_legit_email
                if total_email > 0:
                    phish_ratio = p_phish_email / total_email
                else:
                    phish_ratio = p_phish_email

                label = "phishing_email" if phish_ratio >= 0.5 else "legitimate_email"
                confidence = phish_ratio if label == "phishing_email" else (1.0 - phish_ratio)
                suspicious = phish_ratio >= 0.5
                phish_prob = phish_ratio

            print(json.dumps({
                "label": label,
                "confidence": round(float(confidence), 6),
                "phish_probability": round(float(phish_prob), 6),
                "suspicious": bool(suspicious),
                "scores": scores
            }), flush=True)
        except Exception as exc:
            print(json.dumps({"error": str(exc)}), flush=True)

if __name__ == "__main__": main()
