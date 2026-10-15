# PhishGuard

PhishGuard is a CyberCup 6.0 prototype for explainable screening of suspicious messages and HTTP(S) URLs. Messages use the local rule engine plus the Hugging Face model configured in `model.py`; URLs are parsed locally and never fetched.

## Setup

Requires Node.js 18+, Python 3.10+, and the Python `transformers` package.

```bash
npm install
npm start
```

Install the model dependency once with `python -m pip install transformers torch`. On first startup, Hugging Face downloads the configured model. If Python or the model is unavailable, the rule-based analyzer continues to work and the API reports that the model was unavailable.

Open `http://localhost:3000`. Development mode is `npm run dev`; health is available at `/api/health`.

## Architecture

- `server.js` serves the existing UI, validates API requests through `analyze`, and sends message text to the long-lived Python worker in `ml-service.js`.
- `model.py` loads `cybersectony/phishing-email-detection-distilbert_v2.4.1` once and communicates through JSON lines. `PYTHON_BIN` can be set when the Python executable is not named `python`.
- `analyzer.js` has separate message and URL pipelines. URL mode requires a complete HTTP/HTTPS URL and only inspects its parsed text: hostname, subdomains, look-alike brand placement, IP hosts, path/query structure, encoding, ports, and HTTPS context.
- Message mode scores weighted language indicators and combinations for credential theft, KYC/bank impersonation, payment/refund/UPI fraud, and job/investment fraud. It does not run URL-structure rules.
- `public/` contains the unchanged Express-served UI, with validation messages, evidence, categories, safe actions, and five demo cases using the real API.
- `data/dataset.js` contains 100 labelled examples (50 legitimate, 50 suspicious). `evaluate.js` runs the real analyzer over all examples.

## API

`POST /api/analyze` accepts:

```json
{ "type": "message", "content": "text to inspect" }
```

or `{ "type": "url", "content": "https://example.com" }`.

The response includes `riskScore` (0–100), `riskLevel`, `scamCategory`, `detectedIndicators` with evidence, `indicatorDetails` with weights, and `recommendedActions`. Invalid URL input returns HTTP 400 and is never assigned a risk score.

## Verification

```bash
npm test
npm run evaluate
```

The evaluation command prints measured precision, recall, F1, false-positive rate, and a confusion matrix from the checked-in labelled dataset. Results are intentionally generated at run time rather than written as claims here.

Latest local run (`npm run evaluate`, 100 examples): precision **1.00**, recall **0.90**, F1 **0.9474**, false-positive rate **0.00**. Confusion matrix: TP **45**, TN **50**, FP **0**, FN **5**. These are measurements on this small checked-in dataset only, not a production benchmark.

## Limitations

This is a transparent screening aid, not a fraud determination. It does not resolve domains, check reputation, inspect page content, or replace independent verification. Rule-based detectors can miss new wording and may flag legitimate messages that use similar language. HTTPS indicates transport encryption only, not trustworthiness. The small demo dataset is not representative of production traffic; metrics should not be generalized beyond it.
