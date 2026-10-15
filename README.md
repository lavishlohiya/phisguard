# PhishGuard

PhishGuard screens messages and URLs without fetching the supplied URL. URL detection combines transparent structural rules and a trained scikit-learn model using character-level TF-IDF, structural URL features, and Logistic Regression. Inputs may be `example.com`, `www.example.com`, `http://...`, or `https://...`; they are normalized consistently.

## Run

```bash
npm.cmd install
npm.cmd test
npm.cmd start
```

The existing API and frontend remain at `POST /api/analyze`, `POST /api/batch-analyze`, and `http://localhost:3000`.

## Reproduce the URL model

Python 3.10+ is required. The preparation script downloads verified online phishing URLs from [PhishTank](https://www.phishtank.com/) and legitimate-domain examples from the current [Tranco research ranking](https://tranco-list.eu/). It does not visit any URL.

```bash
python -m pip install --user -r requirements.txt
python prepare_url_dataset.py --phishing-limit 5000 --legitimate-limit 5000
python train_url_model.py --data data/url_dataset.jsonl --model data/url_model.joblib --seed 42
```

The model command prints metrics from a stratified 80/20 holdout and writes the local artifact to `data/url_model.joblib`. Dataset and model artifacts are intentionally gitignored because the source feeds change. If the artifact is absent, the API continues with the local URL rules and reports the model as unavailable.

The run performed during development used 10,000 samples (5,000 per class), seed 42, and 2,000 held-out URLs. Accuracy was **0.9785**, precision **0.9868**, recall **0.9700**, and F1 **0.9783**; the confusion matrix was `[[987, 13], [30, 970]]`. These are measurements on that dated source snapshot, not a production benchmark.

## Safety and scope

Known legitimate domains are not blindly trusted: verified-domain handling only prevents model false positives for the configured domains, while deceptive subdomains, typo-squats, IP hosts, suspicious paths, encodings, ports, and high-risk TLDs remain inspectable. HTTPS is treated as transport encryption, not proof of legitimacy. The detector is a screening aid and does not resolve domains or inspect page content.
