"""Download and prepare a reproducible URL dataset from public sources.

PhishTank supplies verified phishing URLs. Tranco supplies a research-backed
ranking of popular domains; only its domains are used to create legitimate
homepage examples. No URLs are visited by this script.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import random
import urllib.request
import zipfile
from pathlib import Path

PHISHTANK_URL = "https://www.phishtank.com/data/online-valid.csv"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "PhishGuard dataset preparation"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def phishtank_urls(raw: bytes, limit: int) -> list[str]:
    text = raw.decode("utf-8-sig", errors="replace")
    rows = csv.DictReader(io.StringIO(text))
    values = []
    for row in rows:
        url = (row.get("url") or "").strip()
        if url.startswith(("http://", "https://")) and url not in values:
            values.append(url)
        if len(values) >= limit:
            break
    return values


def tranco_domains(raw: bytes, limit: int) -> list[str]:
    if raw[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            csv_name = next(name for name in archive.namelist() if name.endswith(".csv"))
            text = archive.read(csv_name).decode("utf-8-sig", errors="replace")
    else:
        text = raw.decode("utf-8-sig", errors="replace")
    values = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2:
            continue
        domain = (row[1] if len(row) > 1 else row[0]).strip().lower().rstrip(".")
        if domain and " " not in domain and domain not in values:
            values.append(domain)
        if len(values) >= limit:
            break
    return values


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phishing-limit", type=int, default=10000)
    parser.add_argument("--legitimate-limit", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=Path("data/url_dataset.jsonl"))
    args = parser.parse_args()

    phishing = phishtank_urls(download(PHISHTANK_URL), args.phishing_limit)
    domains = tranco_domains(download(TRANCO_URL), args.legitimate_limit)
    rows = ([{"url": url, "label": 1, "source": "PhishTank online-valid"} for url in phishing] +
            [{"url": f"https://{domain}/", "label": 0, "source": "Tranco top domains"} for domain in domains])
    random.Random(args.seed).shuffle(rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as output:
        for row in rows:
            output.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps({"output": str(args.output), "phishing": len(phishing), "legitimate": len(domains), "seed": args.seed}))


if __name__ == "__main__":
    main()
