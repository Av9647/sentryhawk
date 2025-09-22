#!/usr/bin/env python3
import csv
import gzip
import hashlib
import json
import requests
from io import BytesIO
from datetime import datetime, timezone
from kafka import KafkaProducer

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
HASH_FILE = "/tmp/epss_hash.txt"
DATE = datetime.now(timezone.utc).strftime("%Y-%m-%d")

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

def fetch_and_hash():
    resp = requests.get(EPSS_URL, timeout=30)
    resp.raise_for_status()
    data = resp.content
    hash_now = hashlib.sha256(data).hexdigest()
    try:
        with open(HASH_FILE, "r") as f:
            last_hash = f.read().strip()
    except FileNotFoundError:
        last_hash = None
    if hash_now == last_hash:
        print("No update in EPSS feed.")
        return
    with open(HASH_FILE, "w") as f:
        f.write(hash_now)
    with gzip.open(BytesIO(data), 'rt') as f:
        reader = csv.DictReader(line for i, line in enumerate(f) if i != 0)
        for row in reader:
            record = {
                "cve": row["cve"],
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
                "date": DATE
            }
            producer.send("feed.epss", value=record)
    producer.flush()
    print(f"Published EPSS records to Kafka.")

if __name__ == "__main__":
    fetch_and_hash()
