#!/usr/bin/env python3
import json
import hashlib
import requests
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HASH_FILE = "/tmp/kev_hash.txt"

def fetch_and_hash():
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    text = resp.text
    hash_now = hashlib.sha256(text.encode()).hexdigest()
    try:
        with open(HASH_FILE, "r") as f:
            last_hash = f.read().strip()
    except FileNotFoundError:
        last_hash = None
    if hash_now == last_hash:
        print("No update in KEV feed.")
        return
    with open(HASH_FILE, "w") as f:
        f.write(hash_now)
    kev_data = resp.json().get("vulnerabilities", [])
    for record in kev_data:
        producer.send("feed.kev", value=record)
    producer.flush()
    print(f"Published {len(kev_data)} KEV records to Kafka.")

if __name__ == "__main__":
    fetch_and_hash()
