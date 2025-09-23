#!/usr/bin/env python3
import json
import hashlib
import os
import requests
from kafka import KafkaProducer

# Kafka
producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

# Constants
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HASH_FILE = "/tmp/kev_hash.txt"

def load_prev_hashes():
    if not os.path.exists(HASH_FILE):
        return set()
    with open(HASH_FILE, "r") as f:
        return set(line.strip() for line in f)

def persist_hashes(hashes):
    with open(HASH_FILE, "w") as f:
        for h in sorted(hashes):
            f.write(h + "\n")

def fetch_and_diff():
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])

    old_hashes = load_prev_hashes()
    new_hashes = set()
    to_send = []

    for v in vulns:
        # Hash using CVE ID and dateAdded for consistency
        h = hashlib.sha256((v["cveID"] + v["dateAdded"]).encode()).hexdigest()
        new_hashes.add(h)
        if h not in old_hashes:
            to_send.append(v)

    if not to_send:
        print("No new KEV records found.")
        return

    # Send new records to Kafka
    for v in to_send:
        producer.send("feed.kev", value=v)

    producer.flush()
    persist_hashes(new_hashes)
    print(f"Published {len(to_send)} new KEV records to Kafka (feed.kev)")

if __name__ == "__main__":
    fetch_and_diff()
