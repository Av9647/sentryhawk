#!/usr/bin/env python3
import csv
import gzip
import hashlib
import json
import os
import requests
import time
from io import BytesIO
from datetime import datetime, timezone
from kafka import KafkaProducer

# Constants
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
HASH_FILE = "/tmp/epss_hash.txt"
DATE = datetime.now(timezone.utc).strftime("%Y-%m-%d")

# Kafka setup
producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

def on_send_success(record_metadata):
    print(f"[Kafka] Sent to {record_metadata.topic} partition {record_metadata.partition} offset {record_metadata.offset}")

def on_send_error(excp):
    print(f"[Kafka ERROR] Failed to send message: {excp}")

def drop_epss_druid_table():
    druid_url = "http://localhost:8081/druid/coordinator/v1/datasources/epss_scores"
    print("Dropping Druid table epss_scores...")
    resp = requests.delete(druid_url, params={"cascade": "true"})
    if resp.status_code not in (200, 202, 404):
        resp.raise_for_status()
    
    # Wait for table to disappear
    for _ in range(60):
        tables = requests.get("http://localhost:8081/druid/coordinator/v1/datasources").json()
        if "epss_scores" not in tables:
            print("✔ epss_scores table dropped.")
            return
        time.sleep(5)
    raise RuntimeError("Timed out waiting for epss_scores to drop.")

def fetch_and_maybe_publish():
    print("Fetching EPSS feed...")
    resp = requests.get(EPSS_URL, timeout=30)
    resp.raise_for_status()
    raw_data = resp.content
    hash_now = hashlib.sha256(raw_data).hexdigest()

    # Check if hash has changed
    last_hash = None
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, "r") as f:
            last_hash = f.read().strip()

    if hash_now == last_hash:
        print("No update in EPSS feed. Skipping publish.")
        return

    # Drop old Druid table
    drop_epss_druid_table()

    # Save new hash
    with open(HASH_FILE, "w") as f:
        f.write(hash_now)

    # Parse and publish to Kafka
    print("Publishing updated EPSS records to Kafka...")
    count = 0
    error_count = 0
    with gzip.open(BytesIO(raw_data), 'rt') as f:
        lines = (line for line in f if not line.startswith("#"))
        reader = list(csv.DictReader(lines))
        print(f"Total records parsed from CSV: {len(reader)}")

        for i, row in enumerate(reader):
            try:
                record = {
                    "cve": row["cve"],
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                    "date": DATE
                }
                producer.send("feed.epss", value={
                    "cve": row["cve"],
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                    "date": DATE
                })
                count += 1
            except Exception as e:
                print(f"[WARN] Row {i} skipped due to error: {e}")
                error_count += 1

    producer.flush()
    print(f"✔ Published {count} EPSS records to Kafka (feed.epss)")
    if error_count > 0:
        print(f"{error_count} rows were skipped due to errors")

if __name__ == "__main__":
    fetch_and_maybe_publish()
