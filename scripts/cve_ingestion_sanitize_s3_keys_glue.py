#!/usr/bin/env python3
import re
import boto3
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

# CONFIG
BUCKET      = "cve-ingestion"
SRC_PREFIX  = "cve_json/2025-05-03/"
DEST_PREFIX = "cve_json/2025-05-03_sanitized/"
MAX_WORKERS = 50

s3 = boto3.client("s3")

def normalize_component(comp: str) -> str:
    """
    1) Replace any character NOT in [A-Za-z0-9._-] with underscore.
    2) Strip any leading dots, dashes, or underscores so Spark will see the files.
    3) If the result is empty, fall back to an alphanumeric name.
    """
    safe = re.sub(r"[^A-Za-z0-9\._\-]", "_", comp)
    safe = re.sub(r"^[\._\-]+", "", safe)
    if not safe:
        safe = "file"
    return safe

def sanitize_key(key: str, src_prefix: str, dest_prefix: str) -> str:
    """
    Strip src_prefix, split on '/', normalize each piece,
    then re-join under dest_prefix.
    """
    suffix = key[len(src_prefix):]
    parts = suffix.split("/")
    safe_parts = [normalize_component(p) for p in parts]
    return dest_prefix + "/".join(safe_parts)

def list_all_keys(bucket: str, prefix: str):
    """Yield every key under the given prefix."""
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            yield obj["Key"]

def copy_object(src_key: str, dst_key: str):
    """
    Copy a single object; exceptions are caught and logged.
    """
    try:
        print(f"Copying: {src_key} → {dst_key}")
        s3.copy_object(
            Bucket=BUCKET,
            CopySource={"Bucket": BUCKET, "Key": src_key},
            Key=dst_key
        )
        return (src_key, True, None)
    except ClientError as e:
        return (src_key, False, str(e))

def main():
    keys = list(list_all_keys(BUCKET, SRC_PREFIX))
    print(f"Found {len(keys)} objects under {SRC_PREFIX}")

    # Prepare and run copy tasks in parallel
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for key in keys:
            new_key = sanitize_key(key, SRC_PREFIX, DEST_PREFIX)
            dst = new_key  # always write into DEST_PREFIX
            futures.append(executor.submit(copy_object, key, dst))

        # Gather results
        success = failure = 0
        for future in as_completed(futures):
            src_key, ok, err = future.result()
            if ok:
                success += 1
            else:
                failure += 1
                print(f"  ERROR copying {src_key}: {err}")

    print(f"Done. {success} succeeded, {failure} failed.")

if __name__ == "__main__":
    main()
