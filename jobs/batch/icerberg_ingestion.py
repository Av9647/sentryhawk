import requests
import json
from datetime import datetime

BASE_URL = "https://cve.circl.lu/api"
STAGING_FILE = "staging.jsonl"  # File to simulate our staging table

def fetch_vendor_list():
    """
    Fetch the list of vendors from the CIRCL CVE Search API.
    """
    url = f"{BASE_URL}/browse"
    response = requests.get(url)
    if response.status_code == 200:
        vendors = response.json()
        print("Fetched vendors:")
        print(json.dumps(vendors, indent=2))
        return vendors
    else:
        print("Error fetching vendor list:", response.status_code)
        return None

def fetch_product_list(vendor):
    """
    Fetch the list of products for a given vendor from the CIRCL CVE Search API.
    """
    url = f"{BASE_URL}/browse/{vendor}"
    response = requests.get(url)
    if response.status_code == 200:
        products = response.json()
        print(f"Fetched products for {vendor}:")
        print(json.dumps(products, indent=2))
        return products
    else:
        print(f"Error fetching products for {vendor}: {response.status_code}")
        return None

def fetch_cve_data(vendor, product):
    """
    Fetch CVE data for a given vendor and product.
    """
    url = f"{BASE_URL}/search/{vendor}/{product}"
    response = requests.get(url)
    if response.status_code == 200:
        cve_data = response.json()
        print(f"Fetched CVE data for {vendor} - {product}:")
        # For brevity, print only the first 1000 characters of the JSON response.
        print(json.dumps(cve_data, indent=2)[:1000])
        return cve_data
    else:
        print(f"Error fetching CVE data for {vendor} - {product}: {response.status_code}")
        return None

def process_cve_records_variot(response_json):
    """
    Process the variotdbs CVE data response.

    Expected structure:
      {
         "cvelistv5": [
             [ variot_id (str), details (dict) ],
             ...
         ]
      }

    For each record, extract:
      - cve_id: From details["cve"] if available; otherwise, use the first element.
      - published_date: First, try details["containers"]["cna"]["datePublic"]. 
                        If absent, fall back to the "sources_release_date" array using the order:
                        NVD > CNNVD > BID > JVNDB.
                        The date is formatted as "YYYY-MM-DD".
      - date_updated: From details["cveMetadata"]["dateUpdated"] (formatted as "YYYY-MM-DD").
      - base_score and base_severity: Extracted from the metrics under containers -> cna.
        We first look for a "cvssV3_1" block, then "cvssV3", and lastly "cvssV2" (with a derived severity if needed).

    Returns a list of dictionaries with keys: cve_id, published_date, date_updated, base_score, and base_severity.
    """
    processed_records = []
    records = response_json.get("cvelistv5", [])
    
    # Fallback order for sources_release_date.
    fallback_order = ["NVD", "CNNVD", "BID", "JVNDB"]
    
    for pair in records:
        if isinstance(pair, list) and len(pair) == 2 and isinstance(pair[1], dict):
            details = pair[1]
            # Use details["cve"] if available; if not, use the first element.
            cve_id = details.get("cve", pair[0])
            
            published_date = None
            # Primary: try to get datePublic from containers -> cna.
            try:
                containers = details.get("containers", {})
                cna = containers.get("cna", {})
                date_public_str = cna.get("datePublic")
                if date_public_str:
                    if date_public_str.endswith("Z"):
                        date_public_str = date_public_str[:-1] + "+00:00"
                    dt_pub = datetime.fromisoformat(date_public_str)
                    published_date = dt_pub.strftime("%Y-%m-%d")
            except Exception as e:
                print(f"Error parsing datePublic for {cve_id}: {e}")
            
            # Fallback: use sources_release_date.
            if not published_date:
                sr_release_data = details.get("sources_release_date", {}).get("data", [])
                selected_date_str = None
                if sr_release_data and isinstance(sr_release_data, list):
                    for trusted_db in fallback_order:
                        for entry in sr_release_data:
                            if entry.get("db", "").upper() == trusted_db:
                                selected_date_str = entry.get("date")
                                break
                        if selected_date_str:
                            break
                    if not selected_date_str and len(sr_release_data) > 0:
                        selected_date_str = sr_release_data[0].get("date")
                    if selected_date_str:
                        try:
                            dt_pub = datetime.strptime(selected_date_str, "%Y-%m-%dT%H:%M:%S")
                            published_date = dt_pub.strftime("%Y-%m-%d")
                        except Exception as e:
                            print(f"Error parsing fallback published date for {cve_id}: {e}")
            
            # Extract dateUpdated from cveMetadata.
            date_updated = None
            try:
                cve_meta = details.get("cveMetadata", {})
                date_updated_str = cve_meta.get("dateUpdated")
                if date_updated_str:
                    if date_updated_str.endswith("Z"):
                        date_updated_str = date_updated_str[:-1] + "+00:00"
                    dt_upd = datetime.fromisoformat(date_updated_str)
                    date_updated = dt_upd.strftime("%Y-%m-%d")
            except Exception as e:
                print(f"Error parsing dateUpdated for {cve_id}: {e}")
            
            # Extract baseScore and baseSeverity from metrics.
            base_score = None
            base_severity = None
            try:
                metrics = details.get("containers", {}).get("cna", {}).get("metrics", [])
                if metrics and isinstance(metrics, list):
                    for metric in metrics:
                        if "cvssV3_1" in metric:
                            cvss = metric["cvssV3_1"]
                            base_score = cvss.get("baseScore")
                            base_severity = cvss.get("baseSeverity")
                            break
                        elif "cvssV3" in metric:
                            cvss = metric["cvssV3"]
                            base_score = cvss.get("baseScore")
                            base_severity = cvss.get("baseSeverity")
                            break
                        elif "cvssV2" in metric:
                            cvss = metric["cvssV2"]
                            base_score = cvss.get("baseScore")
                            # If baseSeverity is missing, derive it from baseScore.
                            if base_score is not None:
                                if base_score >= 9.0:
                                    base_severity = "CRITICAL"
                                elif base_score >= 7.0:
                                    base_severity = "HIGH"
                                elif base_score >= 4.0:
                                    base_severity = "MEDIUM"
                                else:
                                    base_severity = "LOW"
                            break
            except Exception as e:
                print(f"Error extracting metrics for {cve_id}: {e}")
            
            processed_records.append({
                "cve_id": cve_id,
                "published_date": published_date,
                "date_updated": date_updated,
                "base_score": base_score,
                "base_severity": base_severity
            })
        else:
            print("Skipping unexpected record format:", pair)
    
    return processed_records

def append_to_staging(records, vendor, product):
    """
    Append the given records (list of dicts) to the staging file.
    Each record is augmented with vendor and product.
    We store one JSON object per line.
    """
    with open(STAGING_FILE, "a", encoding="utf-8") as f:
        for rec in records:
            staging_record = {
                "vendor": vendor,
                "product": product,
                "cve_id": rec.get("cve_id"),
                "published_date": rec.get("published_date"),
                "date_updated": rec.get("date_updated"),
                "base_score": rec.get("base_score"),
                "base_severity": rec.get("base_severity")
            }
            f.write(json.dumps(staging_record) + "\n")
    print(f"Appended {len(records)} records for {vendor} - {product} to staging.")

def process_micro_batch(vendor, product):
    """
    Process a micro-batch: fetch CVE data for the given vendor and product,
    process the records, and append them to the staging table.
    """
    print(f"Processing micro-batch for vendor: {vendor}, product: {product}")
    cve_response = fetch_cve_data(vendor, product)
    if cve_response:
        processed_records = process_cve_records_variot(cve_response)
        append_to_staging(processed_records, vendor, product)
    else:
        print(f"No CVE data for vendor: {vendor}, product: {product}")

def main():
    # For demonstration, focus on vendor "microsoft" and product "office".
    vendor = "microsoft"
    product = "office"
    process_micro_batch(vendor, product)
    # Optionally, iterate over all vendors and products.
    # vendors = fetch_vendor_list()
    # for vendor in vendors:
    #     products = fetch_product_list(vendor)
    #     for product in products:
    #         process_micro_batch(vendor, product)

if __name__ == "__main__":
    main()
