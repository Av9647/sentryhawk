import requests
import json
from datetime import datetime

BASE_URL = "https://cve.circl.lu/api"

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
    Fetch CVE data for a given vendor and product from the CIRCL CVE Search API.
    """
    url = f"{BASE_URL}/search/{vendor}/{product}"
    response = requests.get(url)
    if response.status_code == 200:
        cve_data = response.json()
        print(f"Fetched CVE data for {vendor} - {product}:")
        print(json.dumps(cve_data, indent=2))
        return cve_data
    else:
        print(f"Error fetching CVE data for {vendor} - {product}: {response.status_code}")
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
        # For brevity, printing a summary of keys rather than full JSON
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
      - cve_id: From details["cve"] if available, otherwise fall back to the first element.
      - published_date: First, try details["containers"]["cna"]["datePublic"]. 
                        If absent, fallback to the "sources_release_date" array using this order:
                        NVD > CNNVD > BID > JVNDB.
                        Format the date as "YYYY-MM-DD".
                        
    Returns a list of dictionaries with the processed fields.
    """
    processed_records = []
    records = response_json.get("cvelistv5", [])
    
    # Define the fallback order for sources_release_date.
    fallback_order = ["NVD", "CNNVD", "BID", "JVNDB"]
    
    for pair in records:
        if isinstance(pair, list) and len(pair) == 2 and isinstance(pair[1], dict):
            details = pair[1]
            # Use details["cve"] if available; if not, use the first element.
            cve_id = details.get("cve", pair[0])
            
            published_date = None
            # Primary: try to get the datePublic field from containers -> cna.
            try:
                containers = details.get("containers", {})
                cna = containers.get("cna", {})
                date_public_str = cna.get("datePublic")
                if date_public_str:
                    # Handle potential timezone info: replace "Z" with "+00:00" if present.
                    if date_public_str.endswith("Z"):
                        date_public_str = date_public_str[:-1] + "+00:00"
                    dt = datetime.fromisoformat(date_public_str)
                    published_date = dt.strftime("%Y-%m-%d")
            except Exception as e:
                print(f"Error parsing datePublic for {cve_id}: {e}")
            
            # Fallback: if published_date is still None, use sources_release_date.
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
                    # If none found, simply use the first available date.
                    if not selected_date_str and len(sr_release_data) > 0:
                        selected_date_str = sr_release_data[0].get("date")
                    if selected_date_str:
                        try:
                            dt = datetime.strptime(selected_date_str, "%Y-%m-%dT%H:%M:%S")
                            #published_date = dt.strftime("%Y-%m-%d")
                        except Exception as e:
                            print(f"Error parsing fallback published date for {cve_id}: {e}")
            
            processed_records.append({
                "cve_id": cve_id,
                "published_date": dt
            })
        else:
            print("Skipping unexpected record format:", pair)
    
    return processed_records

def main():
    vendor = "microsoft"
    product = "office"
    cve_response = fetch_cve_data(vendor, product)
    if cve_response:
        processed = process_cve_records_variot(cve_response)
        print("Processed CVE Records:")
        print(json.dumps(processed, default=str, indent=2))
    else:
        print("No CVE data fetched.")

if __name__ == "__main__":
    main()
