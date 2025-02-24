import requests
import sqlite3

# API endpoint for latest CVEs
api_url = "https://cve.circl.lu/api/last"

# Fetch data from API
response = requests.get(api_url)
if response.status_code == 200:
    cve_list = response.json()  # This should be a list of CVEs
else:
    print(f"Error fetching data: {response.status_code}")
    exit()

# Connect to SQLite database (Replace with PostgreSQL/MySQL as needed)
conn = sqlite3.connect("cyber_threats.db")
cursor = conn.cursor()

# Create the table if it doesn't exist
cursor.execute("""
    CREATE TABLE IF NOT EXISTS staging_cve (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT UNIQUE,
        description TEXT,
        published_date TEXT,
        vendor TEXT,
        product TEXT,
        version TEXT,
        modules TEXT,
        cvss_score_v4 REAL,
        cvss_score_v3 REAL,
        cvss_score_v2 REAL,
        reference_links TEXT  -- ✅ Renamed from "references" to avoid reserved keyword issue
    )
""")

conn.commit()

# Process & Insert Data
valid_cves = []
for cve in cve_list:
    cve_id = cve.get("cveMetadata", {}).get("cveId")
    descriptions = cve.get("containers", {}).get("cna", {}).get("descriptions", [])
    published_date = cve.get("cveMetadata", {}).get("datePublished")

    # Get the first English description, if available
    description = next((desc["value"] for desc in descriptions if desc.get("lang") == "en"), "No description available")

    # Vendor, Product, and Version Info (Extract first affected component)
    affected = cve.get("containers", {}).get("cna", {}).get("affected", [{}])
    vendor = affected[0].get("vendor", "Unknown")
    product = affected[0].get("product", "Unknown")
    version = affected[0].get("versions", [{}])[0].get("version", "Unknown")
    modules = ", ".join(affected[0].get("modules", [])) if affected[0].get("modules") else "N/A"

    # CVSS Scores (Extract latest available version)
    metrics = cve.get("containers", {}).get("cna", {}).get("metrics", [])
    cvss_v4 = next((m["cvssV4_0"]["baseScore"] for m in metrics if "cvssV4_0" in m), None)
    cvss_v3 = next((m["cvssV3_1"]["baseScore"] for m in metrics if "cvssV3_1" in m), None)
    cvss_v2 = next((m["cvssV2_0"]["baseScore"] for m in metrics if "cvssV2_0" in m), None)

    # References (Collect all URLs)
    references = cve.get("containers", {}).get("cna", {}).get("references", [])
    reference_urls = ", ".join([ref["url"] for ref in references if "url" in ref])

    # Only store valid CVEs
    if cve_id and description and cve_id != "N/A":
        valid_cves.append((cve_id, description, published_date, vendor, product, version, modules, cvss_v4, cvss_v3, cvss_v2, reference_urls))

# Insert valid CVEs into the database
cursor.executemany("""
    INSERT OR IGNORE INTO staging_cve (
        cve_id, description, published_date, vendor, product, version, modules, 
        cvss_score_v4, cvss_score_v3, cvss_score_v2, reference_links
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""", valid_cves)

conn.commit()
conn.close()

# Print only valid entries
for cve in valid_cves:
    print(f"CVE ID: {cve[0]}")
    print(f"Description: {cve[1]}")
    print(f"Published Date: {cve[2]}")
    print(f"Vendor: {cve[3]}")
    print(f"Product: {cve[4]} (Version: {cve[5]})")
    print(f"Modules: {cve[6]}")
    print(f"CVSS Scores - V4: {cve[7] if cve[7] else 'N/A'}, V3: {cve[8] if cve[8] else 'N/A'}, V2: {cve[9] if cve[9] else 'N/A'}")
    print(f"References: {cve[10]}")
    print("-" * 80)
