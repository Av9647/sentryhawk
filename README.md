# Real-time Cyber Threat Intel Platform

## Overview
This project is a data engineering solution designed to aggregate and analyze cybersecurity threat data from multiple public APIs. 
By computing a cumulative threat exposure metric, the system provides actionable insights into the evolving risk landscape, 
aiding security teams in proactive threat management.

## Objectives
- **Data Ingestion:** Daily extraction of threat data (e.g., vulnerabilities, exposed assets) from APIs like CIRCL CVE Search and VirusTotal.
- **Data Transformation:** Process and compute a daily weighted threat score using recursive aggregation techniques.
- **Data Loading & Visualization:** Store the processed data in a scalable data warehouse and visualize trends using dashboards.

## Data Sources
- **CIRCL CVE Search API:** Provides detailed vulnerability information including CVSS scores.

  List All Vendors:
    • Endpoint: https://cve.circl.lu/api/browse
    • Description: Retrieves a JSON-formatted list of all vendors with known vulnerabilities.

  List Products by Vendor:
    • Endpoint: https://cve.circl.lu/api/browse/{vendor}
    • Example: https://cve.circl.lu/api/browse/microsoft
    • Description: Fetches all products associated with a specified vendor.
    
  Search CVEs by Product:
    • Endpoint: https://cve.circl.lu/api/search/{vendor}/{product}
    • Example: https://cve.circl.lu/api/search/microsoft/office
    • Description: Retrieves vulnerabilities related to a specific vendor and product.
    
  Retrieve Specific CVE Details:
    • Endpoint: https://cve.circl.lu/api/cve/{CVE-ID}
    • Example: https://cve.circl.lu/api/cve/CVE-2010-3333
    • Description: Provides detailed information about a particular CVE.
        
  Get Latest CVEs:
    • Endpoint: https://cve.circl.lu/api/last
    • Description: Returns the most recent 30 CVEs, including additional context.
    
  Database Information:
    • Endpoint: https://cve.circl.lu/api/dbInfo
    • Description: Offers metadata about the current CVE database, such as last update times.

  References:
  Vulnerability-Lookup Documentation: https://www.vulnerability-lookup.org/documentation/index.html
  About Page: https://cve.circl.lu/about
  Real-time JSON Dumps: https://vulnerability.circl.lu/dumps/

- **VirusTotal API:** Offers insights into file, URL, and IP reputations.
- **BinaryEdge/Censys:** (Planned) To count exposed assets and scan for misconfigurations.

## Architecture & Workflow
- **ETL Pipeline:** Orchestrated using Apache Airflow with separate DAGs for ingestion, transformation, and loading.
- **Recursive Aggregation:** SQL recursive CTEs compute cumulative threat exposure similar to stock price cumulative metrics.
- **Deployment:** Containerized using Docker and set up with CI/CD pipelines for automated testing and deployment.

## Future Enhancements
- Integration of real-time data streaming.
- Expansion to additional threat intelligence sources.
- Advanced analytics and alerting mechanisms.

