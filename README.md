# Cybersecurity Threat Intelligence Project

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

