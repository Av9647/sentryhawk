# Sentryhawk — Real-time CVE Intel Platform

![status](https://img.shields.io/badge/status-Production-green) ![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)

Sentryhawk is a cloud-native cybersecurity intelligence platform that aggregates and enriches public vulnerability (CVE) data from multiple feeds. It computes a cumulative Exposure Index (an aggregated CVSS-based score) to highlight where software flaws are clustering. By turning scattered threat data into structured, continuously updated insights, Sentryhawk helps security teams proactively prioritize patching and mitigation before adversaries can exploit issues. Real-world breaches (e.g. Log4Shell, WannaCry) often stem from known but unpatched vulnerabilities. Sentryhawk aims to give organizations the clarity to see the next breach before it happens. The platform’s value lies in surfacing actionable intelligence – global, vendor and product-specific risk trends – so that defenders can make informed decisions in a rapidly evolving threat landscape.

## Features

- **Interactive Dashboards**: Out-of-the-box Superset dashboards show global vulnerability trends, vendor-specific risk rankings, and product-level details. Users can filter by year or vendor and see visualizations of new CVEs and exposure scores. Dashboards are publicly sharable and support alerts/reports. The stack is fully open-source, providing sub-second query latency on aggregated views.

  ![Global View](assets/global_view.png)

- **Exposure Index**: A composite score aggregating CVSS severity across all known CVEs for a vendor/product. The Exposure Index highlights which vendors or products have an unusually high concentration of vulnerabilities. Teams can use it to prioritize patching or inventory audits where the index is high.

- **Normalization & Deduplication**: Sentryhawk automatically cleans and merges overlapping feeds. Inconsistent vendor/product naming conventions are harmonized so that the same entity isn’t counted twice. This avoids false inflation of vulnerability counts and ensures the Exposure Index is meaningful.

  ![Drill Down](assets/drill_down.png)

- **KEV & EPSS Integration**: The platform ingests the CISA’s Known Exploited Vulnerabilities (KEV) feed and the NIST EPSS CSV each run. CVEs present in the KEV list are highlighted in dashboards, and EPSS scores are attached to CVE records. This emphasizes vulnerabilities with known exploits or high expected exploitability.

  ![KEV](assets/kev.png)

- **Open Source Stack**: All components are based on OSS (Python, MongoDB, Druid, Redis, Superset, etc.), with infrastructure defined in code. The result is a cost-effective, extensible system that any organization can audit and extend. All services run in Docker containers, enabling easy upgrades and community contributions.

## Data Pipeline Architecture

The deployed Sentryhawk pipeline is fully managed in AWS and consists of these stages:

1. **Trigger & Orchestration (EventBridge + Step Functions)**: An Amazon EventBridge scheduled rule (cron) triggers the data pipeline at fixed intervals. This invokes an AWS Step Functions state machine, which orchestrates all downstream processing. Step Functions handles sequencing, retry logic, and error handling for the entire workflow.

  ![Sentryhawk Architecture](assets/high_level.png)

2. **Change Data Capture Engine (CDC)**: At the start of each run, the pipeline uses AWS Systems Manager to start an EC2 backend server. This instance runs Docker containers for MongoDB and a CVE-search service. A script on the instance fetches the latest CVE data from the NVD API and the cvelistV5 GitHub repository. A MongoDB map-diff process then determines which vendor–product combinations have new, removed, or changed CVEs. These differences are sent as messages to an Amazon SQS Product Queue. If any tasks fail to process, they go to a dead-letter queue. Unprocessed items in the DLQ are logged and an SNS alert is sent to administrator.

  ![Scalable Ingestion](assets/ingestion.png)

3. **Scalable Ingestion (SQS + Lambda)**: Messages in the SQS queue drive the ingestion of product JSON data. AWS Lambda functions take each vendor–product message and call the external Vulnerability Lookup API to retrieve detailed CVE JSON data for that vendor/product. The raw JSON results are stored in an S3 ingestion bucket.

4. **ETL and Data Quality (AWS Glue)**: The raw JSON files are then processed by a sequence of AWS Glue jobs. The jobs run in order:
    
    - **Merge JSONs**: Combine the raw files into NDJSONs.
    - **Staging Load**: Ingest the merged data into a staging Iceberg table in S3.
    - **Data Quality Check**: Validate data (e.g. schema, null checks) on the staging table.
    - **Production Load**: Merge staging into the production Iceberg table using Slowly-Changing-Dimension Type II logic, so that historical CVE records are preserved.
    
    If any Glue job fails or finds critical issues, the pipeline pauses and an SNS notification is sent to the admin.

5. **Materialized Views (Amazon EMR)**: After the production data is updated, the Step Function launches an Amazon EMR Spark cluster. This cluster computes pre-aggregated materialized views (for example, aggregations of CVSS scores by vendor/product, exposure indices, etc.) using Spark. The resulting views in parquet are written to S3. The EMR cluster then terminates automatically to minimize cost.

  ![Data Processing](assets/processing.png)

6. **Analytics Update (Druid & ECS)**: Finally, the pipeline refreshes the analytics layer. The EC2 instance hosting Apache Druid is scaled up. A containerized ingestion task runs on Amazon ECS using a Docker image from Amazon ECR to load the new materialized views into Druid. Once the fresh data is ingested, the EC2 analytics server is scaled back down. This ensures that the Apache Superset dashboards always query up-to-date data with low latency.

  ![Analytics and Visualization](assets/analytics.png)

Throughout the pipeline, Amazon SNS and CloudWatch provide monitoring and alerting. Any step failure triggers an SNS alert so administrators can investigate, ensuring reliability and transparency.

## Setup & Deployment

The Sentryhawk repository includes all configuration and code needed for deployment. In summary, a typical setup involves:

1. **Launch an EC2 Host**: Start an EC2 instance (e.g. Amazon Linux 2, c5.xlarge or larger) and install Docker & Docker Compose:

    ```
    sudo yum update -y
    sudo yum install git -y
    sudo amazon-linux-extras install docker -y
    sudo systemctl start docker && sudo systemctl enable docker
    sudo usermod -aG docker ec2-user
    # Install Docker Compose (v2 plugin)
    mkdir -p ~/.docker/cli-plugins
    curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 \
      -o ~/.docker/cli-plugins/docker-compose
    chmod +x ~/.docker/cli-plugins/docker-compose
    ```

    Also obtain an NVD API key (from https://nvd.nist.gov/developers/request-an-api-key) for the CIRCL CVE search component.

2. **Configure Environment**: Clone the CVE-Search pipeline repo:

    ```
    git clone https://github.com/cve-search/CVE-Search-Docker.git
    cd CVE-Search-Docker
    ```

    Copy the provided configuration files into the root directory: docker-compose.yml, .config.yml, Dockerfile.api, cve_backfill.sh, cve_mongo_map_backup.sh, cve_sqs_log.py, etc. Populate your environment (e.g. in a .env file or via export) with the required secrets and endpoints. For example, set your NVD API key and other variables:

    ```
    NVD_NIST_API_KEY="<YOUR_NVD_KEY>"
    MONGO_URI="mongodb://mongo:27017/"
    DB_NAME="cvedb"
    CVELIST_COLL="cvelistv5"
    NVD_COLL="cves"
    MAP_NVD_COLL="map_vendor_product_nvd"
    MAP_CVELIST_COLL="map_vendor_product_cvelistv5"
    DELTA_QUEUE_URL="https://sqs.<REGION>.amazonaws.com/<ACCOUNT_ID>/<QUEUE_NAME>"
    ```

3. **Build & Launch CVE Services**: Run the Docker Compose services:

    ```
    docker compose build --no-cache
    docker compose up -d mongo redis cve_search
    ```

    Wait a few minutes for MongoDB and Redis to start. Then execute the initial backfill to load all historical vulnerability feeds:

    ```
    chmod +x cve_backfill.sh
    nohup ./cve_backfill.sh > cve_backfill.log 2>&1 &
    tail -f cve_backfill.log
    ```

    This populates MongoDB with NVD, CVE-List V5, and other CVE sources, and builds the vendor–product mapping collections. Once finished, start the lookup API container:

    ```
    docker compose up -d vendor_product_api
    ```

    You can verify the API is running by querying `http://<EC2-IP>:8000/api/search/{vendor}/{product}`

4. **Setup ETL Workflow on AWS**: In the AWS console or via IaC, create: an S3 bucket for ingestion data, an SQS queue with DLQ for changed keys, and an AWS Step Functions state machine using the provided JSON definition (step_functions/sentryhawk_state_machine.json). Attach an IAM role granting access to S3, SQS, Glue, EMR, etc. Configure an EventBridge Scheduled rule to trigger the Step Function daily. The Step Function uses AWS Systems Manager (Run Command) to launch the Docker-based services (MongoDB + CVE-Search) and run the CDC job each cycle.

5. **Data Transformation**: The workflow will launch the AWS Glue jobs (also provided in glue/ scripts) to transform the NDJSON data into Parquet, run DQ checks, and apply Type 2 merges. After that, it fires up an EMR Spark cluster (using the emr/ scripts) to generate the final materialized view tables. Verify that the Glue and EMR steps complete successfully. SNS alerts will notify you on failure for any step.

6. **Deploy Analytics Stack**: Build the Druid ingestion image from the druid/ directory:

    ```
    docker build -t cve-ingestion-druid:latest druid/cve-ingestion-druid
    ```

    Tag and push this image to your ECR repository (sentryhawk_repo):

    ```
    aws ecr get-login-password --region <REGION> | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com
    docker tag cve-ingestion-druid:latest <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/sentryhawk_repo:cve-ingestion-druid
    docker push <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/sentryhawk_repo:cve-ingestion-druid
    ```

    (Adjust <REGION> and <ACCOUNT_ID> for your AWS account.). Next, run this image as a task on ECS to ingest the materialized views into Apache Druid.

7. **Configure Superset**: Launch a PostgreSQL RDS instance for Superset’s metadata. In your Docker setup, place superset_config.py (customized for the RDS host and credentials) alongside the docker-compose.yml. In .env, set the DATABASE_ variables to point Superset at the RDS (for example, DATABASE_HOST, DATABASE_USER, etc.). Then run Superset and Redis via Docker:

    ```
    docker compose up -d superset redis
    ```

    Initialize the Superset DB `superset db upgrade`, create an admin user, and import the included dashboards `superset import-dashboards -p dashboards`.

8. **Domain and Security**: Finally, configure DNS and CDN. Point your domain (e.g. example.com) to a CloudFront distribution in front of the EC2 instance running Superset. Use ACM to attach an SSL certificate. Enable WAF rules. The documentation provides a CloudFront Function that forces “www” and rewrites / to the Superset dashboard home. Redact any account-specific details (like IPs or ARNs) when you publish your config.

**Note**: The above steps outline a complete deployment. All sensitive values (API keys, passwords, ARNs) should be replaced with placeholders or stored in secrets managers.

## License
Released under the [Apache License 2.0](./LICENSE).  
© 2025 Athul Vinod — [sentryhawk.org](https://www.sentryhawk.org)

## Disclaimer
*Sentryhawk is an independent open-source project and is not affiliated with, endorsed by,  
or associated with any commercial entity of the same or similar name, if one exists.*
