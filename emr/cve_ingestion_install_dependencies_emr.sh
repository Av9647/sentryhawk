#!/bin/bash
set -eux

# 1) Where to drop the jars so Spark driver & executors pick them up
SPARK_JAR_DIR=/usr/lib/spark/jars

# 2) S3 bucket/path where you uploaded your jars
S3_BASE=s3://cve-code/emr

# 3) List of jars to install
JARS=(
  bundle-2.29.5.jar
  iceberg-aws-bundle-1.9.0.jar
  iceberg-spark-runtime-3.5_2.12-1.9.0.jar
)

# 4) Make sure the dir exists
sudo mkdir -p "${SPARK_JAR_DIR}"
sudo chown hadoop:hadoop "${SPARK_JAR_DIR}"

# 5) Copy each jar from S3
for J in "${JARS[@]}"; do
  aws s3 cp "${S3_BASE}/${J}" "${SPARK_JAR_DIR}/${J}"
done

# 6) Install boto3 for any Python scripts
sudo pip3 install --upgrade boto3
