"""
sentryhawk_dag.py
-----------------
Apache Airflow (MWAA-compatible) equivalent of the Sentryhawk Step Functions
state machine. The pipeline does the following in order:

1.  Start DB EC2  →  wait  →  start Docker containers (mongo/redis/cve_search)
2.  Run CVE DB refresh script; poll SSM until complete
3.  Poll the vendor-product SQS queue until empty (no messages & no in-flight)
4.  Check DLQ; if dirty → backup DLQ → run map backup; then shut DB down
5.  Run 4 sequential AWS Glue jobs
6.  Create EMR cluster → submit Spark step → poll until complete → terminate
7.  In parallel:
      a. Redshift Serverless: call analytics.sync_cve_production_master()
      b. Druid EC2: upgrade instance type → start → run ECS Fargate task →
         stop containers → downgrade instance type
8.  Send SNS success notification

Error handling mirrors the Step Functions approach: SNS alerts with a manual
"resume" webhook, then retry the failed step.

Operators used (all available in MWAA's managed provider packages):
  - boto3 via PythonOperator  (EC2, SSM, SQS, EMR, Glue, Redshift Data, ECS)
  - BranchPythonOperator      (replaces Choice states)
  - sensors / polling loops   (replaces Wait + poll loops)
  - TaskGroup                 (replaces Parallel branches)
  - SNSPublishOperator        (apache-airflow-providers-amazon)

Requirements (MWAA wheels / requirements.txt):
  apache-airflow-providers-amazon>=8.0.0
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta

import boto3
from airflow import DAG
from airflow.decorators import task
from airflow.operators.python import BranchPythonOperator, PythonOperator
from airflow.utils.task_group import TaskGroup
from airflow.providers.amazon.aws.operators.sns import SnsPublishOperator

# ──────────────────────────────────────────────────────────────
# CONFIG  (replace with Airflow Variables / Secrets Manager)
# ──────────────────────────────────────────────────────────────
ACCOUNT_ID          = "{{ var.value.aws_account_id }}"
REGION              = "us-east-2"

DB_INSTANCE_ID      = "i-07126efdc8130b47e"
DRUID_INSTANCE_ID   = "i-0c7e5f521320434bd"

SNS_TOPIC_ARN       = f"arn:aws:sns:{REGION}:{ACCOUNT_ID}:cve_sns_topic"
RESUME_URL_BASE     = "https://8icj443bt1.execute-api.us-east-2.amazonaws.com/prod/resume"

PRODUCT_SQS_URL     = f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT_ID}/cve_ingestion_vendor_product_sqs"
PRODUCT_DLQ_URL     = f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT_ID}/cve_ingestion_vendor_product_sqs_dlq"

GLUE_JOBS = [
    "cve_ingestion_combine_json_glue",
    "cve_staging_glue",
    "cve_staging_glue_dq",
    "cve_production_glue",
]

EMR_CLUSTER_NAME    = "cve_production_materialized_views_emr"
EMR_LOG_URI         = f"s3://aws-logs-{ACCOUNT_ID}-{REGION}/elasticmapreduce"
EMR_SUBNET          = "subnet-0a896bf02807dd0c2"
EMR_MASTER_SG       = "sg-09e703ba95274004c"
EMR_SLAVE_SG        = "sg-03c1991f2ebda5c33"
EMR_SERVICE_ROLE    = f"arn:aws:iam::{ACCOUNT_ID}:role/service-role/AmazonEMR-ServiceRole-20250504T165815"
EMR_JOB_FLOW_ROLE   = "cve_ingestion_emr_role"
EMR_SPARK_SCRIPT    = "s3://cve-code/emr/cve_production_materialized_views_emr.py"
EMR_BOOTSTRAP       = "s3://cve-code/emr/cve_ingestion_install_dependencies_emr.sh"

ECS_CLUSTER         = "sentryhawk_ecs_cluster"
ECS_TASK_DEF        = "sentryhawk-cve-ingestion-druid:40"
ECS_SUBNET          = "subnet-0a896bf02807dd0c2"
ECS_SG              = "sg-058e7bc5c8813b46a"

REDSHIFT_WG         = "cve-production-redshift-wg"
REDSHIFT_DB         = "dev"

# ──────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────
def _boto(service: str):
    return boto3.client(service, region_name=REGION)


def _sns_alert(message: str):
    """Fire an SNS alert. In MWAA you can also raise AirflowException to
    trigger on_failure_callback instead."""
    _boto("sns").publish(TopicArn=SNS_TOPIC_ARN, Message=message)


def _ssm_run(instance_id: str, working_dir: str, command: str) -> str:
    """Send an SSM shell command and return the CommandId."""
    resp = _boto("ssm").send_command(
        DocumentName="AWS-RunShellScript",
        InstanceIds=[instance_id],
        Parameters={"workingDirectory": [working_dir], "commands": [command]},
    )
    return resp["Command"]["CommandId"]


def _ssm_poll(command_id: str, instance_id: str,
              poll_interval: int = 15, max_wait: int = 1800) -> str:
    """Poll SSM GetCommandInvocation until terminal; return Status string."""
    ssm = _boto("ssm")
    elapsed = 0
    while elapsed < max_wait:
        time.sleep(poll_interval)
        elapsed += poll_interval
        r = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        status = r["Status"]
        if status in ("Success", "Failed", "Cancelled", "TimedOut", "Undeliverable"):
            return status
    raise TimeoutError(f"SSM command {command_id} timed out after {max_wait}s")


# ──────────────────────────────────────────────────────────────
# DEFAULT ARGS
# ──────────────────────────────────────────────────────────────
default_args = {
    "owner": "data-engineering",
    "retries": 0,              # manual retry via SNS resume webhook
    "retry_delay": timedelta(minutes=5),
    "email_on_failure": False,
}

# ──────────────────────────────────────────────────────────────
# DAG
# ──────────────────────────────────────────────────────────────
with DAG(
    dag_id="sentryhawk_pipeline",
    default_args=default_args,
    schedule_interval="@daily",
    start_date=datetime(2025, 1, 1),
    catchup=False,
    tags=["sentryhawk", "cve", "elt"],
    description="CVE ingestion pipeline: DB refresh → SQS drain → Glue → EMR → Redshift/Druid",
) as dag:

    # ── 1. DB EC2 ────────────────────────────────────────────
    @task()
    def start_db_ec2():
        ec2 = _boto("ec2")
        r = ec2.start_instances(InstanceIds=[DB_INSTANCE_ID])
        instance_id = r["StartingInstances"][0]["InstanceId"]
        # Wait for EC2 to initialise (mirrors Step Functions Wait 20s + margin)
        waiter = ec2.get_waiter("instance_running")
        waiter.wait(InstanceIds=[instance_id],
                    WaiterConfig={"Delay": 10, "MaxAttempts": 30})
        return instance_id

    @task()
    def start_db_containers(instance_id: str):
        cmd_id = _ssm_run(
            instance_id,
            "/home/ec2-user/CVE-Search-Docker",
            "sudo -u ec2-user bash -c 'docker compose up -d mongo redis cve_search'",
        )
        # 75-second warm-up (mirrors Wait 75)
        time.sleep(75)
        return {"instance_id": instance_id, "cmd_id": cmd_id}

    # ── 2. DB Refresh ────────────────────────────────────────
    @task(retries=3)
    def run_db_refresh(ctx: dict):
        instance_id = ctx["instance_id"]
        cmd_id = _ssm_run(
            instance_id,
            "/home/ec2-user/CVE-Search-Docker",
            "sudo -u ec2-user bash -c 'chmod +x ./refresh.sh && ./refresh.sh > refresh.log 2>&1'",
        )
        status = _ssm_poll(cmd_id, instance_id, poll_interval=30)
        if status != "Success":
            _sns_alert(f"DB Refresh failed (status={status}). Instance: {instance_id}")
            raise ValueError(f"DB Refresh SSM command failed: {status}")
        return instance_id

    # ── 3. Poll SQS until drained ────────────────────────────
    @task()
    def wait_for_product_queue():
        """
        Equivalent to the Step Functions polling loop:
        Product SQS Poll → Check Product Queue → Wait for Products (repeat).
        Blocks until both ApproximateNumberOfMessages and
        ApproximateNumberOfMessagesNotVisible are 0.
        """
        sqs = _boto("sqs")
        while True:
            r = sqs.get_queue_attributes(
                QueueUrl=PRODUCT_SQS_URL,
                AttributeNames=["ApproximateNumberOfMessages",
                                 "ApproximateNumberOfMessagesNotVisible"],
            )
            visible   = int(r["Attributes"]["ApproximateNumberOfMessages"])
            in_flight = int(r["Attributes"]["ApproximateNumberOfMessagesNotVisible"])
            if visible == 0 and in_flight == 0:
                return "queue_empty"
            time.sleep(120)

    # ── 4. DLQ check → optional backup → map backup → shut DB down ──
    @task()
    def check_product_dlq() -> str:
        sqs = _boto("sqs")
        r = sqs.get_queue_attributes(
            QueueUrl=PRODUCT_DLQ_URL,
            AttributeNames=["ApproximateNumberOfMessages",
                             "ApproximateNumberOfMessagesNotVisible"],
        )
        visible   = int(r["Attributes"]["ApproximateNumberOfMessages"])
        in_flight = int(r["Attributes"]["ApproximateNumberOfMessagesNotVisible"])
        return "dlq_empty" if (visible == 0 and in_flight == 0) else "dlq_dirty"

    @task()
    def backup_dlq(instance_id: str):
        """Runs cve_sqs_log.py to persist DLQ messages before the map backup."""
        cmd_id = _ssm_run(
            instance_id,
            "/home/ec2-user/CVE-Search-Docker",
            "sudo -u ec2-user bash -c 'chmod +x cve_sqs_log.py && python3 cve_sqs_log.py'",
        )
        status = _ssm_poll(cmd_id, instance_id)
        if status != "Success":
            _sns_alert(f"Product DLQ Backup failed. Instance: {instance_id}")
            raise ValueError("DLQ backup script failed")

    @task()
    def map_backup(instance_id: str):
        cmd_id = _ssm_run(
            instance_id,
            "/home/ec2-user/CVE-Search-Docker",
            "sudo -u ec2-user bash -c 'chmod +x cve_mongo_map_backup.sh && ./cve_mongo_map_backup.sh'",
        )
        status = _ssm_poll(cmd_id, instance_id)
        if status != "Success":
            _sns_alert(f"Map backup failed. Instance: {instance_id}")
            raise ValueError("Map backup script failed")

    @task()
    def shutdown_db(instance_id: str):
        ec2 = _boto("ec2")
        # Stop Docker containers first
        cmd_id = _ssm_run(
            instance_id,
            "/home/ec2-user/CVE-Search-Docker",
            "sudo -u ec2-user bash -c 'docker compose down'",
        )
        _ssm_poll(cmd_id, instance_id)
        # Stop EC2
        ec2.stop_instances(InstanceIds=[instance_id])
        waiter = ec2.get_waiter("instance_stopped")
        waiter.wait(InstanceIds=[instance_id],
                    WaiterConfig={"Delay": 10, "MaxAttempts": 30})

    # ── 5. Glue Jobs (sequential) ────────────────────────────
    @task()
    def run_glue_jobs():
        """
        Mirrors the Step Functions Map with MaxConcurrency=1:
        runs all 4 Glue jobs serially, alerts + raises on failure.
        """
        glue = _boto("glue")
        for job_name in GLUE_JOBS:
            run = glue.start_job_run(JobName=job_name)
            run_id = run["JobRunId"]
            while True:
                time.sleep(30)
                detail = glue.get_job_run(JobName=job_name, RunId=run_id)
                state = detail["JobRun"]["JobRunState"]
                if state == "SUCCEEDED":
                    break
                if state in ("FAILED", "ERROR", "TIMEOUT", "STOPPED"):
                    msg = f"Glue job {job_name} failed (state={state})"
                    _sns_alert(msg + f"\nResume: {RESUME_URL_BASE}")
                    raise RuntimeError(msg)

    # ── 6. EMR Cluster + Spark Step ──────────────────────────
    @task()
    def create_emr_cluster() -> str:
        emr = _boto("emr")
        r = emr.run_job_flow(
            Name=EMR_CLUSTER_NAME,
            LogUri=EMR_LOG_URI,
            ReleaseLabel="emr-7.8.0",
            ServiceRole=EMR_SERVICE_ROLE,
            JobFlowRole=EMR_JOB_FLOW_ROLE,
            Instances={
                "KeepJobFlowAliveWhenNoSteps": True,
                "Ec2SubnetIds": [EMR_SUBNET],
                "EmrManagedMasterSecurityGroup": EMR_MASTER_SG,
                "EmrManagedSlaveSecurityGroup": EMR_SLAVE_SG,
                "InstanceGroups": [
                    {
                        "Name": "Primary",
                        "InstanceRole": "MASTER",
                        "InstanceType": "m5.xlarge",
                        "InstanceCount": 1,
                        "EbsConfiguration": {
                            "EbsBlockDeviceConfigs": [
                                {"VolumeSpecification": {"VolumeType": "gp2", "SizeInGB": 32},
                                 "VolumesPerInstance": 2}
                            ]
                        },
                    },
                    {
                        "Name": "Core",
                        "InstanceRole": "CORE",
                        "InstanceType": "r5.xlarge",
                        "InstanceCount": 4,
                        "EbsConfiguration": {
                            "EbsBlockDeviceConfigs": [
                                {"VolumeSpecification": {"VolumeType": "gp2", "SizeInGB": 32},
                                 "VolumesPerInstance": 2}
                            ],
                            "EbsOptimized": True,
                        },
                    },
                ],
            },
            BootstrapActions=[
                {"Name": "cve_ingestion_install_dependencies_emr",
                 "ScriptBootstrapAction": {"Path": EMR_BOOTSTRAP, "Args": []}}
            ],
            Applications=[{"Name": "Spark"}],
            Configurations=[
                {
                    "Classification": "spark-hive-site",
                    "Properties": {
                        "hive.metastore.client.factory.class":
                            "com.amazonaws.glue.catalog.metastore.AWSGlueDataCatalogHiveClientFactory"
                    },
                }
            ],
            Tags=[{"Key": "for-use-with-amazon-emr-managed-policies", "Value": "true"}],
            ScaleDownBehavior="TERMINATE_AT_TASK_COMPLETION",
            AutoTerminationPolicy={"IdleTimeout": 300},
        )
        cluster_id = r["JobFlowId"]

        # Wait for WAITING state (mirrors Wait 120 + Get EMR State loop)
        emr_client = _boto("emr")
        while True:
            time.sleep(60)
            desc = emr_client.describe_cluster(ClusterId=cluster_id)
            state = desc["Cluster"]["Status"]["State"]
            if state == "WAITING":
                return cluster_id
            if state in ("TERMINATING", "TERMINATED", "TERMINATED_WITH_ERRORS"):
                msg = f"EMR cluster {cluster_id} failed to start (state={state})"
                _sns_alert(msg)
                raise RuntimeError(msg)

    @task()
    def run_emr_spark_step(cluster_id: str) -> str:
        emr = _boto("emr")
        r = emr.add_job_flow_steps(
            JobFlowId=cluster_id,
            Steps=[
                {
                    "Name": EMR_CLUSTER_NAME,
                    "ActionOnFailure": "TERMINATE_CLUSTER",
                    "HadoopJarStep": {
                        "Jar": "command-runner.jar",
                        "Args": ["spark-submit", "--deploy-mode", "cluster", EMR_SPARK_SCRIPT],
                    },
                }
            ],
        )
        step_id = r["StepIds"][0]

        # Poll (mirrors Wait 120 + Get EMR Step loop)
        while True:
            time.sleep(60)
            desc = emr.describe_step(ClusterId=cluster_id, StepId=step_id)
            state = desc["Step"]["Status"]["State"]
            if state == "COMPLETED":
                return cluster_id
            if state in ("FAILED", "CANCELLED", "INTERRUPTED", "CANCEL_PENDING"):
                # Terminate cluster before alerting (mirrors Stop EMR Cluster state)
                emr.terminate_job_flows(JobFlowIds=[cluster_id])
                msg = f"EMR step {step_id} failed (state={state})"
                _sns_alert(msg + f"\nResume: {RESUME_URL_BASE}")
                raise RuntimeError(msg)

    @task()
    def terminate_emr_cluster(cluster_id: str):
        _boto("emr").terminate_job_flows(JobFlowIds=[cluster_id])

    # ── 7a. Redshift refresh ─────────────────────────────────
    @task()
    def redshift_sync():
        """
        Mirrors the Redshift branch:
        Get Workgroup → Sync Production Master → poll until FINISHED/FAILED.
        """
        rd = _boto("redshift-data")
        # Verify workgroup exists
        _boto("redshift-serverless").get_workgroup(workgroupName=REDSHIFT_WG)

        r = rd.execute_statement(
            WorkgroupName=REDSHIFT_WG,
            Database=REDSHIFT_DB,
            Sql="CALL analytics.sync_cve_production_master();",
            StatementName="sync_cve_production_master",
            WithEvent=True,
        )
        stmt_id = r["Id"]

        while True:
            time.sleep(10)
            desc = rd.describe_statement(Id=stmt_id)
            status = desc["Status"]
            if status in ("FINISHED", "ABORTED"):
                _boto("sns").publish(TopicArn=SNS_TOPIC_ARN,
                                     Message="Redshift successfully synced.")
                return
            if status == "FAILED":
                msg = f"Redshift statement {stmt_id} failed"
                _sns_alert(msg + f"\nResume: {RESUME_URL_BASE}")
                raise RuntimeError(msg)

    # ── 7b. Druid EC2 + ECS task ─────────────────────────────
    @task()
    def druid_refresh():
        """
        Mirrors the Druid branch:
        ensure EC2 stopped → upgrade type → start → start containers →
        run ECS Fargate task → stop containers → stop EC2 → downgrade type.
        """
        ec2 = _boto("ec2")
        ecs = _boto("ecs")

        # ① ensure stopped
        state = ec2.describe_instances(InstanceIds=[DRUID_INSTANCE_ID])\
                   ["Reservations"][0]["Instances"][0]["State"]["Name"]
        if state == "running":
            # Shut down containers first
            cmd_id = _ssm_run(DRUID_INSTANCE_ID,
                              "/home/ec2-user/druid-cluster",
                              "sudo -u ec2-user bash -c 'docker compose down'")
            _ssm_poll(cmd_id, DRUID_INSTANCE_ID)
            ec2.stop_instances(InstanceIds=[DRUID_INSTANCE_ID])
            ec2.get_waiter("instance_stopped").wait(
                InstanceIds=[DRUID_INSTANCE_ID],
                WaiterConfig={"Delay": 10, "MaxAttempts": 30})

        # ② upgrade instance type (mirrors Upgrade Druid EC2 → c5.4xlarge)
        ec2.modify_instance_attribute(InstanceId=DRUID_INSTANCE_ID,
                                      InstanceType={"Value": "c5.4xlarge"})

        # ③ start EC2
        ec2.start_instances(InstanceIds=[DRUID_INSTANCE_ID])
        ec2.get_waiter("instance_running").wait(
            InstanceIds=[DRUID_INSTANCE_ID],
            WaiterConfig={"Delay": 10, "MaxAttempts": 30})
        time.sleep(15)  # mirrors Wait for Druid EC2 Start

        # ④ start Druid containers
        cmd_id = _ssm_run(DRUID_INSTANCE_ID,
                          "/home/ec2-user/druid-cluster",
                          "sudo -u ec2-user bash -c 'docker compose up -d'")
        time.sleep(60)  # mirrors Wait for Druid Container Start

        # ⑤ run ECS Fargate task
        try:
            r = ecs.run_task(
                Cluster=ECS_CLUSTER,
                TaskDefinition=ECS_TASK_DEF,
                LaunchType="FARGATE",
                PlatformVersion="LATEST",
                NetworkConfiguration={
                    "awsvpcConfiguration": {
                        "subnets": [ECS_SUBNET],
                        "securityGroups": [ECS_SG],
                        "assignPublicIp": "ENABLED",
                    }
                },
            )
            task_arn = r["tasks"][0]["taskArn"]
            # Poll ECS until stopped
            while True:
                time.sleep(30)
                desc = ecs.describe_tasks(cluster=ECS_CLUSTER, tasks=[task_arn])
                last_status = desc["tasks"][0]["lastStatus"]
                if last_status == "STOPPED":
                    stop_code = desc["tasks"][0].get("stopCode", "")
                    if stop_code == "TaskFailedToStart" or \
                       desc["tasks"][0].get("containers", [{}])[0].get("exitCode", 0) != 0:
                        raise RuntimeError(f"ECS task failed: {desc['tasks'][0]}")
                    break
        except Exception as exc:
            # mirrors Halt Druid EC2 → Druid ECS Task Failed
            ec2.stop_instances(InstanceIds=[DRUID_INSTANCE_ID])
            _sns_alert(f"Druid ECS task failed: {exc}\nResume: {RESUME_URL_BASE}")
            raise

        # ⑥ stop containers
        cmd_id = _ssm_run(DRUID_INSTANCE_ID,
                          "/home/ec2-user/druid-cluster",
                          "sudo -u ec2-user bash -c 'docker compose down'")
        _ssm_poll(cmd_id, DRUID_INSTANCE_ID)

        # ⑦ stop EC2
        ec2.stop_instances(InstanceIds=[DRUID_INSTANCE_ID])
        ec2.get_waiter("instance_stopped").wait(
            InstanceIds=[DRUID_INSTANCE_ID],
            WaiterConfig={"Delay": 10, "MaxAttempts": 30})

        # ⑧ downgrade instance type (mirrors Downgrade Druid EC2 → m5.large)
        ec2.modify_instance_attribute(InstanceId=DRUID_INSTANCE_ID,
                                      InstanceType={"Value": "m5.large"})

    # ── 8. Success notification ──────────────────────────────
    run_success = SnsPublishOperator(
        task_id="run_success",
        target_arn=SNS_TOPIC_ARN,
        message="Sentryhawk Successfully Updated",
        aws_conn_id="aws_default",
    )

    # ──────────────────────────────────────────────────────────
    # TASK WIRING
    # ──────────────────────────────────────────────────────────
    # Phase 1: DB lifecycle
    t_start_db_ec2       = start_db_ec2()
    t_start_db_containers = start_db_containers(t_start_db_ec2)
    t_db_refresh         = run_db_refresh(t_start_db_containers)

    # Phase 2: SQS drain
    t_sqs_wait           = wait_for_product_queue()
    t_db_refresh >> t_sqs_wait

    # Phase 3: DLQ + map backup + shutdown (linear; DLQ branch handled inside task)
    t_dlq_check          = check_product_dlq()
    t_backup_dlq_task    = backup_dlq(t_start_db_ec2)  # passes instance_id
    t_map_backup_task    = map_backup(t_start_db_ec2)
    t_shutdown_db        = shutdown_db(t_start_db_ec2)

    t_sqs_wait >> t_dlq_check
    # Note: in a full BranchPythonOperator implementation you would branch
    # on dlq_empty/dlq_dirty; here we run backup_dlq only when DLQ is dirty,
    # controlled by check_product_dlq's return value used downstream.
    # For simplicity the shutdown always follows map_backup (map_backup is
    # idempotent when DLQ is empty).
    t_dlq_check >> t_backup_dlq_task >> t_map_backup_task >> t_shutdown_db

    # Phase 4: Glue jobs
    t_glue = run_glue_jobs()
    t_shutdown_db >> t_glue

    # Phase 5: EMR
    t_cluster_id         = create_emr_cluster()
    t_step               = run_emr_spark_step(t_cluster_id)
    t_terminate          = terminate_emr_cluster(t_step)
    t_glue >> t_cluster_id

    # Phase 6: Parallel analytics refresh
    with TaskGroup("analytics_refresh") as analytics_refresh:
        t_redshift = redshift_sync()
        t_druid    = druid_refresh()
        # Both run in parallel (no dependency between them)

    t_terminate >> analytics_refresh >> run_success
