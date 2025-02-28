from airflow import DAG
from airflow.operators.python import PythonOperator
from datetime import datetime, timedelta
from jobs.batch.threat_ingestion import fetch_threat_data, transform_threat_data, load_threat_data

# Default arguments for Airflow DAG
default_args = {
    'owner': 'athul_vinod',
    'depends_on_past': False,
    'start_date': datetime(2025, 2, 27),
    'retries': 2,
    'retry_delay': timedelta(minutes=5),
}

# Define the DAG
dag = DAG(
    'cyber_threat_ingestion',
    default_args=default_args,
    description='Cybersecurity Threat Intelligence - Daily Data Pipeline',
    schedule_interval='@daily',  # Runs once per day
    catchup=False,
)

# Define the tasks
fetch_data = PythonOperator(
    task_id='fetch_threat_data',
    python_callable=fetch_threat_data,
    dag=dag,
)

transform_data = PythonOperator(
    task_id='transform_threat_data',
    python_callable=transform_threat_data,
    dag=dag,
)

load_data = PythonOperator(
    task_id='load_threat_data',
    python_callable=load_threat_data,
    dag=dag,
)

# Define task dependencies
fetch_data >> transform_data >> load_data
