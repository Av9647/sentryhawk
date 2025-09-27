UNLOAD ('SELECT * FROM analytics.cve_current')
TO 's3://cve-production/redshift_exports/cve_current'
IAM_ROLE 'arn:aws:iam::${ACCOUNT_ID}:role/cve_redshift_export_role'
FORMAT AS CSV
DELIMITER ','
ALLOWOVERWRITE
PARALLEL OFF;

UNLOAD ('SELECT * FROM analytics.cve_current')
TO 's3://cve-production/redshift_exports/cve_current'
IAM_ROLE 'arn:aws:iam::${ACCOUNT_ID}:role/cve_redshift_export_role'
FORMAT AS PARQUET
ALLOWOVERWRITE;
