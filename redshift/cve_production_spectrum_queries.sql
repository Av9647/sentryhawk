-- Redshift Spectrum

-- 1. Create External Schema
-- CREATE EXTERNAL SCHEMA cve_ext
-- FROM DATA CATALOG
-- DATABASE 'cve_db'
-- IAM_ROLE 'arn:aws:iam::692859941232:role/cve_production_redshift_role';

-- 2. Perform Sanity Check 
-- SELECT COUNT(*) FROM cve_ext.cve_production_master
-- WHERE currentFlag = true;

-- 3. Query directly from S3/Iceberg
-- SELECT vendor, COUNT(DISTINCT cveId) AS distinct_cves
-- FROM cve_ext.cve_production_lookup
-- GROUP BY vendor
-- ORDER BY distinct_cves DESC
-- LIMIT 50;

-- 4. Create schema if not exists
-- CREATE SCHEMA IF NOT EXISTS analytics;
-- CREATE OR REPLACE VIEW analytics.cve_current AS
-- SELECT vendor, product, cveId, descriptions, cvssScore,
--   cvssVersion, severity, datePublished, dateReserved,
--   dateUpdated, datePublic, lastModified
-- FROM cve_ext.cve_production_master
-- WHERE currentFlag = true
-- WITH NO SCHEMA BINDING;  -- required for external tables

-- 5. Check if view exists
-- SELECT table_schema, table_name
-- FROM information_schema.views
-- WHERE table_schema = 'analytics';

-- 6. Query View
SELECT vendor, product, cveId, severity
FROM analytics.cve_current
LIMIT 10;

-- 7. Granting access to other users
-- GRANT USAGE ON SCHEMA analytics TO some_user;
-- GRANT SELECT ON ALL TABLES IN SCHEMA analytics TO some_user;  -- includes views
