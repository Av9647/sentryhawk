WITH RECURSIVE threat_history AS (
    -- Base case: First time a CVE was seen
    SELECT 
        cve_id,
        MIN(published_date) AS first_seen,
        MAX(published_date) AS last_seen,
        COUNT(*) AS total_mentions,
        AVG(cvss_score) AS avg_cvss_score
    FROM staging_cve
    GROUP BY cve_id

    UNION ALL

    -- Recursive step: Update cumulative scores when the CVE appears again
    SELECT 
        t.cve_id,
        t.first_seen,
        s.published_date AS last_seen,
        t.total_mentions + 1,
        (t.avg_cvss_score * t.total_mentions + s.cvss_score) / (t.total_mentions + 1) AS avg_cvss_score
    FROM threat_history t
    JOIN staging_cve s ON t.cve_id = s.cve_id
    WHERE s.published_date > t.last_seen
)
SELECT * FROM threat_history;
