-- ToolShell Critical Alert Generation
-- Monitors attack chains and generates alerts with appropriate priority

-- Read from the attack chains stream
CREATE TABLE attack_chains_stream (
    window_time TIMESTAMP,
    hostname TEXT,
    threat_actor TEXT,
    risk_score INT,
    exploit_count BIGINT,
    webshell_count BIGINT,
    key_theft_count BIGINT,
    c2_count BIGINT,
    earliest_activity TIMESTAMP,
    latest_activity TIMESTAMP,
    total_events BIGINT,
    affected_processes TEXT,
    ioc_context TEXT
) WITH (
    connector = 'kafka',
    bootstrap_servers = 'redpanda-0:9092',
    topic = 'toolshell-attack-chains',
    format = 'json',
    type = 'source'
);

-- Generate prioritized alerts based on risk score and activity
CREATE VIEW critical_alerts AS
SELECT 
    window_time as detection_window,
    hostname,
    threat_actor,
    risk_score,
    CASE 
        WHEN risk_score >= 90 AND threat_actor != 'Unknown' THEN 'P1'
        WHEN risk_score >= 75 OR key_theft_count > 0 THEN 'P2'
        WHEN risk_score >= 50 THEN 'P3'
        ELSE 'P4'
    END as priority,
    CASE 
        WHEN exploit_count > 0 AND webshell_count > 0 AND key_theft_count > 0 THEN 'COMPLETE_CHAIN'
        WHEN exploit_count > 0 AND webshell_count > 0 THEN 'PARTIAL_CHAIN'
        WHEN exploit_count > 0 THEN 'INITIAL_EXPLOITATION'
        ELSE 'SUSPICIOUS_ACTIVITY'
    END as chain_status,
    CONCAT(
        'ToolShell Attack Detected on ', hostname,
        CASE 
            WHEN threat_actor != 'Unknown' THEN CONCAT(' by ', threat_actor)
            ELSE ''
        END
    ) as alert_title,
    exploit_count as exploit_attempts,
    webshell_count as webshells_deployed,
    key_theft_count as key_theft_attempts,
    c2_count as c2_connections,
    ioc_context as ioc_details,
    NOW() as alert_generated_at
FROM attack_chains_stream
WHERE risk_score >= 50;

-- Create critical alerts output table
CREATE TABLE critical_alerts_output (
    detection_window TIMESTAMP,
    hostname TEXT,
    threat_actor TEXT,
    risk_score INT,
    priority TEXT,
    chain_status TEXT,
    alert_title TEXT,
    exploit_attempts BIGINT,
    webshells_deployed BIGINT,
    key_theft_attempts BIGINT,
    c2_connections BIGINT,
    ioc_details TEXT,
    alert_generated_at TIMESTAMP
) WITH (
    connector = 'kafka',
    bootstrap_servers = 'redpanda-0:9092',
    topic = 'toolshell-critical-alerts',
    format = 'json',
    type = 'sink'
);

-- Output critical alerts
INSERT INTO critical_alerts_output
SELECT * FROM critical_alerts;