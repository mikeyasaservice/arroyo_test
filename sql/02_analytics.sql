-- ToolShell Analytics Pipeline
-- Advanced threat analytics and anomaly detection

-- Read from attack chains
CREATE TABLE attack_chains_stream (
    window_time TIMESTAMP,
    hostname TEXT,
    threat_actor TEXT,
    risk_score INT,
    exploit_count BIGINT,
    webshell_count BIGINT,
    key_theft_count BIGINT,
    c2_count BIGINT,
    detection_time TIMESTAMP,
    source_ips TEXT,
    ioc_context TEXT
) WITH (
    connector = 'kafka',
    bootstrap_servers = 'redpanda-0:9092',
    topic = 'toolshell-attack-chains',
    format = 'json',
    type = 'source'
);

-- Analytics view for threat actor activity
CREATE VIEW threat_actor_analytics AS
SELECT 
    TUMBLE(INTERVAL '1' HOUR) as hour_window,
    threat_actor,
    COUNT(*) as attack_count,
    COUNT(DISTINCT hostname) as unique_targets,
    SUM(exploit_count) as total_exploits,
    SUM(webshell_count) as total_webshells,
    MAX(risk_score) as max_risk_score,
    ARRAY_AGG(DISTINCT hostname) as targeted_hosts
FROM attack_chains_stream
WHERE threat_actor != 'Unknown'
GROUP BY 1, threat_actor;

-- Create analytics output table
CREATE TABLE analytics_output (
    window_time TIMESTAMP,
    analysis_type TEXT,
    threat_actor TEXT,
    hostname TEXT,
    metric_name TEXT,
    metric_value DOUBLE,
    details TEXT
) WITH (
    connector = 'kafka',
    bootstrap_servers = 'redpanda-0:9092',
    topic = 'toolshell-analytics',
    format = 'json',
    type = 'sink'
);

-- Output threat actor analytics
INSERT INTO analytics_output
SELECT 
    hour_window.end as window_time,  -- Extract end timestamp from window struct
    'threat_actor_activity' as analysis_type,
    threat_actor,
    targeted_hosts[1] as hostname,
    'attack_count' as metric_name,
    CAST(attack_count AS DOUBLE) as metric_value,
    CONCAT('Targets: ', CAST(unique_targets AS TEXT), ', Max Risk: ', CAST(max_risk_score AS TEXT)) as details
FROM threat_actor_analytics;