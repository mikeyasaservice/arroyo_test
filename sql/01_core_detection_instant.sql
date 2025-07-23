-- ToolShell Core Detection Pipeline (Instant Detection)
-- Fires immediately on each exploit attempt

-- Create source tables
CREATE TABLE web_logs (
    timestamp TIMESTAMP,
    source_ip TEXT,
    destination_ip TEXT,
    destination_hostname TEXT,
    url_path TEXT,
    query_string TEXT,
    request_method TEXT,
    referer TEXT,
    user_agent TEXT,
    response_code INT,
    response_size BIGINT,
    request_body TEXT
) WITH (
    connector = 'kafka',
    bootstrap_servers = 'redpanda-0:9092',
    topic = 'web-logs',
    format = 'json',
    type = 'source'
);

-- Create output table
CREATE TABLE toolshell_attack_chains (
    detection_time TIMESTAMP,
    hostname TEXT,
    source_ip TEXT,
    threat_actor TEXT,
    risk_score INT,
    url_path TEXT,
    query_string TEXT,
    referer TEXT,
    ioc_context TEXT
) WITH (
    connector = 'kafka',
    bootstrap_servers = 'redpanda-0:9092',
    topic = 'toolshell-attack-chains',
    format = 'json',
    type = 'sink'
);

-- Instant detection - no windowing
INSERT INTO toolshell_attack_chains
SELECT 
    NOW() as detection_time,
    destination_hostname as hostname,
    source_ip,
    extract_threat_actor(source_ip) as threat_actor,
    calculate_risk_score(
        extract_threat_actor(source_ip) != 'Unknown',
        true,  -- is_exploit_attempt
        false, -- has_webshell
        false, -- has_key_theft
        false  -- has_c2
    ) as risk_score,
    url_path,
    query_string,
    referer,
    extract_ioc_context(null, null, null, null) as ioc_context
FROM web_logs
WHERE is_toolpane_exploit(url_path, query_string, request_method, referer) = true;

-- Also output to UI
SELECT 
    NOW() as detection_time,
    destination_hostname as hostname,
    source_ip,
    extract_threat_actor(source_ip) as threat_actor,
    calculate_risk_score(
        extract_threat_actor(source_ip) != 'Unknown',
        true,  -- is_exploit_attempt
        false, -- has_webshell
        false, -- has_key_theft
        false  -- has_c2
    ) as risk_score,
    url_path,
    query_string,
    referer,
    extract_ioc_context(null, null, null, null) as ioc_context
FROM web_logs
WHERE is_toolpane_exploit(url_path, query_string, request_method, referer) = true;