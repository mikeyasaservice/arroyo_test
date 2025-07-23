-- ToolShell Core Detection Pipeline
-- Handles real-time detection and correlation

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

CREATE TABLE process_events (
    timestamp TIMESTAMP,
    hostname TEXT,
    process_id INT,
    process_name TEXT,
    process_path TEXT,
    command_line TEXT,
    parent_process_id INT,
    parent_process_name TEXT,
    user_name TEXT,
    process_hash TEXT
) WITH (
    connector = 'kafka',
    bootstrap_servers = 'redpanda-0:9092',
    topic = 'process-events',
    format = 'json',
    type = 'source'
);

CREATE TABLE file_events (
    timestamp TIMESTAMP,
    hostname TEXT,
    file_path TEXT,
    file_name TEXT,
    file_hash TEXT,
    file_size BIGINT,
    action TEXT,
    process_name TEXT,
    process_id INT
) WITH (
    connector = 'kafka',
    bootstrap_servers = 'redpanda-0:9092',
    topic = 'file-events',
    format = 'json',
    type = 'source'
);

CREATE TABLE network_connections (
    timestamp TIMESTAMP,
    hostname TEXT,
    process_name TEXT,
    process_id INT,
    local_address TEXT,
    local_port INT,
    remote_address TEXT,
    remote_port INT,
    protocol TEXT,
    direction TEXT,
    bytes_sent BIGINT,
    bytes_received BIGINT
) WITH (
    connector = 'kafka',
    bootstrap_servers = 'redpanda-0:9092',
    topic = 'network-connections',
    format = 'json',
    type = 'source'
);

-- Windowed exploit detection directly from source
CREATE VIEW exploit_detections AS
SELECT 
    TUMBLE(INTERVAL '1' MINUTE) as window_time,
    destination_hostname as hostname,
    COUNT(*) as exploit_attempts,
    COUNT(DISTINCT CASE 
        WHEN is_toolpane_exploit(url_path, query_string, request_method, referer) 
        THEN source_ip 
    END) as unique_exploit_ips,
    ARRAY_AGG(DISTINCT CASE 
        WHEN is_toolpane_exploit(url_path, query_string, request_method, referer) 
        THEN source_ip 
    END) as exploit_source_ips,
    ARRAY_AGG(DISTINCT CASE 
        WHEN is_toolpane_exploit(url_path, query_string, request_method, referer) 
        THEN extract_threat_actor(source_ip) 
    END) as threat_actors
FROM web_logs
WHERE is_toolpane_exploit(url_path, query_string, request_method, referer) = true
GROUP BY 1, destination_hostname;

-- Windowed webshell detection
CREATE VIEW webshell_detections AS
SELECT 
    TUMBLE(INTERVAL '1' MINUTE) as window_time,
    hostname,
    COUNT(*) as webshell_file_count,
    ARRAY_AGG(DISTINCT file_name) as webshell_files,
    ARRAY_AGG(DISTINCT file_hash) as file_hashes
FROM file_events
WHERE 
    action = 'create' AND (
        file_name LIKE '%spinstall%.aspx' OR
        file_name = 'xxx.aspx' OR
        file_hash IN (
            '92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514',
            'f5b60a8ead96703080e73a1f79c3e70ff44df271',
            'fe3a3042890c1f11361368aeb2cc12647a6fdae1'
        )
    )
GROUP BY 1, hostname;

-- Windowed machine key theft detection
CREATE VIEW key_theft_detections AS
SELECT 
    TUMBLE(INTERVAL '1' MINUTE) as window_time,
    hostname,
    COUNT(*) as key_theft_attempts,
    ARRAY_AGG(DISTINCT process_name) as suspicious_processes,
    ARRAY_AGG(DISTINCT command_line) as suspicious_commands
FROM process_events
WHERE 
    command_line LIKE '%MachineKey%' OR
    command_line LIKE '%ValidationKey%' OR
    command_line LIKE '%DecryptionKey%' OR
    (process_name = 'powershell.exe' AND command_line LIKE '%aspnet_regiis%')
GROUP BY 1, hostname;

-- Windowed C2 detection
CREATE VIEW c2_detections AS
SELECT 
    TUMBLE(INTERVAL '1' MINUTE) as window_time,
    hostname,
    COUNT(*) as c2_connections,
    ARRAY_AGG(DISTINCT remote_address) as c2_servers,
    SUM(bytes_sent + bytes_received) as total_bytes
FROM network_connections
WHERE 
    remote_address LIKE '%.ngrok-free.app' OR
    remote_port IN (4444, 8080, 8443, 9001) OR
    (protocol = 'tcp' AND direction = 'outbound' AND bytes_sent > 1000000)
GROUP BY 1, hostname;

-- For now, just use exploit detections directly as attack chains
-- Arroyo doesn't support re-aggregating windowed joins
CREATE VIEW attack_chains AS
SELECT 
    window_time.end as window_time,  -- Extract the end timestamp from the window struct
    hostname,
    threat_actors[1] as threat_actor,
    calculate_risk_score(
        threat_actors[1] != 'Unknown',
        exploit_attempts > 0,
        false,  -- webshell_count > 0
        false,  -- key_theft_count > 0
        false   -- c2_count > 0
    ) as risk_score,
    exploit_attempts as exploit_count,
    0 as webshell_count,
    0 as key_theft_count,
    0 as c2_count,
    NOW() as detection_time,
    CONCAT_WS(',', exploit_source_ips[1], exploit_source_ips[2]) as source_ips,
    extract_ioc_context(
        null,  -- webshell_files
        null,  -- file_hashes
        null,  -- suspicious_commands
        null   -- c2_servers
    ) as ioc_context
FROM exploit_detections;

-- Create output table
CREATE TABLE toolshell_attack_chains (
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
    type = 'sink'
);

-- Output attack chains
INSERT INTO toolshell_attack_chains
SELECT 
    window_time,
    hostname,
    threat_actor,
    risk_score,
    exploit_count,
    webshell_count,
    key_theft_count,
    c2_count,
    detection_time,
    source_ips,
    ioc_context
FROM attack_chains;