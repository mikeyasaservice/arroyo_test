-- Simple passthrough test to verify Kafka connection
CREATE TABLE web_logs_source (
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

-- Just pass through all events to verify connection
SELECT * FROM web_logs_source;