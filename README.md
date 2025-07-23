# Arroyo Real-Time Stream Processing Platform

A production-ready deployment of [Arroyo](https://arroyo.dev), an open-source distributed stream processing engine, configured with Redpanda (Kafka-compatible) for high-performance event streaming.

This repository provides:
- **Generic streaming infrastructure** ready for any real-time processing use case
- **Example implementation**: SharePoint ToolShell (CVE-2025-49706/49704) exploit detection
- **Automated deployment** designed for operators with varying skill levels
- **Python UDF support** for rapid prototyping and custom logic

## Architecture

- **Arroyo**: Distributed SQL stream processing engine
- **Redpanda**: Kafka-compatible streaming platform (lighter weight than Kafka)
- **PostgreSQL**: Metadata storage for Arroyo
- **Python UDFs**: Custom processing logic (with notes on Rust UDF migration path)

## Quick Start

```bash
# 1. Deploy the detection system
./scripts/deploy.sh
```

This automated deployment will:
- Start all services (Arroyo, Redpanda, PostgreSQL)
- Create Kafka topics
- Deploy Python UDFs
- Create SQL streaming pipelines
- Send a test event to verify operation

```bash
# 2. View real-time detections in Arroyo UI
# Open http://localhost:5115
# Click on 'toolshell-instant-detection' pipeline
# Click 'Start Trailing' to see outputs

# 3. Generate demo traffic
./scripts/demo.sh
```

The demo script generates realistic SharePoint traffic with ~20% exploit attempts to showcase real-time detection capabilities.

## Access Points

- **Arroyo UI**: http://localhost:5115 - Monitor pipelines and processing
- **Redpanda Console**: http://localhost:8090 - Kafka topic management
- **Kafka API**: localhost:19092 - For producers/consumers

## Python vs Rust UDFs

### Current Implementation (Python UDFs)

This prototype uses Python UDFs for all custom logic. Python UDFs are:
- ✅ Easy to write and maintain
- ✅ Familiar to most analysts and engineers
- ✅ Perfect for synchronous, computational logic (parsing, pattern matching, scoring)
- ✅ Quick to prototype and iterate

**Limitations**: Python UDFs in Arroyo do not support async operations, meaning they cannot:
- ❌ Make external API calls without blocking the pipeline
- ❌ Perform database lookups for enrichment
- ❌ Call AI/ML model endpoints
- ❌ Do any I/O operations that would benefit from async execution

### Future Migration Path (Rust Async UDFs)

For production deployments requiring async operations, consider migrating to Rust UDFs which support:
- ✅ Non-blocking I/O operations
- ✅ Parallel execution with configurable concurrency
- ✅ External service calls (databases, APIs, ML models)
- ✅ Higher performance for CPU-intensive operations

**When to migrate**: Only necessary if you need external enrichment or I/O operations. For pure computational logic (like the ToolShell detection example), Python UDFs are sufficient.

## Example Use Case: ToolShell Detection

The included example demonstrates detecting SharePoint exploitation attempts:

### Deploy the Example
```bash
# Everything is automated in the deploy script
./scripts/deploy.sh
```

### View Detection Results

After running the demo script:
1. **Arroyo UI**: Pipeline outputs show real-time detections
2. **Redpanda Console**: Check the `toolshell-attack-chains` topic
3. **Command line**: 
   ```bash
   docker exec redpanda-0 rpk topic consume toolshell-attack-chains -f '%v\n' | jq .
   ```

### Topics Created
- `web-logs` - HTTP access logs
- `process-events` - System process execution events
- `file-events` - File system activity
- `network-connections` - Network connection logs
- `toolshell-attack-chains` - Detected attack patterns (output)

### UDFs Deployed
1. `decode_base64_command` - Extracts encoded payloads
2. `is_toolpane_exploit` - Detects ToolPane.aspx exploitation
3. `extract_threat_actor` - Maps IPs to known actors
4. `calculate_risk_score` - Computes risk scores (0-100)
5. `extract_ioc_context` - Extracts indicators of compromise

## Customizing for Your Use Case

1. **Replace UDFs**: Edit `sql/udfs.py` with your detection logic
2. **Update SQL Pipelines**: Modify files in `sql/` directory
3. **Change Topics**: Update topic names in `scripts/deploy.sh`
4. **Add New Data Sources**: Extend `docker-compose.yml`

## Development

```bash
# View logs
docker-compose logs -f arroyo

# Access Redpanda CLI
docker exec -it redpanda-0 rpk topic list

# Check pipeline status
curl http://localhost:5115/api/v1/pipelines | jq

# Manually deploy a UDF
./scripts/deploy_udfs.sh

# Stop all services
docker-compose down
```

## Troubleshooting

- **Port conflicts**: Ensure ports 5115, 8090, 19092, 5432 are available
- **Memory issues**: Arroyo requires at least 4GB RAM allocated to Docker
- **Pipeline failures**: Check Arroyo UI for detailed error messages
- **Redpanda issues**: Use `rpk cluster health` to diagnose

## Production Considerations

1. **Scaling**: Configure Arroyo parallelism in pipeline definitions
2. **Persistence**: Mount volumes for PostgreSQL and Redpanda data
3. **Monitoring**: Export metrics to Prometheus/Grafana
4. **Security**: Enable authentication on all services
5. **UDF Migration**: Consider Rust UDFs for I/O-bound operations

## License

This deployment configuration is provided as-is for use with open-source Arroyo and Redpanda.