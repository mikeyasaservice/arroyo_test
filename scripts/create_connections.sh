#!/bin/bash
set -euo pipefail

# Create Connection Profiles for Arroyo
echo "🔌 Creating Arroyo connection profiles..."

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

ARROYO_API="http://localhost:5115/api/v1"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create Kafka connection profile for Redpanda
create_kafka_connection() {
    log_info "Creating Kafka connection profile for Redpanda..."
    
    response=$(curl -s -X POST "${ARROYO_API}/connection_profiles" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "redpanda",
            "connector": "kafka",
            "config": {
                "bootstrap_servers": "redpanda-0:9092",
                "type": "sink",
                "format": "json"
            }
        }')
    
    if echo "$response" | jq -e '.error' > /dev/null 2>&1; then
        error_msg=$(echo "$response" | jq -r '.error')
        if [[ "$error_msg" == *"already exists"* ]]; then
            log_info "✓ Kafka connection already exists"
        else
            log_error "Failed to create Kafka connection:"
            echo "$response" | jq .
            return 1
        fi
    else
        log_info "✓ Created Kafka connection profile"
    fi
}

# Main execution
main() {
    # Wait for Arroyo to be ready
    log_info "Waiting for Arroyo API..."
    for i in {1..30}; do
        if curl -s "${ARROYO_API}/ping" > /dev/null 2>&1; then
            break
        fi
        sleep 2
    done
    
    # Create connections
    create_kafka_connection
    
    log_info "Connection profiles ready!"
}

main "$@"