#!/bin/bash
set -euo pipefail

# Demo script to showcase Arroyo as a real-time detection pipeline
echo "Starting Arroyo Real-Time Detection Demo..."
echo "This will generate mixed traffic to demonstrate detection capabilities"
echo

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
KAFKA_CONTAINER="redpanda-0"
TOPIC="web-logs"
EVENTS_PER_SECOND=10
EXPLOIT_PERCENTAGE=20  # 20% of traffic will be malicious

# Known threat actors and their IPs - using arrays instead of associative array for compatibility
THREAT_IPS=("131.226.2.6" "45.9.74.85" "185.225.19.69")
THREAT_NAMES=("Storm-2603" "Mint Sandstorm" "Unknown")

# Normal user IPs
NORMAL_IPS=("10.0.1.100" "10.0.1.101" "10.0.1.102" "10.0.1.103" "192.168.1.50" "192.168.1.51")

# SharePoint paths
NORMAL_PATHS=(
    "/sites/HR/Documents/policy.docx"
    "/sites/Finance/Reports/Q4_2024.xlsx"
    "/sites/IT/Wiki/setup-guide.aspx"
    "/sites/Legal/Contracts/template.docx"
    "/_layouts/15/start.aspx"
    "/sites/Marketing/Shared%20Documents/campaign.pptx"
)

EXPLOIT_PATHS=(
    "/_layouts/15/ToolPane.aspx"
    "/sites/HR/_layouts/15/ToolPane.aspx"
    "/sites/Finance/_layouts/15/ToolPane.aspx"
    "/sites/Legal/_layouts/15/ToolPane.aspx"
)

# Query strings for exploits
EXPLOIT_QUERIES=(
    "displaymode=edit"
    "displaymode=edit&cmd=whoami"
    "displaymode=edit&exec=powershell"
    "displaymode=edit&debug=true"
)

# Malicious referers
MALICIOUS_REFERERS=(
    "http://evil.com"
    "http://attacker.com"
    "http://phishing-site.ru"
    "http://malware-c2.net"
)

# Function to generate normal traffic
generate_normal_event() {
    local ip="${NORMAL_IPS[$RANDOM % ${#NORMAL_IPS[@]}]}"
    local path="${NORMAL_PATHS[$RANDOM % ${#NORMAL_PATHS[@]}]}"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
    
    echo "{\"timestamp\":\"$timestamp\",\"source_ip\":\"$ip\",\"destination_ip\":\"10.0.1.50\",\"destination_hostname\":\"sharepoint.corp.local\",\"url_path\":\"$path\",\"query_string\":\"\",\"request_method\":\"GET\",\"referer\":\"https://sharepoint.corp.local\",\"user_agent\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\",\"response_code\":200,\"response_size\":$((RANDOM % 50000 + 1000)),\"request_body\":\"\"}"
}

# Function to generate exploit traffic
generate_exploit_event() {
    local ip="${THREAT_IPS[$RANDOM % ${#THREAT_IPS[@]}]}"
    local path="${EXPLOIT_PATHS[$RANDOM % ${#EXPLOIT_PATHS[@]}]}"
    local query="${EXPLOIT_QUERIES[$RANDOM % ${#EXPLOIT_QUERIES[@]}]}"
    local referer="${MALICIOUS_REFERERS[$RANDOM % ${#MALICIOUS_REFERERS[@]}]}"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
    
    echo "{\"timestamp\":\"$timestamp\",\"source_ip\":\"$ip\",\"destination_ip\":\"10.0.1.50\",\"destination_hostname\":\"sharepoint.corp.local\",\"url_path\":\"$path\",\"query_string\":\"$query\",\"request_method\":\"POST\",\"referer\":\"$referer\",\"user_agent\":\"Mozilla/5.0\",\"response_code\":200,\"response_size\":$((RANDOM % 5000 + 500)),\"request_body\":\"encoded_malicious_payload\"}"
}

# Stats tracking
total_events=0
exploit_events=0
normal_events=0

echo -e "${BLUE}Configuration:${NC}"
echo "• Events per second: $EVENTS_PER_SECOND"
echo "• Exploit percentage: $EXPLOIT_PERCENTAGE%"
echo "• Threat actors: ${#THREAT_IPS[@]} known"
echo
echo -e "${YELLOW}Press Ctrl+C to stop the demo${NC}"
echo
echo -e "${GREEN}Starting event generation...${NC}"
echo

# Main loop
while true; do
    for ((i=0; i<$EVENTS_PER_SECOND; i++)); do
        # Determine if this should be an exploit or normal traffic
        if [ $((RANDOM % 100)) -lt $EXPLOIT_PERCENTAGE ]; then
            # Generate exploit event
            event=$(generate_exploit_event)
            echo "$event" | docker exec -i $KAFKA_CONTAINER rpk topic produce $TOPIC
            ((exploit_events++))
            echo -ne "\r${RED}[EXPLOIT]${NC} "
        else
            # Generate normal event
            event=$(generate_normal_event)
            echo "$event" | docker exec -i $KAFKA_CONTAINER rpk topic produce $TOPIC
            ((normal_events++))
            echo -ne "\r${GREEN}[NORMAL]${NC} "
        fi
        ((total_events++))
        
        # Update stats display
        echo -ne "Total: $total_events | Exploits: ${RED}$exploit_events${NC} | Normal: ${GREEN}$normal_events${NC} | Rate: ${EVENTS_PER_SECOND}/s"
    done
    
    # Sleep for 1 second to maintain rate
    sleep 1
done