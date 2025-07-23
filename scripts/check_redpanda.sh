#!/bin/bash
set -euo pipefail

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🔍 Checking Redpanda Status..."

# Check if Redpanda container is running
if docker ps | grep -q "redpanda-0"; then
    echo -e "${GREEN}✓${NC} Redpanda container is running"
else
    echo -e "${RED}✗${NC} Redpanda container is not running"
    exit 1
fi

# Check Redpanda health using rpk
echo -e "\n${YELLOW}Cluster Health:${NC}"
docker exec redpanda-0 rpk cluster health

# List topics
echo -e "\n${YELLOW}Topics:${NC}"
docker exec redpanda-0 rpk topic list

# Create required topics if they don't exist
echo -e "\n${YELLOW}Creating required topics...${NC}"
for topic in web-logs process-events file-events network-connections toolshell-attack-chains; do
    docker exec redpanda-0 rpk topic create $topic --partitions 3 --replicas 1 2>/dev/null || echo "Topic $topic already exists"
done

# Show topic configuration
echo -e "\n${YELLOW}Topic Configuration:${NC}"
docker exec redpanda-0 rpk topic describe web-logs

echo -e "\n${GREEN}✓${NC} Redpanda is ready for use!"