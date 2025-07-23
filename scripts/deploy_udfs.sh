#!/usr/bin/env bash
set -euo pipefail

# Deploy UDFs to Arroyo via API
echo "Deploying UDFs to Arroyo..."

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
ARROYO_API="http://localhost:5115/api/v1"

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to validate UDF
validate_udf() {
    local name=$1
    local definition=$2
    
    log_info "Validating UDF: $name"
    
    response=$(curl -s -X POST "${ARROYO_API}/udfs/validate" \
        -H "Content-Type: application/json" \
        -d "{
            \"definition\": $(echo "$definition" | jq -Rs .),
            \"language\": \"python\"
        }")
    
    errors=$(echo "$response" | jq -r '.errors[]' 2>/dev/null || echo "")
    
    if [ -n "$errors" ]; then
        log_error "Validation failed for $name:"
        echo "$errors"
        return 1
    else
        log_info "Validation passed for $name"
        return 0
    fi
}

# Function to create UDF
create_udf() {
    local name=$1
    local definition=$2
    local description=$3
    
    log_info "Creating UDF: $name"
    
    response=$(curl -s -X POST "${ARROYO_API}/udfs" \
        -H "Content-Type: application/json" \
        -d "{
            \"definition\": $(echo "$definition" | jq -Rs .),
            \"prefix\": \"$name\",
            \"description\": \"$description\",
            \"language\": \"python\"
        }")
    
    if echo "$response" | jq -e '.error' > /dev/null 2>&1; then
        error_msg=$(echo "$response" | jq -r '.error')
        if [[ "$error_msg" == *"already exists"* ]]; then
            log_warn "UDF $name already exists, skipping..."
            return 0
        else
            log_error "Failed to create $name:"
            echo "$response" | jq .
            return 1
        fi
    else
        log_info "Created UDF: $name"
        return 0
    fi
}

# Check if Arroyo is accessible
log_info "Checking Arroyo API..."
if ! curl -s "${ARROYO_API}/ping" > /dev/null; then
    log_error "Arroyo API is not accessible at ${ARROYO_API}"
    exit 1
fi

# UDF descriptions
DESC_DECODE="Extract and decode base64 from PowerShell commands"
DESC_TOOLPANE="Detect ToolPane exploitation patterns"
DESC_ACTOR="Map IP to known threat actor"
DESC_RISK="Calculate risk score 0-100"
DESC_IOC="Extract IOC context as JSON"

# UDF definitions
read -r -d '' DECODE_BASE64 << 'EOF' || true
from arroyo_udf import udf
import base64
import re

@udf
def decode_base64_command(command: str) -> str:
    """Extract and decode base64 from PowerShell commands"""
    if not command:
        return None
    
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    matches = b64_pattern.findall(command)
    
    for match in matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if any(indicator in decoded.lower() for indicator in ['spinstall', 'machinekey', 'layouts']):
                return decoded[:500]
        except:
            continue
    return None
EOF

read -r -d '' IS_TOOLPANE << 'EOF' || true
from arroyo_udf import udf
import re

@udf
def is_toolpane_exploit(path: str, query: str, method: str, referer: str) -> bool:
    """Detect ToolPane exploitation patterns"""
    if not path or not method:
        return False
    
    if method.upper() != 'POST':
        return False
        
    if 'toolpane.aspx' not in path.lower():
        return False
        
    if query and 'displaymode=edit' in query.lower():
        return True
        
    bypass_patterns = [
        r'%54%6f%6f%6c%50%61%6e%65',
        r'tool[^a-z]*pane',
        r'\.\..*toolpane',
    ]
    
    combined = (path + (query or '')).lower()
    return any(re.search(pattern, combined, re.IGNORECASE) for pattern in bypass_patterns)
EOF

read -r -d '' EXTRACT_ACTOR << 'EOF' || true
from arroyo_udf import udf

@udf
def extract_threat_actor(ip: str) -> str:
    """Map IP to known threat actor"""
    actor_map = {
        '131.226.2.6': 'Storm-2603',
        '134.199.202.205': 'CN-Actor',
        '104.238.159.149': 'CN-Actor',
        '188.130.206.168': 'CN-Actor',
        '107.191.58.76': 'CN-Actor',
        '96.9.125.147': 'CN-NoShell'
    }
    return actor_map.get(ip, 'Unknown')
EOF

read -r -d '' CALC_RISK << 'EOF' || true
from arroyo_udf import udf

@udf
def calculate_risk_score(
    is_known_ip: bool,
    is_exploit_attempt: bool,
    has_webshell: bool,
    has_key_theft: bool,
    has_c2: bool
) -> int:
    """Calculate risk score 0-100"""
    score = 0
    if is_known_ip:
        score += 30
    if is_exploit_attempt:
        score += 25
    if has_webshell:
        score += 20
    if has_key_theft:
        score += 15
    if has_c2:
        score += 10
    return min(score, 100)
EOF

read -r -d '' EXTRACT_IOC << 'EOF' || true
from arroyo_udf import udf
import re
import json

@udf
def extract_ioc_context(
    file_path: str,
    file_hash: str,
    command_line: str,
    url: str
) -> str:
    """Extract IOC context as JSON"""
    iocs = {
        'webshells': [],
        'suspicious_paths': [],
        'c2_indicators': [],
        'key_theft': False
    }
    
    if file_path:
        if re.search(r'spinstall\d*\.aspx', file_path, re.IGNORECASE):
            iocs['webshells'].append(file_path)
        if 'xxx.aspx' in file_path.lower():
            iocs['webshells'].append(file_path)
        if 'debug_dev.js' in file_path.lower():
            iocs['key_theft'] = True
            
    known_hashes = {
        '92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514': 'spinstall0.aspx',
        'f5b60a8ead96703080e73a1f79c3e70ff44df271': 'spinstall0.aspx',
        'fe3a3042890c1f11361368aeb2cc12647a6fdae1': 'xxx.aspx'
    }
    
    if file_hash and file_hash.lower() in known_hashes:
        iocs['webshells'].append(f"{known_hashes[file_hash.lower()]} (hash: {file_hash[:8]}...)")
    
    if command_line:
        if any(key in command_line for key in ['MachineKey', 'ValidationKey', 'DecryptionKey']):
            iocs['key_theft'] = True
            
    if url and 'ngrok-free.app' in url:
        iocs['c2_indicators'].append(url)
        
    return json.dumps(iocs)
EOF

# Deploy each UDF
log_info "Starting UDF deployment..."

# 1. decode_base64_command
if validate_udf "decode_base64_command" "$DECODE_BASE64"; then
    create_udf "decode_base64_command" "$DECODE_BASE64" "$DESC_DECODE"
fi

# 2. is_toolpane_exploit
if validate_udf "is_toolpane_exploit" "$IS_TOOLPANE"; then
    create_udf "is_toolpane_exploit" "$IS_TOOLPANE" "$DESC_TOOLPANE"
fi

# 3. extract_threat_actor
if validate_udf "extract_threat_actor" "$EXTRACT_ACTOR"; then
    create_udf "extract_threat_actor" "$EXTRACT_ACTOR" "$DESC_ACTOR"
fi

# 4. calculate_risk_score
if validate_udf "calculate_risk_score" "$CALC_RISK"; then
    create_udf "calculate_risk_score" "$CALC_RISK" "$DESC_RISK"
fi

# 5. extract_ioc_context
if validate_udf "extract_ioc_context" "$EXTRACT_IOC"; then
    create_udf "extract_ioc_context" "$EXTRACT_IOC" "$DESC_IOC"
fi

log_info "UDF deployment complete!"
log_info "You can now deploy the SQL pipelines that use these UDFs"