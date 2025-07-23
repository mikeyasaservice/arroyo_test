# Python UDFs for ToolShell Detection
from arroyo_udf import udf
import base64
import re
import json
from datetime import datetime

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
