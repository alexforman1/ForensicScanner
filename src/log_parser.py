# parser.py
import json
import re
from typing import List, Dict, Union, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

@dataclass
class Indicator:
    description: str
    severity: int
    category: str
    pattern: str  # Added pattern field for regex matching

@dataclass
class Finding:
    content: str
    severity: int
    indicators: List[Indicator]
    source_line: Optional[str] = None
    timestamp: Optional[str] = None

# Define suspicious patterns with regex patterns
SUSPICIOUS_PATTERNS = [
    Indicator(
        description="Port scan detected",
        severity=4,
        category="RECON",
        pattern=r"(?i)(scan|probe|discover).*port|(?:\b\d{1,5}\b.*){5,}"
    ),
    Indicator(
        description="Potential brute force attempt",
        severity=4,
        category="ATTACK",
        pattern=r"(?i)(failed|invalid|wrong).*(?:login|password|authentication)|authentication\s+failure"
    ),
    Indicator(
        description="Suspicious outbound connection",
        severity=3,
        category="MALWARE",
        pattern=r"(?i)(?:outbound|external).*(?:connection|traffic).*(?:unknown|suspicious|malicious)"
    ),
    Indicator(
        description="DNS query to known malicious domain",
        severity=5,
        category="C2",
        pattern=r"(?i)dns.*(?:query|lookup).*(?:malicious|suspicious|blocked)"
    ),
    Indicator(
        description="HTTP request with malicious payload",
        severity=5,
        category="EXPLOIT",
        pattern=r"(?i)(?:GET|POST|PUT).*(?:eval|exec|system|cmd|shell|script|wget|curl)"
    ),
    Indicator(
        description="Failed authentication attempt",
        severity=2,
        category="AUTH",
        pattern=r"(?i)(?:failed|invalid|error).*(?:login|auth|password)"
    ),
    Indicator(
        description="Unusual protocol behavior",
        severity=3,
        category="ANOMALY",
        pattern=r"(?i)(?:unusual|abnormal|unexpected).*(?:protocol|behavior|traffic)"
    ),
    Indicator(
        description="Data exfiltration attempt",
        severity=5,
        category="EXFIL",
        pattern=r"(?i)(?:upload|transfer|copy).*(?:large|multiple|suspicious).*(?:file|data)"
    ),
    Indicator(
        description="Privilege escalation attempt",
        severity=5,
        category="PRIVESC",
        pattern=r"(?i)(?:sudo|su|runas|privilege|admin).*(?:escalation|elevation)"
    ),
    Indicator(
        description="Suspicious file access",
        severity=3,
        category="ACCESS",
        pattern=r"(?i)(?:access|read|write).*(?:denied|unauthorized|suspicious)"
    ),
    # Network specific patterns
    Indicator(
        description="Suspicious network traffic pattern",
        severity=4,
        category="NETWORK",
        pattern=r"(?i)(?:syn|ack|fin|rst).*flood|(?:ddos|dos).*attack"
    ),
    Indicator(
        description="Malware communication pattern",
        severity=5,
        category="MALWARE",
        pattern=r"(?i)(?:beacon|callback|c2|command.*control)"
    ),
    # Process patterns
    Indicator(
        description="Suspicious process execution",
        severity=4,
        category="PROCESS",
        pattern=r"(?i)(?:cmd\.exe|powershell|bash).*(?:execute|spawn|run)"
    ),
    # File patterns
    Indicator(
        description="Suspicious file operation",
        severity=3,
        category="FILE",
        pattern=r"(?i)(?:create|modify|delete).*(?:system32|windows|etc)"
    )
]

def check_patterns(content: str) -> List[Indicator]:
    """Check content against all suspicious patterns."""
    matches = []
    for pattern in SUSPICIOUS_PATTERNS:
        try:
            if re.search(pattern.pattern, content, re.IGNORECASE):
                matches.append(pattern)
        except re.error as e:
            logger.error(f"Invalid regex pattern '{pattern.pattern}': {e}")
    return matches

def parse_wireshark_log(file_path: str) -> List[Finding]:
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                    
                # Check for suspicious patterns
                indicators = check_patterns(line)
                if indicators:
                    findings.append(Finding(
                        content=line,
                        severity=max(i.severity for i in indicators),
                        indicators=indicators,
                        source_line=str(line_num),
                        timestamp=datetime.now().isoformat()
                    ))
                    
    except Exception as e:
        logger.error(f"Error parsing Wireshark log: {e}")
    return findings

def parse_volatility_json(file_path: str) -> List[Finding]:
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
            
            # Handle both list and dict formats
            if isinstance(data, dict):
                items = [data]
            elif isinstance(data, list):
                items = data
            else:
                logger.error(f"Unexpected JSON format: {type(data)}")
                return findings
            
            for item in items:
                # Convert item to string for pattern matching
                item_str = json.dumps(item)
                
                # Check for suspicious patterns
                indicators = check_patterns(item_str)
                if indicators:
                    findings.append(Finding(
                        content=item_str[:1000],  # Limit content length
                        severity=max(i.severity for i in indicators),
                        indicators=indicators,
                        timestamp=datetime.now().isoformat()
                    ))
                    
    except Exception as e:
        logger.error(f"Error parsing Volatility JSON: {e}")
    return findings

def parse_volatility_text(file_path: str) -> List[Finding]:
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                    
                # Check for suspicious patterns
                indicators = check_patterns(line)
                if indicators:
                    findings.append(Finding(
                        content=line,
                        severity=max(i.severity for i in indicators),
                        indicators=indicators,
                        source_line=str(line_num),
                        timestamp=datetime.now().isoformat()
                    ))
                    
    except Exception as e:
        logger.error(f"Error parsing Volatility text: {e}")
    return findings

def parse_generic_text(file_path: str) -> List[Finding]:
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                    
                # Check for suspicious patterns
                indicators = check_patterns(line)
                if indicators:
                    findings.append(Finding(
                        content=line,
                        severity=max(i.severity for i in indicators),
                        indicators=indicators,
                        source_line=str(line_num),
                        timestamp=datetime.now().isoformat()
                    ))
                    
    except Exception as e:
        logger.error(f"Error parsing generic text: {e}")
    return findings

# For testing
if __name__ == "__main__":
    import sys
    
    def print_findings(findings: List[Finding]):
        for finding in findings:
            if finding.indicators:
                print(f"\nLine {finding.source_line}:")
                print(f"Content: {finding.content}")
                print(f"Severity: {finding.severity}")
                print("Indicators:")
                for indicator in finding.indicators:
                    print(f"- {indicator.description} (Severity: {indicator.severity})")
    
    if len(sys.argv) < 3:
        print("Usage: python parser.py <file_type> <file_path>")
        print("File types: wireshark, volatility_text, volatility_json, generic")
        sys.exit(1)
    
    file_type = sys.argv[1]
    file_path = sys.argv[2]
    
    parsers = {
        'wireshark': parse_wireshark_log,
        'volatility_text': parse_volatility_text,
        'volatility_json': parse_volatility_json,
        'generic': parse_generic_text
    }
    
    if file_type not in parsers:
        print(f"Unknown file type: {file_type}")
        sys.exit(1)
    
    findings = parsers[file_type](file_path)
    print_findings(findings)
