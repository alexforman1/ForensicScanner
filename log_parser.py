# parser.py
import json
import re
from typing import List, Dict, Union, Optional, Any, Generator, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import ipaddress
from pathlib import Path
import gc
import psutil
import threading
from concurrent.futures import ThreadPoolExecutor
import weakref
import os
from queue import Queue, Empty
import mmap
from contextlib import contextmanager
import yaml
import collections
import time
from ai_analyzer import NetworkAIAnalyzer, AIAnalysis, RiskFactor
import fnmatch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('log_parser.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constants
MEMORY_THRESHOLD = 0.9  # 90% memory usage threshold
CHUNK_SIZE = 1024 * 1024  # 1MB chunks for file reading
MAX_THREADS = min(os.cpu_count() or 2, 2)  # Limit threads
FILE_TIMEOUT = 30  # File operation timeout in seconds
MAX_LINE_LENGTH = 1024  # Maximum line length to process

@dataclass
class Indicator:
    """Structure for threat indicators"""
    description: str
    category: str
    severity: int
    pattern: str
    confidence: float
    source: str
    timestamp: datetime = field(default_factory=datetime.now)

# Suspicious patterns with severity levels
SUSPICIOUS_PATTERNS = [
    Indicator(
        description="Port scan detected (Nmap/Masscan Only)",
        severity=3,
        category="RECON",
        pattern=r"(?i)(?:nmap|masscan|aggressive\s+scan).*(?:port|scan)",
        confidence=1.0,
        source="default"
    ),
    # Update SSH patterns to differentiate internal vs external
    Indicator(
        description="External SSH brute force attempt",
        severity=4,
        category="ATTACK",
        pattern=r"(?i)(?:failed|invalid)\s+ssh\s+(?:login|password|authentication).*?from\s+(?!192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        confidence=1.0,
        source="default"
    ),
    Indicator(
        description="Internal SSH failed login",
        severity=2,
        category="AUTH",
        pattern=r"(?i)(?:failed|invalid)\s+ssh\s+(?:login|password|authentication).*?from\s+(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.).*",
        confidence=1.0,
        source="default"
    ),
    # Separate pattern for successful internal SSH
    Indicator(
        description="Successful internal SSH login",
        severity=1,
        category="AUTH",
        pattern=r"(?i)accepted\s+(?:password|publickey)\s+for.*?from\s+(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.).*",
        confidence=1.0,
        source="default"
    ),
    Indicator(
        description="Suspicious outbound connection",
        severity=3,
        category="MALWARE",
        pattern=r"(?i)(?:outbound|external)\s+connection\s+to\s+(?:known\s+malicious|blacklisted|c2|command.*control)\s+(?:host|ip|domain)",
        confidence=1.0,
        source="default"
    ),
    # Update DNS patterns to differentiate normal vs suspicious
    Indicator(
        description="Routine DNS query",
        severity=1,
        category="NETWORK",
        pattern=r"(?i)dns\s+query\s+(?:to|for)\s+(?:google\.com|microsoft\.com|windowsupdate\.com|.*\.local)",
        confidence=1.0,
        source="default"
    ),
    Indicator(
        description="DNS query to known malicious domain",
        severity=5,
        category="C2",
        pattern=r"(?i)dns\s+query\s+(?:to|for)\s+(?:known\s+malicious|blacklisted|malware|c2)\s+domain:\s*\S+",
        confidence=1.0,
        source="default"
    ),
    # Update HTTP patterns to differentiate severity
    Indicator(
        description="Suspicious HTTP request",
        severity=2, # Lowered from 3, needs other factors to become high severity
        category="WEB",
        pattern=r"(?i)(?:GET|POST|PUT)\s+.*?(?:admin|login|wp-admin|phpmyadmin)",
        confidence=1.0,
        source="default"
    ),
    Indicator(
        description="Critical HTTP exploit attempt",
        severity=5,
        category="EXPLOIT",
        pattern=r"(?i)(?:GET|POST|PUT)\s+.*?(?:eval\(|exec\(|system\(|\bcmd\.exe\b|\bpowershell\s+-enc\b|\bbase64\b.*?\bexec\b)",
        confidence=1.0,
        source="default"
    ),
    # Update authentication patterns
    Indicator(
        description="Failed authentication - internal",
        severity=2,
        category="AUTH",
        pattern=r"(?i)(?:failed|invalid)\s+(?:login|auth|password).*?from\s+(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.).*",
        confidence=1.0,
        source="default"
    ),
    Indicator(
        description="Failed authentication - external",
        severity=4,
        category="AUTH",
        pattern=r"(?i)(?:failed|invalid)\s+(?:login|auth|password).*?from\s+(?!192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        confidence=1.0,
        source="default"
    ),
    # Network anomaly patterns with context
    Indicator(
        description="Unusual protocol behavior - internal",
        severity=2,
        category="ANOMALY",
        pattern=r"(?i)(?:unusual|abnormal|unexpected)\s+(?:protocol|behavior|traffic)\s+(?:detected|observed|found).*?(?:source|from):\s+(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.).*",
        confidence=1.0,
        source="default"
    ),
    Indicator(
        description="Unusual protocol behavior - external",
        severity=3,
        category="ANOMALY",
        pattern=r"(?i)(?:unusual|abnormal|unexpected)\s+(?:protocol|behavior|traffic)\s+(?:detected|observed|found).*?(?:source|from):\s+(?!192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        confidence=1.0,
        source="default"
    ),
    # Data exfiltration with size context
    Indicator(
        description="Large data transfer - internal",
        severity=2,
        category="EXFIL",
        pattern=r"(?i)(?:large|bulk)\s+(?:upload|transfer|copy)\s+(?:\d+\s*(?:MB|GB|TB)|(?:10|[2-9]0+)\+\s+files)\s+to\s+(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.).*",
        confidence=1.0,
        source="default"
    ),
    Indicator(
        description="Large data transfer - external",
        severity=4,
        category="EXFIL",
        pattern=r"(?i)(?:large|bulk)\s+(?:upload|transfer|copy)\s+(?:\d+\s*(?:MB|GB|TB)|(?:10|[2-9]0+)\+\s+files)\s+to\s+(?!192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        confidence=1.0,
        source="default"
    ),
    # Add patterns for IDS, Vulnerability, Misconfiguration
    Indicator(
        description="IDS Alert: Potential Exploit Detected",
        severity=4, # Start high for IDS alerts
        category="IDS_ALERT",
        # Example: Match Suricata/Snort style alerts (CUSTOMIZE THIS REGEX)
        pattern=r"(?i)(?:ET\s|SNORT\s).*?(?:EXPLOIT|MALWARE|ATTACK|POLICY).*?(?:Sig:.*?)?(?:Cls:.*?Exploit|Cls:.*?Malware)",
        confidence=0.9,
        source="default_ids"
    ),
    Indicator(
        description="IDS Alert: Suspicious Network Activity",
        severity=3,
        category="IDS_ALERT",
        # Example: Match less critical IDS alerts (CUSTOMIZE THIS REGEX)
        pattern=r"(?i)(?:ET\s|SNORT\s).*?(?:SCAN|INFO|POLICY|SUSPICIOUS|ANOMALY).*?(?:Sig:.*?)?(?:Cls:.*?Scan|Cls:.*?Info|Cls:.*?Policy)",
        confidence=0.8,
        source="default_ids"
    ),
    Indicator(
        description="Vulnerability Finding: Critical Severity",
        severity=5, # Critical vulnerabilities are high risk
        category="VULNERABILITY",
        # Example: Match vulnerability scanner output (CUSTOMIZE THIS REGEX)
        pattern=r"(?i)Vulnerability.*?(?:CVE-[0-9]{4}-[0-9]{4,}).*?(?:Severity|Risk):\s*(?:Critical|High|10\\.0|9\\.[0-9])",
        confidence=1.0,
        source="default_vuln"
    ),
    Indicator(
        description="Vulnerability Finding: Medium Severity",
        severity=3,
        category="VULNERABILITY",
        # Example: Match medium vulnerability findings (CUSTOMIZE THIS REGEX)
        pattern=r"(?i)Vulnerability.*?(?:CVE-[0-9]{4}-[0-9]{4,}).*?(?:Severity|Risk):\s*(?:Medium|[4-6]\\.[0-9])",
        confidence=0.9,
        source="default_vuln"
    ),
    Indicator(
        description="Misconfiguration: Insecure Service",
        severity=4,
        category="MISCONFIGURATION",
        # Example: Match configuration audit findings (CUSTOMIZE THIS REGEX)
        pattern=r"(?i)Misconfiguration.*?(?:Insecure|Weak|Default|Exposed).*?(?:Service|Setting|Password|Permissions)",
        confidence=0.9,
        source="default_config"
    )
]

@dataclass
class NetworkEvent:
    """Structure for network events with context."""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: str = ""
    process_name: str = ""
    dns_query: Optional[str] = None
    bytes_transferred: int = 0
    connection_duration: float = 0.0
    status: str = ""
    raw_log: str = ""

@dataclass
class ProcessEvent:
    """Structure for process events."""
    timestamp: datetime
    process_name: str
    pid: int
    parent_pid: Optional[int] = None
    user: str = ""
    command_line: str = ""
    path: str = ""
    status: str = ""
    raw_log: str = ""

@dataclass
class Finding:
    """Enhanced finding structure with context."""
    content: str
    severity: int
    indicators: List[Dict]
    source_file: str
    line_number: Optional[int] = None
    context: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    event_count: int = 1
    related_events: List[str] = field(default_factory=list)
    false_positive: bool = False
    analyst_feedback: str = ""
    risk_factors: List[RiskFactor] = field(default_factory=list)

@dataclass
class LogEvent:
    """Structure for log events."""
    timestamp: datetime
    event_type: str
    source: str
    details: Dict[str, Any]
    raw_log: str
    line_number: int

class ThreatPatterns:
    """Enhanced threat detection patterns"""
    
    # Network-based threats
    NETWORK_PATTERNS = {
        'port_scan': {
            'pattern': r'(?i)(scan|probe|discover).*port.*\b(\d{1,5})\b',
            'severity': 3,
            'category': 'NETWORK',
            'description': 'Potential port scanning activity detected'
        },
        'brute_force': {
            'pattern': r'(?i)(failed|invalid|bad).*(?:login|password|authentication).*attempts?',
            'severity': 4,
            'category': 'NETWORK',
            'description': 'Possible brute force attack'
        },
        'data_exfil': {
            'pattern': r'(?i)(upload|transfer|exfil).*(?:data|file).*(?:external|remote)',
            'severity': 4,
            'category': 'NETWORK',
            'description': 'Potential data exfiltration'
        }
    }
    
    # System-based threats
    SYSTEM_PATTERNS = {
        'privilege_escalation': {
            'pattern': r'(?i)(sudo|su|privilege|admin).*(?:escalation|elevation)',
            'severity': 5,
            'category': 'SYSTEM',
            'description': 'Potential privilege escalation attempt'
        },
        'file_manipulation': {
            'pattern': r'(?i)(modify|delete|change).*(?:system|config|binary).*files?',
            'severity': 4,
            'category': 'SYSTEM',
            'description': 'Suspicious file manipulation'
        }
    }
    
    # Malware indicators
    MALWARE_PATTERNS = {
        'command_control': {
            'pattern': r'(?i)(beacon|callback|c2|command.*control)',
            'severity': 5,
            'category': 'MALWARE',
            'description': 'Potential C2 communication'
        },
        'payload_execution': {
            'pattern': r'(?i)(execute|run|launch).*(?:payload|shellcode|malware)',
            'severity': 5,
            'category': 'MALWARE',
            'description': 'Suspicious payload execution'
        }
    }
    
    # Exploit attempts
    EXPLOIT_PATTERNS = {
        'injection': {
            'pattern': r'(?i)(sql|command|code).*injection',
            'severity': 4,
            'category': 'EXPLOIT',
            'description': 'Potential injection attack'
        },
        'overflow': {
            'pattern': r'(?i)(buffer|stack|heap).*overflow',
            'severity': 5,
            'category': 'EXPLOIT',
            'description': 'Potential overflow attack'
        }
    }
    
    # Suspicious IP patterns
    IP_PATTERNS = {
        'private_ip': {
            'pattern': r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
            'severity': 2,
            'category': 'NETWORK',
            'description': 'Private IP address detected'
        },
        'suspicious_ip': {
            'pattern': r'\b(?:1\.1\.1\.1|8\.8\.8\.8|8\.8\.4\.4)\b',
            'severity': 2,
            'category': 'NETWORK',
            'description': 'Known DNS server IP detected'
        }
    }

    @classmethod
    def get_all_patterns(cls) -> Dict:
        """Get all threat patterns"""
        return {
            **cls.NETWORK_PATTERNS,
            **cls.SYSTEM_PATTERNS,
            **cls.MALWARE_PATTERNS,
            **cls.EXPLOIT_PATTERNS,
            **cls.IP_PATTERNS
        }

class NetworkBaseline:
    """Enhanced network baseline with granular trust scoring and behavioral analysis."""
    
    def __init__(self):
        # Benign network patterns with refined thresholds and multipliers
        # Goal: Mark routine internal traffic as extremely low risk unless frequency is excessive.
        self.benign_patterns = {
            # DNS patterns - differentiate internal/external/common
            r'(?i)dns.*query.*(?:\\.local|\\.internal)': {'max_freq': 500, 'description': 'Internal DNS query', 'multiplier': 0.1}, # Very low risk for internal DNS
            r'(?i)dns.*query.*(?:google\\.com|microsoft\\.com|windowsupdate\\.com)': {'max_freq': 200, 'description': 'Common External DNS query', 'multiplier': 0.3},
            r'(?i)dns.*response.*(?:NXDOMAIN|SERVFAIL)': {'max_freq': 100, 'description': 'Failed DNS response', 'multiplier': 0.7}, # Slightly elevated risk for failures
            
            # ARP patterns - very high threshold for internal network, very low risk
            r'(?i)arp.*who-has.*(?:192\\.168\\.|10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.)': {'max_freq': 1000, 'description': 'Internal ARP request', 'multiplier': 0.1}, # Routine internal ARP
            r'(?i)arp.*reply.*(?:192\\.168\\.|10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.)': {'max_freq': 1000, 'description': 'Internal ARP reply', 'multiplier': 0.1}, # Routine internal ARP
            
            # DHCP patterns - normal for network joins, low risk
            r'(?i)dhcp.*discover': {'max_freq': 50, 'description': 'DHCP discover', 'multiplier': 0.2},
            r'(?i)dhcp.*offer': {'max_freq': 50, 'description': 'DHCP offer', 'multiplier': 0.2},
            
            # TCP handshake - differentiate internal vs external, very low risk for internal
            r'(?i)tcp.*syn.*(?:192\\.168\\.|10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.)': {'max_freq': 1000, 'description': 'Internal TCP SYN', 'multiplier': 0.2}, # Routine internal handshake
            r'(?i)tcp.*(?:syn-ack|ack).*(?:192\\.168\\.|10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.)': {'max_freq': 1000, 'description': 'Internal TCP handshake ACK', 'multiplier': 0.2}, # Routine internal handshake
            r'(?i)tcp.*syn.*(?!192\\.168\\.|10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.)': {'max_freq': 150, 'description': 'External TCP SYN', 'multiplier': 0.6}, # External SYN is slightly more interesting
            
            # Common services - low risk for standard internal traffic
            r'(?i)http.*(?:GET|POST)\\s+/(?!admin|login|wp-admin).*(?:192\\.168\\.|10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.)': {'max_freq': 500, 'description': 'Internal HTTP request', 'multiplier': 0.3},
            r'(?i)https.*(?:GET|POST)\\s+/(?!admin|login|wp-admin).*(?:192\\.168\\.|10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.)': {'max_freq': 500, 'description': 'Internal HTTPS request', 'multiplier': 0.3},
            r'(?i)ntp.*client': {'max_freq': 50, 'description': 'NTP client', 'multiplier': 0.2},
            r'(?i)smb.*negotiate.*(?:192\\.168\\.|10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.)': {'max_freq': 100, 'description': 'Internal SMB negotiation', 'multiplier': 0.4} # Internal SMB is common
        }
        
        # Enhanced trusted process definitions with base_trust_score (1.0 = high trust)
        self.trusted_processes = {
            'svchost.exe': {
                'paths': [r'C:\\Windows\\System32\\svchost.exe'],
                'users': ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'],
                'description': 'Windows Service Host',
                'allowed_ports': {80, 443, 53, 123, 445, 135, 139},
                'max_connections': 500,
                'base_trust_score': 0.8 # High trust, but not perfect
            },
            'lsass.exe': {
                'paths': [r'C:\\Windows\\System32\\lsass.exe'],
                'users': ['SYSTEM'],
                'description': 'Windows Security Process',
                'allowed_ports': {88, 389, 636, 3268, 3269},
                'max_connections': 200,
                'base_trust_score': 0.95 # Very high trust
            },
            'explorer.exe': {
                'paths': [r'C:\\Windows\\explorer.exe'],
                'users': ['*'],
                'description': 'Windows Explorer',
                'allowed_ports': {445, 139, 137, 138},
                'max_connections': 100,
                'base_trust_score': 0.7 # Moderate trust
            },
            'chrome.exe': {
                'paths': [r'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
                         r'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'],
                'users': ['*'],
                'description': 'Google Chrome Browser',
                'allowed_ports': {80, 443, 53},
                'max_connections': 200,
                'base_trust_score': 0.7 # Standard browser trust
            },
            'firefox.exe': {
                'paths': [r'C:\\Program Files\\Mozilla Firefox\\firefox.exe',
                         r'C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe'],
                'users': ['*'],
                'description': 'Mozilla Firefox Browser',
                'allowed_ports': {80, 443, 53},
                'max_connections': 200,
                'base_trust_score': 0.7 # Standard browser trust
            },
            'code.exe': {
                'paths': [r'C:\\Users\\*\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe'],
                'users': ['*'],
                'description': 'Visual Studio Code',
                'allowed_ports': {80, 443},
                'max_connections': 100,
                'base_trust_score': 0.6 # Lower trust for dev tool potentially running arbitrary code
            }
        }
        
        # Enhanced network services with port ranges and refined thresholds
        self.network_services = {
            # Standard services with adjusted thresholds
            'SSH': {'ports': [22], 'protocol': 'TCP', 'internal_only': False, 'max_failed_attempts': 5, 'risk_factor': 1.5}, # External SSH access is notable
            'DNS': {'ports': [53], 'protocol': 'UDP', 'internal_only': False, 'max_queries_per_min': 500, 'risk_factor': 0.5}, # High volume expected
            'HTTP': {'ports': [80, 8080], 'protocol': 'TCP', 'internal_only': False, 'max_requests_per_min': 1000, 'risk_factor': 0.8},
            'HTTPS': {'ports': [443, 8443], 'protocol': 'TCP', 'internal_only': False, 'max_requests_per_min': 1000, 'risk_factor': 0.7},
            'NTP': {'ports': [123], 'protocol': 'UDP', 'internal_only': False, 'max_requests_per_min': 50, 'risk_factor': 0.3},
            'SMTP': {'ports': [25, 587], 'protocol': 'TCP', 'internal_only': False, 'max_connections_per_min': 100, 'risk_factor': 1.0},
            
            # Internal-focused services
            'SMB': {'ports': [445], 'protocol': 'TCP', 'internal_only': True, 'max_connections_per_min': 200, 'risk_factor': 0.6}, # Higher internal threshold
            'RDP': {'ports': [3389], 'protocol': 'TCP', 'internal_only': True, 'max_attempts_per_min': 10, 'risk_factor': 1.2}, # RDP still notable even if internal
            'LDAP': {'ports': [389, 636], 'protocol': 'TCP', 'internal_only': True, 'max_queries_per_min': 500, 'risk_factor': 0.7},
            'SQL': {'ports': [1433, 1434], 'protocol': 'TCP', 'internal_only': True, 'max_connections_per_min': 100, 'risk_factor': 1.0}
        }
        
        # Enhanced time-based policies
        self.business_hours = {
            'start': 8,  # Expanded slightly: 8 AM
            'end': 18,   # Expanded slightly: 6 PM
            'days': {0, 1, 2, 3, 4},  # Monday to Friday
            'risk_multiplier': 0.7  # Lower risk during business hours
        }
        
        self.maintenance_windows = [
            {'day': 6, 'start': 22, 'end': 4, 'description': 'Weekend maintenance', 'risk_multiplier': 0.5},  # Lower risk during maintenance
            {'day': 3, 'start': 23, 'end': 1, 'description': 'Mid-week maintenance', 'risk_multiplier': 0.5}
        ]
        
        # Connection tracking - simplified, frequency checked directly in detector
        # self.connection_history = collections.defaultdict(list) # Removed - handled in detector
        # self.last_cleanup = datetime.now() # Removed
        # self.cleanup_interval = 300 # Removed

    def is_benign_pattern(self, log_content: str, frequency: int) -> Tuple[bool, str, float]:
        """Check if log matches benign pattern and get risk multiplier.
        Prioritize more specific patterns first.
        """
        # Sort patterns by length descending to match specific patterns first
        sorted_patterns = sorted(self.benign_patterns.items(), key=lambda item: len(item[0]), reverse=True)
        
        for pattern, info in sorted_patterns:
            try:
                if re.search(pattern, log_content):
                    # If frequency exceeds threshold, increase multiplier but still consider benign
                    multiplier = info['multiplier']
                    description = info['description']
                    if frequency > info['max_freq']:
                        multiplier *= 1.5 # Moderate increase for high frequency benign traffic
                        description += f" (High Frequency: {frequency} > {info['max_freq']})"
                    
                    # Return True, description, and calculated multiplier
                    return True, description, multiplier
            except re.error as e:
                logger.warning(f"Regex error in benign pattern '{pattern}': {e}")
                continue # Skip invalid patterns
                
        # No benign pattern matched
        return False, "", 1.0 # Default multiplier if no benign pattern matches

    def calculate_process_trust_score(self, process_name: str, ports: Optional[Set[int]] = None,
                                   path: Optional[str] = None, user: Optional[str] = None) -> Tuple[float, List[str]]:
        """Calculate trust score (0.0 = untrusted, 1.0 = fully trusted). Factors reduce trust from a base score."""
        base_trust = 0.1 # Default trust for unknown processes is very low
        reasons = ["Unknown process"] 
        
        if process_name in self.trusted_processes:
            process_info = self.trusted_processes[process_name]
            # Start with the base trust defined for this known process
            base_trust = process_info.get('base_trust_score', 0.5) 
            reasons = [f"Known process: {process_info['description']} (Base Trust: {base_trust:.2f})"]
            trust_penalty = 0.0 # Penalties accumulate for mismatches

            # Check path (if provided) - Mismatch incurs penalty
            if path:
                path_match = any(fnmatch.fnmatch(path.lower(), trusted_path.lower()) 
                               for trusted_path in process_info['paths'])
                if not path_match:
                    trust_penalty += 0.3 # Significant penalty for wrong path
                    reasons.append(f"PENALTY: Running from non-standard path: {path}")
                else:
                    reasons.append("Path matches trusted definition.")
            
            # Check user (if provided) - Mismatch incurs penalty
            if user:
                user_match = (process_info['users'] == ['*'] or user in process_info['users'])
                if not user_match:
                    trust_penalty += 0.2 # Moderate penalty for wrong user
                    reasons.append(f"PENALTY: Running as unexpected user: {user}")
                else:
                     reasons.append("User matches trusted definition.")
            
            # Check ports (if provided and defined) - Mismatch incurs penalty
            if ports and process_info.get('allowed_ports'):
                unexpected_ports = ports - process_info['allowed_ports']
                if unexpected_ports:
                    trust_penalty += 0.15 # Smaller penalty for unexpected ports
                    reasons.append(f"PENALTY: Using unexpected ports: {unexpected_ports}")
                else:
                    reasons.append("Ports match trusted definition.")
            
            # Calculate final trust score by subtracting penalties from base trust
            final_trust_score = base_trust - trust_penalty

        else:
            # Unknown process, keep the very low base trust
            final_trust_score = base_trust

        # Ensure score is clamped between 0.0 and 1.0
        return max(0.0, min(1.0, final_trust_score)), reasons 

    def calculate_connection_risk(self, source_ip: str, dest_ip: str, dest_port: int,
                               protocol: str, timestamp: datetime) -> Tuple[float, List[str]]:
        """Calculate risk score (1.0 = baseline) for a network connection. Lower is better."""
        risk_score = 1.0
        reasons = []
        
        source_location = self._get_location_factor(source_ip)
        dest_location = self._get_location_factor(dest_ip)
        
        # Check if connection is internal-to-internal: very low risk unless port/service is odd
        is_internal_comm = (source_location == 'internal' and dest_location == 'internal')
        if is_internal_comm:
            risk_score *= 0.3 # Significantly reduce baseline risk for internal traffic
            reasons.append("Internal communication")

        # Check service context and apply service-specific risk factor
        service_match = None
        service_risk_factor = 1.5 # Default risk for unknown/non-standard ports
        for service, info in self.network_services.items():
            # Check port ranges if defined, otherwise check single ports
            ports_to_check = info.get('ports', [])
            if isinstance(ports_to_check, range):
                port_match = dest_port in ports_to_check
            else: # Assume list/set
                port_match = dest_port in ports_to_check

            if port_match and protocol.upper() == info['protocol']:
                service_match = service
                service_risk_factor = info.get('risk_factor', 1.0) # Use defined risk factor
                reasons.append(f"Known service: {service} (Risk Factor: {service_risk_factor:.2f})")
                if info.get('internal_only', False) and dest_location != 'internal':
                    service_risk_factor *= 2.5 # High penalty for internal service accessed externally
                    reasons.append(f"WARN: Internal-only service '{service}' accessed from {dest_location}")
                break
        
        risk_score *= service_risk_factor
        if not service_match:
            reasons.append(f"WARN: Connection on uncommon port {dest_port}/{protocol}")
        
        # Apply location-based risk factors (less emphasis on internal-to-external)
        if source_location == 'external' and dest_location == 'internal':
            risk_score *= 1.5 # External source connecting internally is moderately risky
            reasons.append("External to internal connection")
        elif source_location == 'internal' and dest_location == 'external':
            risk_score *= 1.1 # Internal connecting out is less inherently risky
            reasons.append("Internal to external connection")
        elif source_location == 'external' and dest_location == 'external':
            risk_score *= 1.0 # External to external - baseline risk assumed via service factor
            reasons.append("External to external connection")
            
        # Apply time-based risk factor using multipliers from config
        time_multiplier = self._get_time_multiplier(timestamp)
        if time_multiplier != 1.0:
            risk_score *= time_multiplier
            reasons.append(f"Time factor applied: {time_multiplier:.2f}")
        
        # Ensure risk score doesn't go below a minimum floor (e.g., 0.1)
        return max(0.1, risk_score), reasons

    def _get_location_factor(self, ip: str) -> str:
        """Determine location factor for an IP address."""
        try:
            if ip == "127.0.0.1" or ip == "::1":
                return "localhost"
            
            ip_obj = ipaddress.ip_address(ip)
            
            if ip_obj.is_private:
                return "internal"
            elif ip_obj.is_global:
                return "external"
            elif ip_obj.is_multicast:
                return "multicast"
            else:
                return "special"
                
        except ValueError:
            return "unknown"

    def _get_time_multiplier(self, timestamp: datetime) -> float:
        """Calculate time-based risk multiplier (1.0 = normal)."""
        hour = timestamp.hour
        day = timestamp.weekday()
        
        # Check maintenance windows first (lowest risk)
        for window in self.maintenance_windows:
            # Handle overnight window correctly
            start, end = window['start'], window['end']
            in_window = False
            if start <= end: # Same day window
                if day == window['day'] and start <= hour < end:
                    in_window = True
            else: # Overnight window
                if day == window['day'] and hour >= start: # Current day, after start
                    in_window = True
                elif (day == (window['day'] + 1) % 7) and hour < end: # Next day, before end
                    in_window = True
            
            if in_window:
                return window['risk_multiplier'] # Return maintenance window multiplier
        
        # Check business hours (lower risk)
        bh = self.business_hours
        if day in bh['days'] and bh['start'] <= hour < bh['end']:
            return bh['risk_multiplier'] # Return business hours multiplier
            
        # Default: outside business hours and maintenance windows (higher risk)
        return 1.5 # Default higher risk multiplier for off-hours

class EventCorrelator:
    """Enhanced event correlation with improved time-window analysis."""
    def __init__(self, window_size: int = 300):
        self.window_size = window_size  # seconds
        self.network_events: Dict[str, List[NetworkEvent]] = collections.defaultdict(list)
        self.process_events: Dict[str, List[ProcessEvent]] = collections.defaultdict(list)
        self.event_frequencies: Dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
        self.baseline_frequencies: Dict[str, float] = {}
        self.last_baseline_update = datetime.now()
        self.baseline_update_interval = 3600  # 1 hour
        
    def add_network_event(self, event: NetworkEvent):
        """Add network event with enhanced correlation."""
        self.cleanup_old_events()
        key = f"{event.source_ip}:{event.dest_ip}"
        self.network_events[key].append(event)
        
        # Update frequency counters
        event_type = f"network_{event.protocol}_{event.dest_port}"
        self.event_frequencies[event_type][event.source_ip] += 1
        
        # Update baseline if needed
        self._update_baseline_if_needed()
        
    def add_process_event(self, event: ProcessEvent):
        """Add process event with enhanced correlation."""
        self.cleanup_old_events()
        self.process_events[event.process_name].append(event)
        
        # Update frequency counters
        event_type = f"process_{event.process_name}"
        self.event_frequencies[event_type][event.user] += 1
        
        # Update baseline if needed
        self._update_baseline_if_needed()
        
    def _update_baseline_if_needed(self):
        """Update baseline frequencies periodically."""
        now = datetime.now()
        if (now - self.last_baseline_update).total_seconds() >= self.baseline_update_interval:
            for event_type, counter in self.event_frequencies.items():
                if counter:
                    # Calculate average frequency per source
                    total_freq = sum(counter.values())
                    num_sources = len(counter)
                    self.baseline_frequencies[event_type] = total_freq / num_sources
            
            self.last_baseline_update = now
            
    def get_correlated_events(self, event: Union[NetworkEvent, ProcessEvent]) -> List[Dict]:
        """Get correlated events within the time window."""
        correlated = []
        event_time = event.timestamp
        window_start = event_time - timedelta(seconds=self.window_size)
        
        if isinstance(event, NetworkEvent):
            # Check for related network events
            key = f"{event.source_ip}:{event.dest_ip}"
            related_network = [
                e for e in self.network_events[key]
                if window_start <= e.timestamp <= event_time
            ]
            
            # Check for related process events
            if event.process_name:
                related_process = [
                    e for e in self.process_events[event.process_name]
                    if window_start <= e.timestamp <= event_time
                ]
                
                correlated.extend([
                    {
                        'type': 'process',
                        'timestamp': e.timestamp,
                        'details': {
                            'process_name': e.process_name,
                            'pid': e.pid,
                            'user': e.user
                        }
                    } for e in related_process
                ])
            
            correlated.extend([
                {
                    'type': 'network',
                    'timestamp': e.timestamp,
                    'details': {
                        'source_ip': e.source_ip,
                        'dest_ip': e.dest_ip,
                        'protocol': e.protocol,
                        'bytes': e.bytes_transferred
                    }
                } for e in related_network
            ])
            
        return sorted(correlated, key=lambda x: x['timestamp'])
        
    def get_frequency_score(self, event_type: str, source: str) -> float:
        """Calculate frequency-based risk score."""
        if event_type not in self.event_frequencies:
            return 0.0
            
        current_freq = self.event_frequencies[event_type][source]
        baseline_freq = self.baseline_frequencies.get(event_type, 0)
        
        if baseline_freq == 0:
            return 5.0 if current_freq > 10 else 0.0
            
        deviation = (current_freq - baseline_freq) / baseline_freq
        
        # Score based on deviation from baseline
        if deviation <= 0.1:  # Within 10% of baseline
            return 0.0
        elif deviation <= 0.5:  # Within 50% of baseline
            return 2.0
        elif deviation <= 1.0:  # Within 100% of baseline
            return 3.0
        elif deviation <= 2.0:  # Within 200% of baseline
            return 4.0
        else:
            return 5.0
            
    def cleanup_old_events(self):
        """Remove events outside the time window with memory management."""
        cutoff = datetime.now() - timedelta(seconds=self.window_size)
        
        # Cleanup network events
        for key in list(self.network_events.keys()):
            self.network_events[key] = [
                e for e in self.network_events[key]
                if e.timestamp > cutoff
            ]
            if not self.network_events[key]:
                del self.network_events[key]
                
        # Cleanup process events
        for key in list(self.process_events.keys()):
            self.process_events[key] = [
                e for e in self.process_events[key]
                if e.timestamp > cutoff
            ]
            if not self.process_events[key]:
                del self.process_events[key]
                
        # Cleanup frequency counters older than 24 hours
        day_old = datetime.now() - timedelta(days=1)
        self.event_frequencies.clear()
        
        # Force garbage collection after major cleanup
        if len(self.network_events) == 0 and len(self.process_events) == 0:
            gc.collect()

class ThreatDetector:
    """Enhanced threat detection with granular severity scaling and context awareness."""
    def __init__(self):
        self.baseline = NetworkBaseline()
        self.correlator = EventCorrelator()
        self.event_frequencies = collections.defaultdict(lambda: collections.defaultdict(int))
        self.last_cleanup = datetime.now()
        self.cleanup_interval = 300  # 5 minutes

    def analyze_network_event(self, event: NetworkEvent, file_path: str) -> Optional[Finding]:
        """Analyze network event (v5 scoring).
        Goal: Very strong mitigation for whitelisted/baseline events. Severity 3+ requires clear indicators.
        """
        try:
            # 1. Frequency & Benign Check (No change needed)
            # ...
            self._update_frequencies(event)
            event_freq = self._get_event_frequency(event)
            is_benign, benign_desc, benign_multiplier = self.baseline.is_benign_pattern(event.raw_log, event_freq)
            if is_benign and benign_multiplier < 1.5: # Suppress low-freq benign
                return None 

            # 2. Baseline Factors (No change needed)
            # ...
            process_trust_score, process_reasons = 1.0, ["Process info N/A"]
            if event.process_name:
                process_trust_score, process_reasons = self.baseline.calculate_process_trust_score(
                    event.process_name,
                    ports={event.source_port, event.dest_port} if event.source_port and event.dest_port else None
                )
            connection_risk, connection_reasons = self.baseline.calculate_connection_risk(
                event.source_ip, event.dest_ip, event.dest_port or 0,
                event.protocol, event.timestamp
            )
            
            # 3. Dynamic Factors (No change needed)
            # ...
            correlated = self.correlator.get_correlated_events(event)
            correlation_factor = self._calculate_correlation_factor(len(correlated))
            frequency_factor = self._calculate_frequency_factor(event, event_freq)

            # --- Refined Risk Calculation (v5) --- 
            risk_contributors = [] 
            contributing_factors = {} 
            combined_risk = connection_risk 
            risk_contributors.extend(connection_reasons)
            contributing_factors['BaseConnectionRisk'] = connection_risk

            # Apply Process Trust Multiplier (Increase risk for low trust)
            trust_multiplier = 1.0 
            if process_trust_score < 0.6: # Increase risk more significantly if trust < 0.6
                 trust_multiplier = 1.0 + (1.0 - process_trust_score) * 1.5 # Max ~2.5x
                 risk_contributors.extend(process_reasons) 
            elif process_trust_score < 0.8: # Slight increase for moderate trust
                 trust_multiplier = 1.0 + (1.0 - process_trust_score) * 0.5 # Max ~1.1x
                 risk_contributors.extend(process_reasons)
            # Else (trust >= 0.8), multiplier remains 1.0, high trust handled in mitigation.
            combined_risk *= trust_multiplier
            contributing_factors['ProcessTrustMultiplier'] = trust_multiplier
            
            # Apply Correlation & Frequency Boosts (only if > 1.0)
            if correlation_factor > 1.01:
                 combined_risk *= correlation_factor
                 risk_contributors.append(f"Correlation Boost (x{correlation_factor:.2f})")
                 contributing_factors['CorrelationFactor'] = correlation_factor
            if frequency_factor > 1.01:
                 combined_risk *= frequency_factor
                 risk_contributors.append(f"Frequency Boost (x{frequency_factor:.2f})")
                 contributing_factors['FrequencyFactor'] = frequency_factor

            # Apply Benign Pattern Adjustment (if applicable)
            if is_benign and benign_multiplier > 0:
                 combined_risk *= benign_multiplier 
                 risk_contributors.append(f"Benign Pattern Risk Adjustment (x{benign_multiplier:.2f}: {benign_desc})")
                 contributing_factors['BenignMultiplier'] = benign_multiplier
                 
            # *** Enhanced Mitigation Logic (v5) ***
            mitigation_applied = False
            # Primarily mitigate based on base connection risk & process trust.
            # Condition: Is base connection risk very low (e.g., internal known service) OR process trust very high?
            is_low_base_risk = connection_risk < 0.5 
            is_high_trust = process_trust_score >= 0.9 # Stricter threshold for high trust mitigation
            
            if (is_low_base_risk or is_high_trust) and combined_risk > 1.0: 
                 # Calculate potential risk *without* correlation/frequency boosts if base was low/trusted
                 mitigated_risk_base = connection_risk * trust_multiplier * benign_multiplier
                 # Allow *some* increase from freq/corr, but heavily dampened.
                 dampened_boost = 1.0 + (correlation_factor - 1.0)*0.1 + (frequency_factor - 1.0)*0.1
                 mitigated_risk_final = mitigated_risk_base * dampened_boost
                 
                 # Apply strong reduction, ensuring it doesn't go below a floor like 0.5
                 original_risk = combined_risk # Keep for logging/context
                 combined_risk = max(0.5, min(mitigated_risk_final, combined_risk * 0.3)) # Reduce by 70% or to mitigated, whichever is higher (but >= 0.5)
                 
                 mitigation_reason = f"MITIGATION: Risk reduced from {original_risk:.2f} due to "
                 if is_high_trust: mitigation_reason += f"high process trust ({process_trust_score:.2f}) "
                 if is_low_base_risk: mitigation_reason += f"low base connection risk ({connection_risk:.2f}) "
                 risk_contributors.append(mitigation_reason.strip() + ".")
                 mitigation_applied = True
                 
            contributing_factors['FinalCombinedRisk'] = combined_risk
            # --- End Refined Risk Calculation --- 
            
            # 5. Determine Severity Level (1-5) - Further Adjusted Thresholds
            # Make Sev 1/2 cover more ground, require stronger signals for 3+
            if combined_risk < 1.0:  # Default/Mitigated state
                severity = 1 
            elif combined_risk < 2.0: # Minor combined factors needed
                severity = 2 
            elif combined_risk < 4.0: # Moderate combined factors OR one strong one (low trust/high freq/corr)
                severity = 3 
            elif combined_risk < 6.0: # Multiple strong factors needed
                severity = 4 
            else: # Multiple critical factors / Overrides
                severity = 5
            
            # ... (Overrides section remains the same) ...

            # 6. Create Finding (if severity >= 2)
            # ... (RiskFactor creation and Finding object creation remains the same, using v4 logic)
            if severity >= 2:
                # Create RiskFactor objects from numeric factors and reasons
                risk_factors_list = [
                    RiskFactor(name="SeverityDecision", category="SUMMARY", description=f"Final Severity: {severity} based on Calculated Risk: {combined_risk:.2f}", score=float(severity)),
                    RiskFactor(name="BaseConnectionRisk", category="NETWORK", description="; ".join(connection_reasons), score=contributing_factors.get('BaseConnectionRisk', 0)),
                ]
                if event.process_name:
                     risk_factors_list.append(RiskFactor(name="ProcessTrust", category="PROCESS", description="; ".join(process_reasons), score=process_trust_score))
                if 'CorrelationFactor' in contributing_factors:
                     risk_factors_list.append(RiskFactor(name="CorrelationFactor", category="BEHAVIOR", description=f"{len(correlated)} correlated events", score=contributing_factors['CorrelationFactor']))
                if 'FrequencyFactor' in contributing_factors:
                     risk_factors_list.append(RiskFactor(name="FrequencyFactor", category="BEHAVIOR", description=f"Event frequency: {event_freq}", score=contributing_factors['FrequencyFactor']))
                if 'BenignMultiplier' in contributing_factors:
                    risk_factors_list.append(RiskFactor(name="BenignPatternMatch", category="BASELINE", description=f"{benign_desc}", score=contributing_factors['BenignMultiplier']))
                if mitigation_applied:
                     risk_factors_list.append(RiskFactor(name="RiskMitigation", category="BASELINE", description=mitigation_reason, score=0.0)) # Use the generated reason

                # Simplified indicators list
                simple_indicators = []
                for desc in risk_contributors[:4]:
                    if not desc.startswith("MITIGATION"):
                        # ... (indicator creation logic) ...
                        parts = desc.split('(')
                        indicator_type = parts[0].strip().replace("Boost","").replace("Factor","") or "Context"
                        category = "BEHAVIOR"
                        if "Connection" in indicator_type or "Port" in indicator_type or "Service" in indicator_type: category = "NETWORK"
                        if "Process" in indicator_type or "Trust" in indicator_type: category = "PROCESS"
                        if "Pattern" in indicator_type: category = "BASELINE"
                        simple_indicators.append({'type': indicator_type, 'category': category, 'description': desc})
                        
                # Build context string using all contributors
                context = self._build_network_context(
                    event, correlated, all_reasons=risk_contributors, frequency=event_freq, final_risk=combined_risk, final_severity=severity
                )
                
                # Return Finding object
                # ... (Finding creation) ...
                return Finding(
                    content=event.raw_log,
                    severity=severity,
                    indicators=simple_indicators, 
                    source_file=file_path, 
                    line_number=event.line_number if hasattr(event, 'line_number') else None, 
                    context=context,
                    timestamp=event.timestamp,
                    event_count=len(correlated),
                    risk_factors=risk_factors_list 
                )
            else:
                # Suppress severity 1
                return None
            
        except Exception as e:
            logger.exception(f"Error analyzing network event: {e}")
            return None

    def analyze_process_event(self, event: ProcessEvent, file_path: str) -> Optional[Finding]:
        """Analyze process event (v5 scoring).
        Goal: Strong mitigation for high trust & low cmd risk. Elevate for low trust/high cmd risk + dynamic factors.
        """
        try:
            # 1. Frequency (No change)
            # ...
            self._update_frequencies(event)
            event_freq = self._get_event_frequency(event)
            
            # 2. Baseline Factors (No change)
            # ...
            trust_score, trust_reasons = self.baseline.calculate_process_trust_score(
                event.process_name, path=event.path, user=event.user
            )
            cmd_risk, cmd_reasons = self._analyze_command_line(event.command_line or "")
            
            # 3. Dynamic Factors (No change)
            # ...
            correlated = self.correlator.get_correlated_events(event)
            correlation_factor = self._calculate_correlation_factor(len(correlated))
            frequency_factor = self._calculate_frequency_factor(event, event_freq)
            time_multiplier = self.baseline._get_time_multiplier(event.timestamp)

            # --- Refined Risk Calculation (v5) --- 
            risk_contributors = []
            contributing_factors = {}
            
            # Base risk: Higher of (risk from low trust) or (command line risk)
            trust_risk_multiplier = 1.0 + (1.0 - trust_score)**2 * 1.5 # Base risk increases with low trust
            base_process_risk = max(trust_risk_multiplier, cmd_risk) 
            combined_risk = base_process_risk
            risk_contributors.extend(trust_reasons) # Always include trust reasons
            contributing_factors['BaseTrustRiskMultiplier'] = trust_risk_multiplier
            if cmd_risk > 1.0: 
                 risk_contributors.extend(cmd_reasons)
                 contributing_factors['CommandLineRisk'] = cmd_risk
            else:
                 risk_contributors.append("Low command line risk.") # Add positive context
                 
            # Apply Dynamic Factors multiplicatively
            if correlation_factor > 1.01:
                combined_risk *= correlation_factor
                risk_contributors.append(f"Correlation Boost (x{correlation_factor:.2f})")
                contributing_factors['CorrelationFactor'] = correlation_factor
            if frequency_factor > 1.01:
                combined_risk *= frequency_factor
                risk_contributors.append(f"Frequency Boost (x{frequency_factor:.2f})")
                contributing_factors['FrequencyFactor'] = frequency_factor
            if time_multiplier > 1.01: 
                combined_risk *= time_multiplier
                risk_contributors.append(f"Off-Hours Execution (x{time_multiplier:.2f})")
                contributing_factors['TimeFactor'] = time_multiplier

            # *** Enhanced Mitigation Logic (v5) ***
            mitigation_applied = False
            # Mitigate heavily if trust is very high AND command risk is low/moderate
            if trust_score >= 0.9 and cmd_risk < 2.5 and combined_risk > 1.0: # Relaxed cmd_risk condition slightly
                # Recalculate with heavily dampened dynamic factors
                mitigated_risk_base = max(1.0, cmd_risk) # Start with cmd_risk or 1.0
                dampened_boost = 1.0 + (correlation_factor - 1.0)*0.05 + (frequency_factor - 1.0)*0.05 + (time_multiplier - 1.0)*0.1 
                mitigated_risk_final = mitigated_risk_base * dampened_boost
                
                original_risk = combined_risk
                combined_risk = max(0.5, min(mitigated_risk_final, combined_risk * 0.25)) # Very strong reduction (75%)
                
                mitigation_reason = f"MITIGATION: Risk reduced from {original_risk:.2f} due to high process trust ({trust_score:.2f}) and low/moderate cmd risk ({cmd_risk:.1f})."
                risk_contributors.append(mitigation_reason)
                mitigation_applied = True
            
            contributing_factors['FinalCombinedRisk'] = combined_risk
            # --- End Refined Risk Calculation --- 

            # 5. Determine Severity Level (1-5) - Refined Thresholds
            if combined_risk < 1.2: # Wider range for sev 1
                severity = 1
            elif combined_risk < 2.2: # Sev 2 needs slightly more
                severity = 2 
            elif combined_risk < 4.5: # Sev 3 requires moderate factors
                severity = 3
            elif combined_risk < 7.0: # Sev 4 requires strong factors
                severity = 4
            else: # Sev 5 for critical combinations
                severity = 5

            # 6. Create Finding (if severity >= 2)
            # ... (RiskFactor creation and Finding object creation similar to network, using v4 logic)
            if severity >= 2:
                risk_factors_list = [
                    RiskFactor(name="SeverityDecision", category="SUMMARY", description=f"Final Severity: {severity} based on Calculated Risk: {combined_risk:.2f}", score=float(severity)),
                    RiskFactor(name="ProcessTrust", category="PROCESS", description="; ".join(trust_reasons), score=trust_score),
                ]
                if 'CommandLineRisk' in contributing_factors:
                     risk_factors_list.append(RiskFactor(name="CommandLineRisk", category="PROCESS", description="; ".join(cmd_reasons), score=contributing_factors['CommandLineRisk']))
                if 'CorrelationFactor' in contributing_factors:
                     risk_factors_list.append(RiskFactor(name="CorrelationFactor", category="BEHAVIOR", description=f"{len(correlated)} correlated events", score=contributing_factors['CorrelationFactor']))
                if 'FrequencyFactor' in contributing_factors:
                     risk_factors_list.append(RiskFactor(name="FrequencyFactor", category="BEHAVIOR", description=f"Event frequency: {event_freq}", score=contributing_factors['FrequencyFactor']))
                if 'TimeFactor' in contributing_factors:
                     risk_factors_list.append(RiskFactor(name="TimeContextFactor", category="BEHAVIOR", description=f"Execution time factor", score=contributing_factors['TimeFactor']))
                if mitigation_applied:
                     risk_factors_list.append(RiskFactor(name="RiskMitigation", category="BASELINE", description=mitigation_reason, score=0.0))

                simple_indicators = []
                for desc in risk_contributors[:4]:
                     if not desc.startswith("MITIGATION"):
                         # ... (indicator creation logic) ...
                        parts = desc.split('(')
                        indicator_type = parts[0].strip().replace("Boost","").replace("Factor","") or "Context"
                        category = "BEHAVIOR"
                        if "Connection" in indicator_type or "Port" in indicator_type or "Service" in indicator_type: category = "NETWORK"
                        if "Process" in indicator_type or "Trust" in indicator_type or "Command" in indicator_type: category = "PROCESS"
                        if "Pattern" in indicator_type: category = "BASELINE"
                        simple_indicators.append({'type': indicator_type, 'category': category, 'description': desc})

                context = self._build_process_context(
                    event, correlated, all_reasons=risk_contributors, frequency=event_freq, final_risk=combined_risk, final_severity=severity
                )
                
                # ... (Finding creation) ...
                return Finding(
                    content=event.raw_log,
                    severity=severity,
                    indicators=simple_indicators,
                    source_file=file_path, 
                    line_number=event.line_number if hasattr(event, 'line_number') else None,
                    context=context,
                    timestamp=event.timestamp,
                    event_count=len(correlated),
                    risk_factors=risk_factors_list
                )
            else:
                # Suppress severity 1
                return None

        except Exception as e:
            logger.exception(f"Error analyzing process event: {e}")
            return None

    # ... (rest of ThreatDetector methods) ...

    def _update_frequencies(self, event: Union[NetworkEvent, ProcessEvent]):
        """Update event frequencies and cleanup old entries."""
        now = datetime.now()
        # Cleanup old frequencies if needed (every 5 mins)
        if (now - self.last_cleanup).total_seconds() >= self.cleanup_interval:
            # Basic cleanup: Clear counts older than a longer window (e.g., 1 hour) 
            # More sophisticated baseline needed for true anomaly detection
            hour_ago = now - timedelta(hours=1)
            for key, sources in list(self.event_frequencies.items()):
                for source, timestamps in list(sources.items()): # Assuming storing timestamps
                    # Keep only timestamps within the last hour
                    valid_timestamps = [t for t in timestamps if t > hour_ago]
                    if not valid_timestamps:
                        del self.event_frequencies[key][source]
                    else:
                         self.event_frequencies[key][source] = valid_timestamps # Update list
                if not self.event_frequencies[key]:
                    del self.event_frequencies[key]
            self.last_cleanup = now
        
        # Simplified: Just count occurrences per source/key in the current run
        # For frequency factor calculation, a simple count over the session is used.
        # A stateful baseline would be needed for real anomaly detection.
        if isinstance(event, NetworkEvent):
            # Key could be finer (e.g., include dest_port) or broader
            key = f"net:{event.source_ip}->{event.dest_ip}" 
            source = f"{event.protocol}:{event.dest_port or 0}" # Count per service from source
        else: # ProcessEvent
            key = f"proc:{event.process_name}" 
            source = event.user or "UnknownUser" # Count per user for a process
            
        # Increment simple counter for this session
        self.event_frequencies[key][source] = self.event_frequencies[key].get(source, 0) + 1

    def _get_event_frequency(self, event: Union[NetworkEvent, ProcessEvent]) -> int:
        """Get current frequency count for an event type/source in this session."""
        if isinstance(event, NetworkEvent):
            key = f"net:{event.source_ip}->{event.dest_ip}"
            source = f"{event.protocol}:{event.dest_port or 0}"
        else:
            key = f"proc:{event.process_name}" 
            source = event.user or "UnknownUser"
            
        return self.event_frequencies[key].get(source, 0)

    def _calculate_correlation_factor(self, correlation_count: int) -> float:
        """Calculate factor (1.0 = baseline) based on correlation count."""
        if correlation_count <= 1: # No correlation or just self
            return 1.0
        elif correlation_count <= 3:
            return 1.2 # Small boost for few correlations
        elif correlation_count <= 7:
            return 1.5 # Moderate boost
        elif correlation_count <= 15:
            return 2.0 # Significant boost
        else:
            return 2.5 # Maximum boost for high correlation

    def _calculate_frequency_factor(self, event: Union[NetworkEvent, ProcessEvent], frequency: int) -> float:
        """Calculate frequency factor (1.0 = baseline) based on event type and frequency."""
        # Define thresholds based on event type (these could be refined further)
        if isinstance(event, NetworkEvent):
            # Allow higher frequency for network events, especially internal
            loc = self.baseline._get_location_factor(event.source_ip)
            if loc == 'internal':
                thresholds = {'low': 100, 'medium': 500, 'high': 1000, 'critical': 2000}
            else: # External or other
                thresholds = {'low': 20, 'medium': 100, 'high': 300, 'critical': 500}
        else: # ProcessEvent
            # Lower frequency tolerance for process events
            thresholds = {'low': 5, 'medium': 15, 'high': 30, 'critical': 50}

        if frequency <= thresholds['low']:
            return 1.0 # Baseline
        elif frequency <= thresholds['medium']:
            return 1.2 # Low frequency increase
        elif frequency <= thresholds['high']:
            return 1.6 # Medium frequency increase
        elif frequency <= thresholds['critical']:
            return 2.2 # High frequency increase
        else:
            return 3.0 # Critical frequency increase
    
    def _analyze_command_line(self, command_line: str) -> Tuple[float, List[str]]:
        risk_score = 1.0
        reasons = []
        matched_severities = []
        suspicious_patterns = [
            (r'(?i)(?:nc|netcat)\\s+-[el]', 'Netcat execution listener', 5.0),
            (r'(?i)powershell\\s+-[^a-zA-Z]*e[^a-zA-Z]*c', 'PowerShell encoded command', 5.0),
            (r'(?i)(?:mimikatz|psexec|bloodhound)', 'Known hacking tool', 5.0),
            (r'(?i)(?:wget|curl)\\s+http.*\\.exe', 'Download executable from HTTP', 4.5), # Increased slightly
            (r'(?i)base64\\s*-d', 'Base64 decode operation', 4.0),
            (r'(?i)\\\\temp\\\\.*\\.exe', 'Execute from temp directory', 4.0),
            (r'(?i)(?:reg|regedit).*(?:add|delete|modify)', 'Registry modification', 3.5), # Increased slightly
            (r'(?i)(?:net\\s+user|net\\s+localgroup)', 'User/Group manipulation', 3.5), # Increased slightly
            (r'(?i)(?:chmod|icacls)\\s+[+]x', 'Making file executable', 3.0),
            (r'(?i)(?:whoami|systeminfo|ipconfig|netstat)\\s+-[a-z]*', 'System enumeration', 2.5), # Increased slightly
            (r'(?i)(?:wget|curl)\\s+http', 'Download from HTTP source', 2.0),
            (r'(?i)\\\\temp\\', 'Access temp directory', 1.5) # Reduced slightly
        ]
        for pattern, description, severity in suspicious_patterns:
            if re.search(pattern, command_line):
                reasons.append(description)
                matched_severities.append(severity)
        if matched_severities:
            risk_score = max(matched_severities)
            if len(matched_severities) > 1:
                additional_severity = sum(sorted(matched_severities[:-1], reverse=True)) * 0.2
                risk_score = min(5.0, risk_score + additional_severity)
        return risk_score, reasons

    def _build_network_context(self, event: NetworkEvent, correlated: List[Dict],
                             reasons: List[str], frequency: int, final_risk: float, final_severity: int) -> str:
        """Build detailed context for network events, including final score/severity."""
        context_lines = [
            f"Network Event Analysis (Severity: {final_severity}, Risk Score: {final_risk:.2f}):",
            f"Source IP: {event.source_ip} ({self.baseline._get_location_factor(event.source_ip)})",
            f"Destination IP: {event.dest_ip} ({self.baseline._get_location_factor(event.dest_ip)})",
            f"Protocol: {event.protocol}",
            f"Ports: {event.source_port} -> {event.dest_port}",
            f"Frequency: {frequency} occurrences",
            "",
            "Analysis Reasons:"
        ]
        for reason in reasons:
            context_lines.append(f"- {reason}")
        if correlated:
            context_lines.extend([
                "",
                f"Related Events ({len(correlated)}):"
            ])
            for i, evt in enumerate(correlated[:5], 1):
                context_lines.append(f"{i}. {evt['type']} at {evt['timestamp']} - Details: {evt.get('details', {})}")
        return "\n".join(context_lines)

    def _build_process_context(self, event: ProcessEvent, correlated: List[Dict],
                             reasons: List[str], frequency: int, final_risk: float, final_severity: int) -> str:
        """Build detailed context for process events, including final score/severity."""
        context_lines = [
            f"Process Event Analysis (Severity: {final_severity}, Risk Score: {final_risk:.2f}):",
            f"Process: {event.process_name}",
            f"PID: {event.pid}",
            f"User: {event.user}",
            f"Path: {event.path}",
            f"Command Line: {event.command_line}",
            f"Frequency: {frequency} occurrences",
            "",
            "Analysis Reasons:"
        ]
        for reason in reasons:
            context_lines.append(f"- {reason}")
        if correlated:
            context_lines.extend([
                "",
                f"Related Events ({len(correlated)}):"
            ])
            for i, evt in enumerate(correlated[:5], 1):
                 context_lines.append(f"{i}. {evt['type']} at {evt['timestamp']} - Details: {evt.get('details', {})}")
        return "\n".join(context_lines)

class LogParser:
    """Enhanced log parser with context-aware analysis."""
    
    def __init__(self, max_workers: int = MAX_THREADS):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.threat_detector = ThreatDetector()
        self.cleanup_event = threading.Event()
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
        self.correlator = self.threat_detector.correlator 
        self.event_buffer = collections.deque(maxlen=1000)  # Store recent raw events for context
        
    def _cleanup_worker(self):
        """Background worker for cleanup tasks."""
        while not self.cleanup_event.is_set():
            try:
                # Check memory usage periodically
                if not self._check_memory():
                    gc.collect()
                # Sleep for a short interval
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error in cleanup worker: {e}")
                break
        
        # Final cleanup
        try:
            gc.collect()
        except:
            pass

    def parse_file(self, file_path: str) -> List[Finding]:
        """Parse file integrating pattern matching and dynamic ThreatDetector analysis."""
        findings = []
        try:
            # Ensure memory is checked before processing a potentially large file
            if not self._check_memory():
                logger.error(f"Insufficient memory to process {file_path}")
                return []

            with self._open_file_safely(file_path) as f:
                for line_num, raw_line in enumerate(self._read_lines(f), 1):
                    if not raw_line or len(raw_line) > MAX_LINE_LENGTH * 2: # Skip empty or excessively long lines
                        continue
                        
                    try:
                        line = raw_line.replace('\x00', '').strip()
                        if not line:
                            continue

                        # 1. Attempt to parse into a structured event (NetworkEvent, ProcessEvent, or basic LogEvent)
                        structured_event = self._parse_log_line(line, line_num)
                        if structured_event and isinstance(structured_event, (NetworkEvent, ProcessEvent)):
                            # Add structured network/process events to correlator
                            if isinstance(structured_event, NetworkEvent):
                                self.correlator.add_network_event(structured_event)
                            else:
                                self.correlator.add_process_event(structured_event)
                            # Store raw log in event buffer for basic context if needed later
                            self.event_buffer.append(structured_event.raw_log) 
                        elif structured_event: # Generic LogEvent parsed
                            self.event_buffer.append(structured_event.raw_log)
                        else: # Could not parse line structurally
                            self.event_buffer.append(line) # Still store raw line
                            structured_event = None # Ensure it's None if parsing failed

                        # 2. Check Basic Patterns (SUSPICIOUS_PATTERNS)
                        # This catches IDS, Vuln, Config patterns, and simple log matches.
                        pattern_finding: Optional[Finding] = None
                        matched_pattern_indicator: Optional[Indicator] = None
                        for indicator_pattern in SUSPICIOUS_PATTERNS:
                            try:
                                if re.search(indicator_pattern.pattern, line, re.IGNORECASE):
                                    # Create a basic finding based *only* on the pattern
                                    # Use the highest severity if multiple patterns match this line
                                    if pattern_finding is None or indicator_pattern.severity > pattern_finding.severity:
                                        pattern_finding = Finding(
                                            content=line,
                                            severity=indicator_pattern.severity,
                                            indicators=[{
                                                'type': 'PatternMatch', 
                                                'category': indicator_pattern.category,
                                                'description': indicator_pattern.description
                                            }],
                                            source_file=file_path,
                                            line_number=line_num,
                                            timestamp=structured_event.timestamp if structured_event else datetime.now(), # Use parsed time if available
                                            # Use 'score' based on pattern severity for RiskFactor
                                            risk_factors=[RiskFactor(name="PatternMatch", category=indicator_pattern.category, description=indicator_pattern.description, score=float(indicator_pattern.severity))]
                                        )
                                        matched_pattern_indicator = indicator_pattern # Keep track of the highest severity pattern
                            except re.error as e:
                                logger.warning(f"Regex error in SUSPICIOUS_PATTERNS '{indicator_pattern.pattern}': {e}")
                                continue

                        # 3. Perform Dynamic Analysis (if applicable)
                        # If we parsed a Network or Process event, run it through the ThreatDetector
                        dynamic_finding: Optional[Finding] = None
                        if isinstance(structured_event, NetworkEvent):
                            dynamic_finding = self.threat_detector.analyze_network_event(structured_event, file_path)
                        elif isinstance(structured_event, ProcessEvent):
                            dynamic_finding = self.threat_detector.analyze_process_event(structured_event, file_path)

                        # 4. Decide Which Finding to Keep
                        # Prioritize the dynamic finding if it exists and is more severe than the pattern finding.
                        # Also keep dynamic finding if it exists and pattern finding doesn't.
                        final_finding: Optional[Finding] = None
                        if dynamic_finding:
                            if pattern_finding:
                                # If dynamic is more severe OR pattern was just low severity AUTH/NETWORK, prefer dynamic
                                if dynamic_finding.severity >= pattern_finding.severity or \
                                   (matched_pattern_indicator and matched_pattern_indicator.category in ['AUTH', 'NETWORK', 'BASELINE'] and matched_pattern_indicator.severity <= 2):
                                    final_finding = dynamic_finding
                                else:
                                    # Pattern finding was more severe (e.g., critical IDS alert), keep it
                                    # Optional: Could merge indicators/context here if needed
                                    final_finding = pattern_finding 
                            else:
                                # Only dynamic finding exists
                                final_finding = dynamic_finding
                        elif pattern_finding:
                            # Only pattern finding exists
                            final_finding = pattern_finding
                        # Else: Neither pattern nor dynamic analysis yielded a significant finding

                        # 5. Add the final finding to the list if it meets threshold (severity >= 1)
                        if final_finding and final_finding.severity >= 1:
                            # Add basic context from recent raw logs if detailed context is missing
                            if not final_finding.context:
                                final_finding.context = self._get_raw_log_context(line_num)
                            findings.append(final_finding)
                            
                    except Exception as e:
                        logger.error(f"Error processing line {line_num} in {file_path}: {e}", exc_info=True) # Add stack trace
                        continue
                        
        except Exception as e:
            logger.error(f"Error parsing file {file_path}: {e}", exc_info=True)
        
        logger.info(f"Completed parsing {file_path}. Found {len(findings)} findings with severity >= 1.")
        # Optional: Log details of findings counts per severity level
        # severity_counts = collections.Counter(f.severity for f in findings)
        # logger.info(f"Severity distribution: {dict(severity_counts)}")
        
        return findings

    def _parse_log_line(self, line: str, line_num: int) -> Optional[Union[NetworkEvent, ProcessEvent, LogEvent]]:
        """Attempt to parse a log line into a NetworkEvent, ProcessEvent, or generic LogEvent."""
        try:
            # Prioritize more specific parsers (Windows Event, Syslog with details) first
            parsed_event = (
                self._parse_windows_event_detailed(line, line_num) or # Try detailed Windows parser
                self._parse_syslog_detailed(line, line_num) or       # Try detailed Syslog parser
                self._parse_json_log(line, line_num)                # Try JSON parser
                # Add other specific parsers here
            )

            if parsed_event:
                return parsed_event # Return NetworkEvent or ProcessEvent if parsed successfully
            else:
                # Fallback to basic LogEvent structure if no specific parse worked
                # Try to extract at least a timestamp
                timestamp = self._parse_timestamp(line) # Attempt to find timestamp anywhere
                # Basic source extraction (e.g., first word)
                source = line.split(' ', 1)[0] if ' ' in line else 'unknown' 
                return LogEvent(
                    timestamp=timestamp,
                    event_type='GENERIC',
                    source=source,
                    details={'message': line}, # Store full line as message
                    raw_log=line,
                    line_number=line_num
                )

        except Exception as e:
            logger.warning(f"Failed to parse line {line_num}: '{line[:100]}...'. Error: {e}")
            return None # Return None if parsing completely fails

    def _parse_windows_event_detailed(self, line: str, line_num: int) -> Optional[Union[NetworkEvent, ProcessEvent]]:
        # Try Process Creation Event (4688)
        proc_pattern = r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?EventID=(?P<event_id>4688).*?New Process Name:\s*(?P<process_path>[^\n]+?)\s+.*?Creator Process Name:\s*(?P<parent_path>[^\n]+?)\s+.*?Process Command Line:\s*(?P<command_line>[^\n]*)'
        match = re.search(proc_pattern, line, re.IGNORECASE | re.DOTALL)
        if match:
            data = match.groupdict()
            process_name = os.path.basename(data['process_path'].strip())
            parent_pid = None # PID often not directly available in 4688 text logs easily
            user = "Unknown" # User info often in separate fields not easily regexed here
            return ProcessEvent(
                timestamp=self._parse_timestamp(data['timestamp']),
                process_name=process_name,
                pid=0, # Placeholder PID
                parent_pid=parent_pid,
                user=user,
                command_line=data['command_line'].strip(),
                path=data['process_path'].strip(),
                status='Created',
                raw_log=line,
            )

        # Try Network Connection Event (5156 - Windows Filtering Platform)
        net_pattern = r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?EventID=(?P<event_id>5156).*?Application Name:\s*(?P<process_path>[^\n]+?)\s+.*?Source Address:\s*(?P<src_ip>[^\s]+)\s+Source Port:\s*(?P<src_port>\d+)\s+Dest Address:\s*(?P<dst_ip>[^\s]+)\s+Dest Port:\s*(?P<dst_port>\d+)\s+Protocol:\s*(?P<protocol_num>\d+)'
        match = re.search(net_pattern, line, re.IGNORECASE | re.DOTALL)
        if match:
            data = match.groupdict()
            protocol_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}
            protocol = protocol_map.get(data['protocol_num'], data['protocol_num'])
            process_name = os.path.basename(data['process_path'].strip()) if data['process_path'] else 'Unknown'
            return NetworkEvent(
                timestamp=self._parse_timestamp(data['timestamp']),
                source_ip=data['src_ip'],
                dest_ip=data['dst_ip'],
                source_port=int(data['src_port']),
                dest_port=int(data['dst_port']),
                protocol=protocol,
                process_name=process_name,
                status='Allowed', # Assuming 5156 often logs allowed connections, adjust if needed
                raw_log=line
            )
        return None # No detailed Windows event match

    def _parse_syslog_detailed(self, line: str, line_num: int) -> Optional[Union[NetworkEvent, ProcessEvent]]:
        # Example: Parse SSH login success/failure into NetworkEvent
        ssh_pattern = r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?sshd\[\d+\]:\s+(?P<status>Accepted|Failed)\s+(?:password|publickey)\s+for\s+(?P<user>[^\s]+)\s+from\s+(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+(?P<src_port>\d+)'
        match = re.search(ssh_pattern, line)
        if match:
            data = match.groupdict()
            return NetworkEvent(
                timestamp=self._parse_timestamp(data['timestamp']),
                source_ip=data['src_ip'],
                dest_ip='self', # Destination is the SSH server itself
                source_port=int(data['src_port']),
                dest_port=22, # Standard SSH port
                protocol='TCP',
                process_name='sshd',
                status=data['status'].capitalize(),
                raw_log=line
            )
        
        # Add more specific syslog parsers here (e.g., for process starts, other network services)
        
        return None # No detailed Syslog match

    def _parse_json_log(self, line: str, line_num: int) -> Optional[Union[NetworkEvent, ProcessEvent]]:
        """Parse JSON logs, attempting to map fields to NetworkEvent or ProcessEvent."""
        try:
            data = json.loads(line)
            if not isinstance(data, dict):
                return None

            timestamp = self._parse_timestamp(data.get('timestamp', data.get('@timestamp', data.get('time', ''))))

            # Heuristic check for Network Event fields
            if all(k in data for k in ['src_ip', 'dst_ip', 'dst_port', 'protocol']):
                return NetworkEvent(
                    timestamp=timestamp,
                    source_ip=str(data['src_ip']),
                    dest_ip=str(data['dst_ip']),
                    source_port=int(data.get('src_port', 0)),
                    dest_port=int(data['dst_port']),
                    protocol=str(data['protocol']).upper(),
                    process_name=str(data.get('process_name', data.get('app_name', ''))),
                    bytes_transferred=int(data.get('bytes', data.get('bytes_sent', 0)) + data.get('bytes_received', 0)),
                    status=str(data.get('status', data.get('action', ''))),
                    raw_log=line
                )
            
            # Heuristic check for Process Event fields
            if all(k in data for k in ['process_name', 'pid']) or 'command_line' in data:
                return ProcessEvent(
                    timestamp=timestamp,
                    process_name=str(data.get('process_name', '')),
                    pid=int(data.get('pid', data.get('process_id', 0))),
                    parent_pid=int(data.get('parent_pid', data.get('parent_process_id')))\
                               if data.get('parent_pid') or data.get('parent_process_id') else None,
                    user=str(data.get('user', data.get('username', ''))),
                    command_line=str(data.get('command_line', data.get('cmdline', ''))),
                    path=str(data.get('path', data.get('exe', ''))),
                    status=str(data.get('status', data.get('action', ''))),
                    raw_log=line
                )

            # Could not map to Network/Process, return None for specific parsing
            return None 

        except (json.JSONDecodeError, ValueError, TypeError) as e:
            # logger.debug(f"Line {line_num} is not valid JSON or failed mapping: {e}")
            return None
        
    def _get_raw_log_context(self, current_line_num: int, window: int = 5) -> str:
        """Get basic context from recent raw logs in the buffer."""
        context_lines = []
        start_index = max(0, len(self.event_buffer) - window - 1)
        end_index = len(self.event_buffer) -1 # Exclude the current line itself if it's the last
        
        # Slice the deque carefully
        # This is not perfectly efficient but avoids index errors
        buffer_list = list(self.event_buffer)
        if start_index < end_index:
             context_lines = buffer_list[start_index:end_index]

        if context_lines:
             return f"Raw Log Context (Lines around {current_line_num}):\n" + "\n".join(context_lines)
        else:
             return "No recent raw log context available."

    def _parse_timestamp(self, timestamp_data: Union[str, int, float]) -> datetime:
        """Parse timestamp from various formats (string, epoch)."""
        if isinstance(timestamp_data, (int, float)):
            try:
                # Assume epoch timestamp (seconds)
                return datetime.fromtimestamp(timestamp_data)
            except (ValueError, OSError):
                pass # Fall through to string parsing

        timestamp_str = str(timestamp_data).strip()
        # Add more formats as needed, prioritize common ones
        formats = [
            '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S.%fZ', # ISO 8601 UTC
            '%b %d %H:%M:%S', # Syslog default format (requires year)
            '%b  %d %H:%M:%S', # Syslog with double space
            '%Y/%m/%d %H:%M:%S',
            '%m/%d/%Y %H:%M:%S',
            '%d/%b/%Y:%H:%M:%S %z', # Apache Combined Log Format
            # Add epoch ms if common
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                # Handle syslog format needing current year
                if fmt in ('%b %d %H:%M:%S', '%b  %d %H:%M:%S') and dt.year == 1900:
                     dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue
        
        # Fallback: Try regex for any date-like pattern at the start? Less reliable.
        # Example: r'^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})'
        
        # logger.debug(f"Could not parse timestamp: '{timestamp_str}'")
        return datetime.now() # Fallback to current time

    def cleanup(self):
        """Clean up resources."""
        self.cleanup_event.set()
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)
        # Removed call to non-existent threat_detector.cleanup()
        # if hasattr(self, 'threat_detector'):
        #     self.threat_detector.cleanup()
        self.event_buffer.clear()
        gc.collect()

    def _check_memory(self) -> bool:
        """Check if memory usage is below threshold."""
        try:
            memory_percent = psutil.virtual_memory().percent
            if memory_percent >= (MEMORY_THRESHOLD * 100):
                logger.warning(f"High memory usage: {memory_percent}%")
                gc.collect()
                return False
            return True
        except Exception as e:
            logger.error(f"Error checking memory: {e}")
            return False

    @contextmanager
    def _memory_safe_operation(self):
        """Context manager for memory-safe operations."""
        if not self._check_memory():
            raise MemoryError("Memory usage too high")
        try:
            yield
        finally:
            self.cleanup_event.set()

    @contextmanager
    def _open_file_safely(self, file_path: str, binary: bool = False):
        """Safely open and close files with proper error handling."""
        file_obj = None
        try:
            mode = 'rb' if binary else 'r'
            file_obj = open(file_path, mode)
            yield file_obj
        except Exception as e:
            logger.error(f"Error opening file {file_path}: {e}")
            raise
        finally:
            if file_obj:
                try:
                    file_obj.close()
                except:
                    pass
                    
    def _read_lines(self, file_obj):
        """Read lines from a file object."""
        while True:
            line = file_obj.readline()
            if not line:
                break
            yield line

def parse_file(file_path: str, threat_detector: Optional[ThreatDetector] = None) -> List[Finding]:
    """Convenience function to parse a file, optionally using a shared ThreatDetector."""
    parser = LogParser() # Creates a new detector internally now
    # If a specific ThreatDetector is needed, it should be passed during LogParser init
    # or the parser should be used as an object.
    try:
        return parser.parse_file(file_path)
    finally:
        parser.cleanup()

# For testing
if __name__ == "__main__":
    import sys
    
    def print_findings(findings: List[Finding]):
        for finding in findings:
            if finding.indicators:
                print(f"\nFinding:")
                print(f"Content: {finding.content}")
                print(f"Severity: {finding.severity}")
                print("Indicators:")
                for indicator in finding.indicators:
                    print(f"- {indicator['type']} ({indicator['category']})")
                    print(f"  {indicator['description']}")
                print("-" * 80)
    
    if len(sys.argv) != 2:
        print("Usage: python log_parser.py <file_path>")
        sys.exit(1)
    
    try:
        findings = parse_file(sys.argv[1])
        print_findings(findings)
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
