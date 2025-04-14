# searcher.py
import re
from typing import List, Dict, Union, Optional
from datetime import datetime, timedelta
import json

class SearchCriteria:
    def __init__(self, 
                 pattern: str,
                 use_regex: bool = False,
                 case_sensitive: bool = False,
                 time_range: Optional[Dict] = None):
        self.pattern = pattern
        self.use_regex = use_regex
        self.case_sensitive = case_sensitive
        self.time_range = time_range
        
        if use_regex:
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                self.compiled_pattern = re.compile(pattern, flags)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {str(e)}")
        else:
            self.compiled_pattern = None

def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """Try to parse timestamp from common formats."""
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%b %d %H:%M:%S"
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except ValueError:
            continue
    return None

def matches_time_range(line: str, time_range: Dict) -> bool:
    """Check if a log line's timestamp falls within the specified time range."""
    # Try to find a timestamp in the line
    timestamp_pattern = r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
    match = re.search(timestamp_pattern, line)
    
    if not match:
        return True  # If no timestamp found, include the line
        
    timestamp_str = match.group(0)
    timestamp = parse_timestamp(timestamp_str)
    
    if not timestamp:
        return True  # If parsing fails, include the line
        
    start_time = time_range.get('start')
    end_time = time_range.get('end')
    
    if start_time and timestamp < start_time:
        return False
    if end_time and timestamp > end_time:
        return False
        
    return True

def search_logs(log_lines: List[str], criteria: Union[str, SearchCriteria]) -> List[str]:
    """
    Enhanced search through log lines using advanced criteria.
    
    Args:
        log_lines: List of log lines to search through
        criteria: Either a simple search string or SearchCriteria object
        
    Returns:
        List of matching log lines
    """
    if isinstance(criteria, str):
        criteria = SearchCriteria(criteria)
    
    results = []
    for line in log_lines:
        # Skip empty lines
        if not line.strip():
            continue
            
        # Check time range if specified
        if criteria.time_range and not matches_time_range(line, criteria.time_range):
            continue
            
        # Perform pattern matching
        if criteria.use_regex:
            if criteria.compiled_pattern.search(line):
                results.append(line)
        else:
            if criteria.case_sensitive:
                if criteria.pattern in line:
                    results.append(line)
            else:
                if criteria.pattern.lower() in line.lower():
                    results.append(line)
    
    return results

def search_findings(findings: List[str], criteria: Union[str, SearchCriteria]) -> List[str]:
    """
    Enhanced search through structured findings using advanced criteria.
    
    Args:
        findings: List of finding strings or JSON objects
        criteria: Either a simple search string or SearchCriteria object
        
    Returns:
        List of matching findings
    """
    if isinstance(criteria, str):
        criteria = SearchCriteria(criteria)
    
    results = []
    for finding in findings:
        # Handle both string and JSON findings
        if isinstance(finding, str):
            content = finding
        else:
            try:
                content = json.dumps(finding)
            except (TypeError, json.JSONDecodeError):
                content = str(finding)
        
        # Perform pattern matching
        if criteria.use_regex:
            if criteria.compiled_pattern.search(content):
                results.append(finding)
        else:
            if criteria.case_sensitive:
                if criteria.pattern in content:
                    results.append(finding)
            else:
                if criteria.pattern.lower() in content.lower():
                    results.append(finding)
    
    return results

# Example usage
if __name__ == "__main__":
    # Example with simple string search
    sample_lines = [
        "2024-01-15 10:30:45 TCP 192.168.1.10 -> 8.8.8.8 SYN",
        "2024-01-15 10:31:00 UDP packet from 192.168.1.11",
        "2024-01-15 10:32:15 Malformed packet found near error code 404"
    ]
    
    # Simple search
    results = search_logs(sample_lines, "packet")
    print("Simple search results:")
    for result in results:
        print(result)
    
    # Advanced search with regex
    criteria = SearchCriteria(
        pattern=r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        use_regex=True,
        case_sensitive=True,
        time_range={
            'start': datetime(2024, 1, 15, 10, 30, 0),
            'end': datetime(2024, 1, 15, 10, 31, 30)
        }
    )
    
    results = search_logs(sample_lines, criteria)
    print("\nAdvanced search results:")
    for result in results:
        print(result)
