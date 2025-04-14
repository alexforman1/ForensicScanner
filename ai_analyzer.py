"""
AI analyzer for forensic log analysis with dynamic scoring.
"""
import os
import logging
import psutil
from typing import List, Dict, Optional, Union, Tuple, Set
from dataclasses import dataclass, field
import sys
import gc
import threading
import queue
import weakref
from concurrent.futures import ThreadPoolExecutor
import re
import yaml
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Memory threshold (90%)
MEMORY_THRESHOLD = 0.9

# Default benign process list
DEFAULT_BENIGN_PROCESSES = {
    'svchost.exe', 'lsass.exe', 'services.exe', 'chrome.exe', 'firefox.exe',
    'msedge.exe', 'explorer.exe', 'winlogon.exe', 'spoolsv.exe', 'wininit.exe',
    'csrss.exe', 'smss.exe', 'system', 'registry', 'dllhost.exe', 'taskhost.exe'
}

# Common legitimate ports and services
COMMON_PORTS = {
    'tcp': {80, 443, 22, 53, 3389, 445, 139, 135, 25, 587, 993, 995},
    'udp': {53, 67, 68, 123, 137, 138, 161, 162, 500, 514, 1900}
}

# Baseline configuration for network behavior
NETWORK_BASELINE = {
    'max_connections_per_min': 100,
    'max_failed_logins': 5,
    'max_port_scan_threshold': 10,
    'suspicious_time_ranges': [(datetime.strptime('23:00', '%H:%M').time(),
                              datetime.strptime('05:00', '%H:%M').time())]
}

@dataclass
class RiskFactor:
    """Structure for risk factors in analysis."""
    name: str
    score: float
    description: str
    category: str
    context: Dict = field(default_factory=dict)

@dataclass
class AIAnalysis:
    """Enhanced AI analysis results with detailed risk scoring."""
    finding: str
    confidence: float
    explanation: str
    suggested_actions: List[str]
    severity: int
    risk_factors: List[RiskFactor] = field(default_factory=list)
    is_false_positive: bool = False
    false_positive_reason: str = ""
    context_data: Dict = field(default_factory=dict)

class ThreatScorer:
    """Dynamic threat scoring system."""
    
    def __init__(self):
        self.load_config()
        self.event_history = {}
        self.connection_counts = {}
        self.last_cleanup = datetime.now()
    
    def load_config(self):
        """Load scoring configuration."""
        config_path = "config/scoring.yaml"
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    self.config = yaml.safe_load(f)
            else:
                self.config = {
                    'process_weights': {
                        'unknown_process': 2.0,
                        'system_critical': 1.5,
                        'user_space': 1.0
                    },
                    'network_weights': {
                        'external_connection': 1.5,
                        'unusual_port': 1.2,
                        'high_frequency': 1.3
                    },
                    'time_weights': {
                        'business_hours': 0.8,
                        'after_hours': 1.2,
                        'weekend': 1.1
                    }
                }
        except Exception as e:
            logger.error(f"Error loading scoring config: {e}")
            
    def is_business_hours(self) -> bool:
        """Check if current time is during business hours."""
        current_time = datetime.now()
        return (
            current_time.weekday() < 5 and  # Monday to Friday
            datetime.strptime('09:00', '%H:%M').time() <= current_time.time() <= 
            datetime.strptime('17:00', '%H:%M').time()
        )
    
    def calculate_process_risk(self, process_name: str, cmd_line: str = "") -> RiskFactor:
        """Calculate risk score for a process."""
        base_score = 0.0
        context = {}
        
        # Check if process is known benign
        if process_name.lower() in DEFAULT_BENIGN_PROCESSES:
            base_score = 0.2
            context['is_benign'] = True
        else:
            # Check for suspicious process characteristics
            if re.search(r'(?i)(temp|tmp|unknown).*\.exe', process_name):
                base_score += 2.0
                context['suspicious_name'] = True
            
            # Check command line for suspicious args
            if cmd_line:
                if re.search(r'(?i)(bypass|hidden|encrypt|decode)', cmd_line):
                    base_score += 1.5
                    context['suspicious_args'] = True
                    
        return RiskFactor(
            name="process_risk",
            score=base_score,
            description=f"Process risk score for {process_name}",
            category="PROCESS",
            context=context
        )
    
    def calculate_network_risk(self, src_ip: str, dst_ip: str, 
                             port: int, protocol: str) -> RiskFactor:
        """Calculate risk score for network activity."""
        base_score = 0.0
        context = {}
        
        # Check if port is commonly used
        if port not in COMMON_PORTS.get(protocol.lower(), set()):
            base_score += 1.0
            context['unusual_port'] = True
        
        # Check connection frequency
        conn_key = f"{src_ip}:{dst_ip}"
        current_time = datetime.now()
        
        # Cleanup old entries
        if (current_time - self.last_cleanup) > timedelta(minutes=5):
            self._cleanup_old_events()
        
        # Update connection counts
        if conn_key not in self.connection_counts:
            self.connection_counts[conn_key] = []
        self.connection_counts[conn_key].append(current_time)
        
        # Check frequency
        recent_conns = [t for t in self.connection_counts[conn_key] 
                       if (current_time - t) <= timedelta(minutes=1)]
        if len(recent_conns) > NETWORK_BASELINE['max_connections_per_min']:
            base_score += 1.5
            context['high_frequency'] = True
        
        # Adjust for time of day
        if not self.is_business_hours():
            base_score *= self.config['time_weights']['after_hours']
            context['after_hours'] = True
            
        return RiskFactor(
            name="network_risk",
            score=base_score,
            description=f"Network risk score for {src_ip}:{port}",
            category="NETWORK",
            context=context
        )
    
    def _cleanup_old_events(self):
        """Clean up old events from history."""
        current_time = datetime.now()
        cutoff = current_time - timedelta(minutes=5)
        
        # Cleanup connection counts
        for key in list(self.connection_counts.keys()):
            self.connection_counts[key] = [t for t in self.connection_counts[key] 
                                         if t > cutoff]
            if not self.connection_counts[key]:
                del self.connection_counts[key]
        
        self.last_cleanup = current_time

class NetworkAIAnalyzer:
    """Enhanced network traffic analyzer with context-aware analysis."""
    
    def __init__(self):
        """Initialize the analyzer."""
        self.llm = None
        self.has_model = False
        self.scorer = ThreatScorer()
        try:
            self._load_model()
        except Exception as e:
            logger.warning(f"Could not load AI model: {e}")
            logger.info("Falling back to basic analysis")
    
    def analyze_event(self, event_data: Dict) -> AIAnalysis:
        """Analyze an event with context-aware scoring."""
        risk_factors = []
        total_score = 0.0
        
        # Process analysis
        if 'process_name' in event_data:
            process_risk = self.scorer.calculate_process_risk(
                event_data['process_name'],
                event_data.get('command_line', '')
            )
            risk_factors.append(process_risk)
            total_score += process_risk.score
        
        # Network analysis
        if all(k in event_data for k in ['src_ip', 'dst_ip', 'dst_port', 'protocol']):
            network_risk = self.scorer.calculate_network_risk(
                event_data['src_ip'],
                event_data['dst_ip'],
                event_data['dst_port'],
                event_data['protocol']
            )
            risk_factors.append(network_risk)
            total_score += network_risk.score
        
        # Calculate final severity (1-5 scale)
        severity = min(5, max(1, int(total_score)))
        
        # Generate explanation
        explanation = self._generate_explanation(risk_factors)
        
        # Generate suggested actions
        actions = self._generate_actions(risk_factors, severity)
        
        return AIAnalysis(
            finding=event_data.get('raw_log', ''),
            confidence=min(1.0, total_score / 5.0),
            explanation=explanation,
            suggested_actions=actions,
            severity=severity,
            risk_factors=risk_factors,
            context_data=event_data
        )
    
    def _generate_explanation(self, risk_factors: List[RiskFactor]) -> str:
        """Generate a detailed explanation of the risk factors."""
        if not risk_factors:
            return "No significant risk factors identified."
            
        explanations = []
        for rf in risk_factors:
            if rf.score > 0:
                context_details = ", ".join(f"{k}: {v}" 
                                         for k, v in rf.context.items() 
                                         if v)
                explanations.append(
                    f"{rf.category}: {rf.description} "
                    f"(Score: {rf.score:.1f}{' - ' + context_details if context_details else ''})"
                )
        
        return "\n".join(explanations) if explanations else "No significant risk factors identified."
    
    def _generate_actions(self, risk_factors: List[RiskFactor], severity: int) -> List[str]:
        """Generate suggested actions based on risk factors."""
        actions = []
        
        for rf in risk_factors:
            if rf.category == "PROCESS" and rf.score > 1.5:
                actions.append(f"Investigate process {rf.context.get('process_name', 'unknown')}")
                if rf.context.get('suspicious_args'):
                    actions.append("Review process command line arguments")
                    
            elif rf.category == "NETWORK" and rf.score > 1.0:
                if rf.context.get('unusual_port'):
                    actions.append("Review network connections on non-standard ports")
                if rf.context.get('high_frequency'):
                    actions.append("Investigate high-frequency connections")
                if rf.context.get('after_hours'):
                    actions.append("Review after-hours network activity")
        
        if severity >= 4:
            actions.append("Escalate to security team for immediate review")
        elif severity >= 3:
            actions.append("Monitor system for additional suspicious activity")
        
        return actions if actions else ["No immediate action required"]
    
    def _load_model(self) -> None:
        """Load the LLM model."""
        try:
            # Get the absolute path to the model file
            model_path = os.path.join("models", "mistral-7b-instruct-v0.2.Q5_K_M.gguf")
            
            if not os.path.exists(model_path):
                logger.warning(f"Model file not found at {model_path}")
                logger.warning("Please ensure the model file exists at:")
                logger.warning(f"      {os.path.abspath(model_path)}")
                return

            from llama_cpp import Llama
            
            self.llm = Llama(
                model_path=model_path,
                n_ctx=2048,
                n_threads=2
            )
            self.has_model = True
            logger.info(f"Successfully loaded model from {model_path}")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self.has_model = False
    
    def __call__(self, prompt: str, max_tokens: int = 512) -> str:
        """Generate analysis response."""
        if not self.has_model:
            return self._basic_analysis(prompt)
            
        try:
            response = self.llm(
                prompt,
                max_tokens=max_tokens,
                temperature=0.7,
                top_p=0.95,
                stop=["</s>", "[INST]"]
            )
            return response["choices"][0]["text"].strip()
        except Exception as e:
            logger.error(f"Error generating AI response: {e}")
            return self._basic_analysis(prompt)
    
    def _basic_analysis(self, prompt: str) -> str:
        """Provide basic analysis when AI model is not available."""
        if "summary" not in prompt.lower():
            return "AI model not available. Please check the findings section for details."
            
        # Extract basic statistics from the prompt
        lines = prompt.split("\n")
        analysis = ["Basic Analysis (AI model not available):"]
        
        for line in lines:
            if "Total Findings:" in line:
                analysis.append(line)
            elif "Severity" in line and "findings" in line:
                analysis.append(line)
            elif any(cat in line for cat in ["NETWORK:", "SYSTEM:", "MALWARE:", "EXPLOIT:"]):
                analysis.append(line)
        
        if len(analysis) == 1:
            analysis.append("No findings to analyze.")
        
        analysis.append("\nRecommendation: Please review the findings manually for detailed analysis.")
        return "\n".join(analysis)
    
    def cleanup(self):
        """Clean up resources."""
        self.llm = None
        gc.collect()

def main():
    """Test the analyzer."""
    try:
        analyzer = NetworkAIAnalyzer()
        response = analyzer("Test prompt")
        print(f"Response: {response}")
    except Exception as e:
        logger.error(f"Error in main: {e}")
        sys.exit(1)
    finally:
        if 'analyzer' in locals():
            analyzer.cleanup()

if __name__ == "__main__":
    main()