"""
AI-powered network traffic analysis module using local LLM models.
Supports both Llama 2 and Mistral AI models for enhanced threat detection.
"""

import os
import logging
from typing import List, Dict, Optional, Union, Tuple, Callable
from dataclasses import dataclass
from pathlib import Path
import sys
import gc
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor

# Optional imports
try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False
    print("Warning: psutil not available. Memory monitoring disabled.")

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Thread-local storage for LLM instances
thread_local = threading.local()

@dataclass
class AIAnalysis:
    finding: str
    confidence: float
    explanation: str
    suggested_actions: List[str]
    severity: int
    is_false_positive: bool = False
    false_positive_reason: str = ""

class NetworkAIAnalyzer:
    SUPPORTED_MODELS = {
        'mistral': [
            'mistral-7b-instruct-v0.2.Q4_K_M.gguf',
            'mistral-7b-instruct-v0.2.Q5_K_M.gguf'
        ],
        'llama2': [
            'llama-2-7b-chat.Q4_K_M.gguf',
            'llama-2-7b-chat.Q5_K_M.gguf'
        ]
    }

    def __init__(self, debug: bool = False, progress_callback: Optional[Callable[[str], None]] = None):
        """Initialize the AI analyzer with optional progress reporting."""
        self.debug = debug
        self.progress_callback = progress_callback
        self.model_path = None
        self.llm = None
        self._executor = ThreadPoolExecutor(max_workers=1)
        self._lock = threading.Lock()
        
        # Define analysis prompts as instance attributes
        self.analysis_prompt = '''
        You are an expert network security analyst. Analyze this network traffic log entry for potential security threats:

        {log_entry}

        Consider:
        1. Source/destination patterns and known malicious IPs
        2. Protocol anomalies and misuse
        3. Payload contents and potential malware signatures
        4. Traffic timing and frequency patterns
        5. Port usage and scanning behavior
        6. Known attack patterns and signatures
        7. Data exfiltration indicators
        8. Command and control patterns

        Provide a detailed analysis in this format:
        THREAT: <brief threat description>
        CONFIDENCE: <score between 0 and 1>
        EXPLANATION: <detailed technical explanation>
        ACTIONS: <comma-separated list of recommended actions>
        SEVERITY: <score between 1 and 5>
        '''

        self.false_positive_prompt = '''
        You are an expert network security analyst reviewing potential security threats. 
        Analyze this finding to determine if it's a false positive:

        Original Finding:
        {finding}

        Consider:
        1. Common legitimate network patterns
        2. Standard protocol behaviors
        3. Known benign traffic patterns
        4. Context of the communication
        5. Normal system operations
        6. Standard administrative tasks
        7. Expected application behavior

        Provide your analysis in this format:
        IS_FALSE_POSITIVE: <true/false>
        CONFIDENCE: <score between 0 and 1>
        EXPLANATION: <detailed explanation of why this is or isn't a false positive>
        REVISED_SEVERITY: <if not false positive, provide severity 1-5, otherwise 0>
        '''

        self.correlation_prompt = '''
        Analyze these related log entries for deeper security insights:

        {log_entries}

        Consider:
        1. Attack progression and patterns
        2. Related events and causality
        3. Attack chain reconstruction
        4. Threat actor TTPs
        5. Overall impact assessment

        Provide analysis in this format:
        CORRELATED_THREAT: <brief description>
        CONFIDENCE: <score between 0 and 1>
        EXPLANATION: <detailed correlation analysis>
        SEVERITY: <score between 1 and 5>
        RECOMMENDED_ACTIONS: <comma-separated list>
        '''

        self.summary_prompt = '''
        Analyze these security findings and provide a comprehensive assessment:

        {findings}

        Consider:
        1. Overall threat landscape
        2. Most critical findings
        3. Common patterns or campaigns
        4. Recommended mitigations
        5. Risk assessment

        Provide a detailed summary in this format:
        SUMMARY: <brief overview>
        CRITICAL_FINDINGS: <list key findings>
        RISK_LEVEL: <low/medium/high>
        RECOMMENDATIONS: <prioritized list>
        '''
        
        try:
            self._initialize_model(None)
        except Exception as e:
            logger.error(f"Failed to initialize model: {e}")
            raise

    def __del__(self):
        """Cleanup resources."""
        try:
            if hasattr(self, '_executor'):
                self._executor.shutdown(wait=False)
            if hasattr(self, 'llm'):
                del self.llm
            gc.collect()
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    def _report_progress(self, message: str):
        """Report progress if callback is available."""
        if self.progress_callback:
            self.progress_callback(message)
        if self.debug:
            logger.info(message)

    def _initialize_model(self, model_path: Optional[str]) -> None:
        """Initialize the model with proper error handling and progress reporting."""
        self._report_progress("Looking for model file...")
        
        if model_path:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model not found: {model_path}")
            self.model_path = model_path
        else:
            # Look for models in the models directory
            models_dir = Path("models")
            if not models_dir.exists():
                self._report_progress("Creating models directory...")
                models_dir.mkdir(exist_ok=True)
                
            model_files = list(models_dir.glob("*.gguf"))
            if not model_files:
                raise FileNotFoundError("No GGUF models found in models directory")
                
            self.model_path = str(model_files[0])
        
        self._report_progress(f"Found model: {self.model_path}")
        
        try:
            # Check available memory if psutil is available
            if HAVE_PSUTIL:
                self._report_progress("Checking available memory...")
                available_memory = psutil.virtual_memory().available
                required_memory = 8 * 1024 * 1024 * 1024  # 8GB minimum
                
                if available_memory < required_memory:
                    self._report_progress(f"Low memory available: {available_memory / (1024**3):.2f}GB")
                    gc.collect()
            else:
                # Force garbage collection anyway as a precaution
                gc.collect()
            
            self._report_progress("Loading model into memory...")
            from llama_cpp import Llama
            with self._lock:
                self.llm = Llama(
                    model_path=self.model_path,
                    n_ctx=2048,  # Reduced context size for stability
                    n_threads=min(os.cpu_count() or 4, 4),  # Limit threads
                    n_batch=8,  # Reduced batch size
                    seed=42  # Fixed seed for stability
                )
            self._report_progress("Model loaded successfully")
            
        except ImportError:
            logger.error("Failed to import llama_cpp. Please install with: pip install llama-cpp-python")
            raise
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise

    def _get_thread_local_llm(self):
        """Get or create thread-local LLM instance."""
        if not hasattr(thread_local, 'llm'):
            from llama_cpp import Llama
            thread_local.llm = Llama(
                model_path=self.model_path,
                n_ctx=2048,
                n_threads=1,  # Single thread per instance
                n_batch=8
            )
        return thread_local.llm

    def _find_model(self) -> Optional[str]:
        """Find an available model in the models directory."""
        model_dir = Path("models")
        if not model_dir.exists():
            logger.warning("Models directory not found. Creating...")
            model_dir.mkdir(exist_ok=True)
            return None

        # Try all supported model variants
        for model_variants in self.SUPPORTED_MODELS.values():
            if isinstance(model_variants, str):
                model_variants = [model_variants]
            for model_name in model_variants:
                model_path = model_dir / model_name
                if model_path.exists():
                    return str(model_path)

        return None

    def _handle_initialization_error(self) -> None:
        """Handle model initialization errors with helpful messages."""
        logger.warning("\nNo suitable model found. Please follow these steps:")
        logger.warning("\n1. Download one of these models:")
        logger.warning("   a. Mistral 7B (Recommended):")
        logger.warning("      https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF")
        logger.warning("   b. Llama 2 7B:")
        logger.warning("      https://huggingface.co/TheBloke/Llama-2-7B-Chat-GGUF")
        logger.warning("\n2. Place the .gguf file in the 'models' directory")
        logger.warning("\n3. Ensure you have the required dependencies:")
        logger.warning("   pip install -r requirements.txt")

    def __call__(self, prompt: str, max_tokens: int = 512, temperature: float = 0.7) -> str:
        """Generate a response from the LLM with progress reporting."""
        if not self.llm:
            return "Error: No model loaded"
            
        try:
            self._report_progress("Preparing prompt...")
            # Add safety checks for prompt length
            if len(prompt) > 2048:
                prompt = prompt[:2048]
                
            self._report_progress("Generating response...")
            with self._lock:
                response = self.llm(
                    prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    echo=False,
                    stop=["</s>", "[INST]", "[/INST]"]
                )
                
            if not response or 'choices' not in response:
                return "Error: Invalid response from model"
                
            self._report_progress("Response generated")
            return response['choices'][0]['text'].strip()
            
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            return f"Error: {str(e)}"

    def analyze_log_entry(self, log_entry: str) -> Optional[Dict]:
        """Analyze a single log entry using the LLM."""
        if not self.llm:
            logger.warning("No model loaded")
            return None

        try:
            self._report_progress("Analyzing log entry...")
            prompt = f'''Analyze this network traffic log entry for security threats:

{log_entry}

Format:
THREAT: <description>
CONFIDENCE: <0-1>
EXPLANATION: <brief>
ACTIONS: <list>
SEVERITY: <1-5>'''
            
            response = self(prompt)
            if response.startswith("Error:"):
                return None
                
            self._report_progress("Parsing response...")
            return self._parse_response(response)
            
        except Exception as e:
            logger.error(f"Error during log entry analysis: {e}")
            return None

    def _parse_response(self, response: Union[Dict, str]) -> Dict:
        """Parse the LLM response into a dictionary."""
        try:
            # Handle both string and dictionary responses
            if isinstance(response, dict):
                text = response.get('choices', [{}])[0].get('text', '')
            else:
                text = str(response).strip()
            
            lines = text.split('\n')
            result = {}
            
            current_key = None
            current_value = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                if ':' in line:
                    # If we have a stored key, save it before starting new one
                    if current_key:
                        result[current_key] = '\n'.join(current_value).strip()
                        current_value = []
                    
                    # Start new key-value pair
                    key, value = line.split(':', 1)
                    current_key = key.strip()
                    current_value = [value.strip()]
                else:
                    # Append to current value if we have a key
                    if current_key:
                        current_value.append(line)
            
            # Save the last key-value pair if exists
            if current_key and current_value:
                result[current_key] = '\n'.join(current_value).strip()

            return result
        except Exception as e:
            logger.error(f"Error parsing AI response: {e}")
            return {}

    def analyze_findings_batch(self, findings: List[str]) -> str:
        """Analyze a batch of findings to generate a comprehensive security assessment."""
        if not self.llm:
            logger.warning("No model loaded. Skipping batch analysis.")
            return ""

        try:
            findings_text = "\n".join(findings)
            prompt = self.summary_prompt.format(findings=findings_text)
            response = self.llm(
                prompt,
                max_tokens=1024,
                temperature=0.2,
                top_p=0.95
            )
            
            return response['choices'][0]['text'].strip()
        except Exception as e:
            logger.error(f"Error during batch analysis: {e}")
            return ""

    def get_model_info(self) -> Dict[str, Union[str, int, None]]:
        """Get information about the loaded model."""
        if not self.llm:
            return {
                "status": "No model loaded",
                "model_path": None,
                "n_ctx": None,
                "n_threads": None
            }
        
        return {
            "status": "Model loaded",
            "model_path": self.model_path,
            "n_ctx": self.llm.n_ctx,
            "n_threads": self.llm.n_threads
        }

    def perform_second_pass_analysis(self, findings: List[Dict]) -> List[Dict]:
        """
        Perform a second pass analysis to reduce false positives and identify complex patterns.
        
        Args:
            findings: List of initial findings from first pass
            
        Returns:
            List of refined findings with false positives removed and new correlated threats added
        """
        if not self.llm:
            logger.warning("No model loaded. Skipping second pass analysis.")
            return findings

        refined_findings = []
        correlated_groups = {}

        # First, check each finding for false positives
        for finding in findings:
            try:
                # Convert Finding object to dict if needed
                finding_dict = finding
                if not isinstance(finding, dict):
                    try:
                        finding_dict = {
                            'content': finding.content,
                            'severity': finding.severity,
                            'indicators': [{'description': i.description, 'severity': i.severity} for i in finding.indicators],
                            'source_line': finding.source_line,
                            'timestamp': finding.timestamp
                        }
                    except AttributeError as e:
                        logger.error(f"Failed to convert finding to dict: {e}")
                        continue

                # Prepare finding description
                indicators = []
                try:
                    for indicator in finding_dict.get('indicators', []):
                        if isinstance(indicator, dict):
                            indicators.append(indicator['description'])
                        else:
                            indicators.append(str(indicator))
                except Exception as e:
                    logger.error(f"Error processing indicators: {e}")
                    indicators = ['Unknown indicator']

                finding_desc = f"""
                Content: {finding_dict.get('content', 'No content')}
                Initial Severity: {finding_dict.get('severity', 0)}
                Indicators: {', '.join(indicators)}
                """

                # Check for false positives
                prompt = self.false_positive_prompt.format(finding=finding_desc)
                response = self.llm(
                    prompt,
                    max_tokens=512,
                    temperature=0.1,
                    top_p=0.95
                )

                result = self._parse_response(response)
                if not result:
                    logger.warning("Empty response from AI analysis, keeping original finding")
                    refined_findings.append(finding_dict)
                    continue
                
                # Parse false positive analysis with safe type conversion
                try:
                    is_false_positive = str(result.get('IS_FALSE_POSITIVE', '')).lower() == 'true'
                    confidence = float(result.get('CONFIDENCE', 0))
                    revised_severity = result.get('REVISED_SEVERITY', '')
                    revised_severity = int(revised_severity) if str(revised_severity).isdigit() else finding_dict.get('severity', 0)
                except (ValueError, TypeError) as e:
                    logger.error(f"Error parsing AI analysis values: {e}")
                    is_false_positive = False
                    confidence = 0
                    revised_severity = finding_dict.get('severity', 0)
                
                if not is_false_positive or confidence < 0.8:  # Keep if not confident it's false positive
                    # Group related findings for correlation
                    key = str(finding_dict.get('source_line', '')) + str(finding_dict.get('timestamp', ''))
                    if key not in correlated_groups:
                        correlated_groups[key] = []
                    correlated_groups[key].append(finding_dict)
                    
                    # Update finding with AI analysis
                    finding_dict['ai_analysis'] = {
                        'is_false_positive': is_false_positive,
                        'confidence': confidence,
                        'explanation': result.get('EXPLANATION', 'No explanation provided'),
                        'revised_severity': revised_severity
                    }
                    refined_findings.append(finding_dict)

            except Exception as e:
                logger.error(f"Error during false positive analysis: {e}")
                if 'finding_dict' in locals():
                    refined_findings.append(finding_dict)
                else:
                    refined_findings.append(finding)

        # Perform correlation analysis on related findings
        correlated_threats = []
        for group in correlated_groups.values():
            if len(group) > 1:  # Only correlate multiple related findings
                try:
                    entries = "\n".join([f"Entry {i+1}:\n{f.get('content', 'No content')}" for i, f in enumerate(group)])
                    prompt = self.correlation_prompt.format(log_entries=entries)
                    response = self.llm(
                        prompt,
                        max_tokens=1024,
                        temperature=0.2,
                        top_p=0.95
                    )

                    result = self._parse_response(response)
                    if result:
                        try:
                            confidence = float(result.get('CONFIDENCE', 0))
                            severity = result.get('SEVERITY', '')
                            severity = int(severity) if str(severity).isdigit() else 3
                            
                            if confidence > 0.7:
                                correlated_threats.append({
                                    'type': 'correlated_threat',
                                    'content': result.get('CORRELATED_THREAT', 'Unknown threat'),
                                    'explanation': result.get('EXPLANATION', 'No explanation provided'),
                                    'severity': severity,
                                    'related_findings': [str(f.get('source_line', 'unknown')) for f in group],
                                    'recommended_actions': result.get('RECOMMENDED_ACTIONS', '').split(',')
                                })
                        except (ValueError, TypeError) as e:
                            logger.error(f"Error parsing correlation values: {e}")

                except Exception as e:
                    logger.error(f"Error during correlation analysis: {e}")

        # Add correlated threats to refined findings
        refined_findings.extend(correlated_threats)

        return refined_findings

    def check_false_positive(self, finding: Dict) -> Dict:
        """Check if a finding is likely a false positive."""
        if not self.llm:
            return {}
            
        try:
            # Create a shorter, focused prompt
            finding_desc = f"Content: {finding.get('content', 'No content')}\nSeverity: {finding.get('severity', 0)}"
            
            prompt = f'''Is this security finding a false positive?

{finding_desc}

Format:
IS_FALSE_POSITIVE: <true/false>
CONFIDENCE: <0-1>
EXPLANATION: <brief>
REVISED_SEVERITY: <0-5>'''

            response = self(prompt)
            if response.startswith("Error:"):
                return {}
                
            return self._parse_response(response)
            
        except Exception as e:
            logger.error(f"Error during false positive check: {e}")
            return {}

    def correlate_findings(self, findings: List[Dict]) -> Dict:
        """Analyze multiple findings for correlations and patterns."""
        if not self.llm:
            return {}
            
        try:
            # Prepare a concise summary of findings
            findings_summary = "\n".join(
                f"Finding {i+1}: {f.get('content', 'No content')[:200]}..."  # Limit content length
                for i, f in enumerate(findings[:5])  # Limit number of findings
            )
            
            prompt = f'''Analyze these related security findings:

{findings_summary}

Format:
CORRELATED_THREAT: <description>
CONFIDENCE: <0-1>
EXPLANATION: <brief>
SEVERITY: <1-5>
RECOMMENDED_ACTIONS: <list>'''

            response = self(prompt)
            if response.startswith("Error:"):
                return {}
                
            return self._parse_response(response)
            
        except Exception as e:
            logger.error(f"Error during correlation analysis: {e}")
            return {}

    def chat_response(self, context: str, question: str) -> str:
        """Generate a response to a user question about the findings."""
        if not self.llm:
            return "Error: No model loaded"
            
        try:
            self._report_progress("Preparing context...")
            if len(context) > 1500:
                context = context[:1500] + "...(truncated)"
                
            self._report_progress("Generating response...")
            prompt = f'''Based on these security findings, answer the question:

Context:
{context}

Question: {question}

Provide a clear, focused security analysis.'''

            response = self(prompt)
            self._report_progress("Response ready")
            return response
            
        except Exception as e:
            logger.error(f"Error generating chat response: {e}")
            return f"Error generating response: {str(e)}" 