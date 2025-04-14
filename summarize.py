# summarize.py
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
from typing import Tuple, Optional, Dict
import hashlib
import json
import os
from pathlib import Path
from rich.progress import Progress, SpinnerColumn, TextColumn
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SummaryCache:
    def __init__(self, cache_dir: str = ".cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
    def _get_cache_key(self, prompt: str, max_tokens: int) -> str:
        """Generate a unique cache key based on input parameters."""
        content = f"{prompt}:{max_tokens}"
        return hashlib.md5(content.encode()).hexdigest()
        
    def get(self, prompt: str, max_tokens: int) -> Optional[str]:
        """Retrieve cached summary if it exists."""
        cache_key = self._get_cache_key(prompt, max_tokens)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                return data.get('summary')
            except (json.JSONDecodeError, KeyError):
                return None
        return None
        
    def save(self, prompt: str, max_tokens: int, summary: str):
        """Save summary to cache."""
        cache_key = self._get_cache_key(prompt, max_tokens)
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        with open(cache_file, 'w') as f:
            json.dump({
                'prompt': prompt,
                'max_tokens': max_tokens,
                'summary': summary
            }, f)

class SummarizationMode:
    BRIEF = "brief"
    DETAILED = "detailed"
    TECHNICAL = "technical"
    
    @staticmethod
    def get_prompt_prefix(mode: str) -> str:
        prefixes = {
            SummarizationMode.BRIEF: (
                "Provide a concise summary of the key findings. "
                "Focus only on the most critical security issues."
            ),
            SummarizationMode.DETAILED: (
                "Provide a comprehensive analysis of all findings. "
                "Include both major and minor security concerns, with detailed explanations."
            ),
            SummarizationMode.TECHNICAL: (
                "Provide a technical analysis focusing on specific indicators, "
                "timestamps, IP addresses, and technical details of potential threats."
            )
        }
        return prefixes.get(mode, prefixes[SummarizationMode.DETAILED])

def load_model(model_name: str = "mistralai/Mistral-7B-v0.1") -> Tuple[AutoTokenizer, AutoModelForCausalLM]:
    """
    Load the model and tokenizer with progress tracking.
    """
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        progress.add_task(description="Loading tokenizer...", total=None)
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        
        progress.add_task(description="Loading model...", total=None)
        model = AutoModelForCausalLM.from_pretrained(model_name)
        
    return tokenizer, model

def generate_summary(
    prompt: str,
    tokenizer: AutoTokenizer,
    model: AutoModelForCausalLM,
    max_tokens: int = 200,
    mode: str = SummarizationMode.DETAILED,
    use_cache: bool = True
) -> str:
    """
    Generate an AI summary with caching and different modes.
    """
    # Initialize cache
    cache = SummaryCache()
    
    # Check cache first
    if use_cache:
        cached_summary = cache.get(prompt, max_tokens)
        if cached_summary:
            logger.info("Using cached summary")
            return cached_summary
    
    # Prepare the prompt with the selected mode
    mode_prefix = SummarizationMode.get_prompt_prefix(mode)
    full_prompt = f"{mode_prefix}\n\n{prompt}"
    
    # Tokenize the prompt
    inputs = tokenizer(full_prompt, return_tensors="pt")
    
    # Generate output with progress tracking
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        task = progress.add_task(description="Generating summary...", total=None)
        
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_tokens,
            do_sample=True,
            temperature=0.7,
            top_p=0.9
        )
        
        progress.update(task, completed=True)
    
    # Decode and clean up the summary
    summary = tokenizer.decode(outputs[0], skip_special_tokens=True)
    
    # Cache the result
    if use_cache:
        cache.save(prompt, max_tokens, summary)
    
    return summary

# For testing purposes:
if __name__ == "__main__":
    test_prompt = (
        "Analyze the following forensic log sample and describe any suspicious activities:\n"
        "- Multiple failed login attempts from IP 192.168.1.100\n"
        "- Unusual outbound connections to 45.67.89.123 on port 4444\n"
        "- System file modifications in C:\\Windows\\System32\\"
    )
    
    tokenizer, model = load_model()
    
    # Test different summarization modes
    for mode in [SummarizationMode.BRIEF, SummarizationMode.DETAILED, SummarizationMode.TECHNICAL]:
        print(f"\nGenerating {mode} summary:")
        summary = generate_summary(test_prompt, tokenizer, model, mode=mode)
        print(summary)
