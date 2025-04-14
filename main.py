# main.py
import argparse
import json
import sys
from pathlib import Path
from parser import (
    parse_wireshark_log, 
    parse_volatility_json, 
    parse_volatility_text,
    parse_generic_text,
    Finding
)
from searcher import search_logs, search_findings, SearchCriteria
from summarize import load_model, generate_summary, SummarizationMode
import os
from typing import Optional, Dict, List, Union
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

# Initialize rich console for better output
console = Console()

def load_config(config_path: Optional[str] = None) -> Dict:
    """Load configuration from a JSON file."""
    default_config = {
        "model_name": "mistralai/Mistral-7B-v0.1",
        "max_tokens": 200,
        "temperature": 0.7,
        "top_p": 0.9,
        "summarization_mode": "detailed"
    }
    
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                return {**default_config, **json.load(f)}
        except json.JSONDecodeError:
            console.print("[yellow]Warning: Invalid config file. Using defaults.[/yellow]")
    return default_config

def process_file(
    file_path: str,
    log_type: str,
    search_query: Optional[Union[str, SearchCriteria]] = None
) -> List[Finding]:
    """Process a log file and return findings."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        parsers = {
            "wireshark": parse_wireshark_log,
            "volatility_json": parse_volatility_json,
            "volatility_text": parse_volatility_text,
            "generic": parse_generic_text
        }
        
        if log_type not in parsers:
            raise ValueError(f"Unsupported log type: {log_type}")
            
        findings = parsers[log_type](file_path)
        console.print(f"[green]Imported {len(findings)} entries from {log_type} file.[/green]")
        
        if search_query:
            if isinstance(search_query, str):
                search_query = SearchCriteria(search_query)
            findings = [f for f in findings if any(
                search_query.pattern.lower() in indicator.description.lower()
                for indicator in f.indicators
            )]
            console.print(f"[green]Found {len(findings)} matching findings.[/green]")
            
        return findings
        
    except Exception as e:
        raise RuntimeError(f"Error processing file: {str(e)}")

def display_findings(findings: List[Finding]):
    """Display findings in a formatted table."""
    if not findings:
        console.print("[yellow]No suspicious findings detected.[/yellow]")
        return
        
    # Group findings by severity
    severity_groups = {}
    for finding in findings:
        if finding.indicators:  # Only show findings with indicators
            severity = finding.severity
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(finding)
    
    if not severity_groups:
        console.print("[yellow]No suspicious findings detected.[/yellow]")
        return
    
    # Display findings by severity (highest to lowest)
    for severity in sorted(severity_groups.keys(), reverse=True):
        console.print(f"\n[bold red]Severity Level {severity} Findings:[/bold red]")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Line")
        table.add_column("Content")
        table.add_column("Indicators")
        table.add_column("Timestamp", justify="right")
        
        for finding in severity_groups[severity]:
            indicators = "\n".join([f"- {i.description}" for i in finding.indicators])
            timestamp = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S") if finding.timestamp else "N/A"
            line = str(finding.source_line) if finding.source_line else "N/A"
            
            table.add_row(
                line,
                finding.content,
                indicators,
                timestamp
            )
        
        console.print(table)

def main():
    parser = argparse.ArgumentParser(description="Local AI Forensic Log Summarizer")
    parser.add_argument("--file", "-f", required=True, help="Path to the log file")
    parser.add_argument("--type", "-t", required=True,
                      choices=["wireshark", "volatility_json", "volatility_text", "generic"],
                      help="Type of log file")
    parser.add_argument("--search", "-s", help="Optional search term to filter findings")
    parser.add_argument("--config", "-c", help="Path to configuration file")
    parser.add_argument("--output", "-o", help="Path to save the summary")
    parser.add_argument("--mode", "-m",
                      choices=["brief", "detailed", "technical"],
                      default="detailed",
                      help="Summarization mode")

    args = parser.parse_args()

    try:
        # Load configuration
        config = load_config(args.config)
        
        with Progress() as progress:
            # Process the file
            task1 = progress.add_task("[cyan]Processing log file...", total=1)
            findings = process_file(args.file, args.type, args.search)
            progress.update(task1, completed=1)
            
            # Display findings
            console.print("\n[bold green]Suspicious Activity Findings:[/bold green]")
            display_findings(findings)

            # Prepare content for AI analysis
            content = "\n".join([
                f"Finding (Severity {f.severity}):\n{f.content}\n"
                f"Indicators: {', '.join(i.description for i in f.indicators)}"
                for f in findings if f.indicators
            ])

            if not content.strip():
                console.print("\n[yellow]No suspicious activities found for AI analysis.[/yellow]")
                return

            # Construct the prompt
            prompt = (
                "You are a forensic analyst reviewing log data for potential suspicious activity. "
                "Based on the following findings, provide a detailed analysis of the potential "
                "security threats and their implications. Include specific indicators and their "
                "significance.\n\n"
            )
            prompt += content

            # Load the model
            task2 = progress.add_task("[cyan]Loading AI model...", total=1)
            tokenizer, model = load_model(config["model_name"])
            progress.update(task2, completed=1)

            # Generate summary
            task3 = progress.add_task("[cyan]Generating AI analysis...", total=1)
            summary = generate_summary(
                prompt, 
                tokenizer, 
                model, 
                max_tokens=config["max_tokens"],
                mode=args.mode
            )
            progress.update(task3, completed=1)

        # Output results
        console.print("\n[bold green]AI Security Analysis:[/bold green]")
        console.print(summary)

        # Save to file if specified
        if args.output:
            with open(args.output, 'w') as f:
                f.write("=== Suspicious Activity Findings ===\n\n")
                for finding in findings:
                    if finding.indicators:
                        f.write(f"Severity: {finding.severity}\n")
                        f.write(f"Content: {finding.content}\n")
                        f.write("Indicators:\n")
                        for indicator in finding.indicators:
                            f.write(f"- {indicator.description}\n")
                        f.write("\n")
                
                f.write("\n=== AI Security Analysis ===\n\n")
                f.write(summary)
            console.print(f"\n[green]Full report saved to: {args.output}[/green]")

    except FileNotFoundError as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)
    except ValueError as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
