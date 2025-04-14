# gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tkinter import filedialog
from tkinterdnd2 import DND_FILES, TkinterDnD
import threading
from queue import Queue, Empty
from pathlib import Path
import os
import psutil
import gc
from typing import Optional, Dict, List, Tuple
from concurrent.futures import ThreadPoolExecutor
import json
import logging
from datetime import datetime
from ai_analyzer import NetworkAIAnalyzer
from log_parser import Finding, parse_file, LogParser, ThreatPatterns
import weakref
import sys
import time
import collections

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
MEMORY_THRESHOLD = 0.9  # 90% memory usage threshold
MAX_TEXT_LENGTH = 50000  # Maximum text length for display
BATCH_SIZE = 50  # Number of items to process in a batch
MAX_THREADS = min(os.cpu_count() or 2, 2)  # Limit threads
CLEANUP_INTERVAL = 30  # seconds
MAX_FINDINGS_PER_PAGE = 50
MAX_QUEUE_SIZE = 100
MAX_DISPLAY_ITEMS = 1000  # Maximum number of items to display at once

class LoadingDialog:
    """Dialog to show loading progress."""
    def __init__(self, parent, title="Loading...", message="Please wait..."):
        self.top = tk.Toplevel(parent)
        self.top.title(title)
        self.top.transient(parent)
        self.top.grab_set()
        
        # Center the dialog
        window_width = 300
        window_height = 100
        screen_width = parent.winfo_screenwidth()
        screen_height = parent.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.top.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # Add progress label
        self.label = ttk.Label(self.top, text=message)
        self.label.pack(pady=10)
        
        # Add progress bar
        self.progress = ttk.Progressbar(self.top, mode='indeterminate')
        self.progress.pack(pady=10, padx=20, fill=tk.X)
        
        self.progress.start()
        
    def update_message(self, message: str):
        """Update the loading message."""
        self.label.config(text=message)
        self.top.update()
        
    def destroy(self):
        self.progress.stop()
        self.top.destroy()

class ForensicScannerGUI:
    """Main GUI with proper memory management."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Local Forensic Scanner")
        self.root.geometry("1200x800")
        
        # Initialize components
        self.setup_variables()
        self.create_widgets()
        self.setup_cleanup()
        
        # Initialize processing components
        self.executor = ThreadPoolExecutor(max_workers=MAX_THREADS)
        self.cleanup_queue = Queue()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
        
        # Initialize state
        self.current_findings = []
        self.current_file = None
        self.current_file_name = None
        self.analyzer = None
        self.parser = LogParser(max_workers=MAX_THREADS)
        self.loading_dialog = None
        self.processing = False
        
        # Schedule periodic cleanup
        self.root.after(CLEANUP_INTERVAL, self._periodic_cleanup)
        
    def setup_variables(self):
        """Set up tkinter variables."""
        self.severity_var = tk.StringVar(value="1")
        self.category_var = tk.StringVar(value="ALL")
        self.status_var = tk.StringVar(value="Ready")
        
    def create_widgets(self):
        """Create GUI widgets with memory management."""
        try:
            # Main container
            self.main_frame = ttk.Frame(self.root, padding="10")
            self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            
            # File selection
            self.create_file_frame()
            
            # Filters
            self.create_filter_frame()
            
            # Findings area
            self.create_findings_area()
            
            # AI Analysis area
            self.create_analysis_area()
            
            # Status bar
            self.create_status_bar()
            
            # Configure grid weights
            self.root.columnconfigure(0, weight=1)
            self.root.rowconfigure(0, weight=1)
            self.main_frame.columnconfigure(0, weight=1)
            self.main_frame.rowconfigure(2, weight=1)
            self.main_frame.rowconfigure(3, weight=1)
            
        except Exception as e:
            logger.error(f"Error creating widgets: {e}")
            raise
            
    def create_file_frame(self):
        """Create file selection frame."""
        self.file_frame = ttk.LabelFrame(self.main_frame, text="File Selection", padding="5")
        self.file_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.file_button = ttk.Button(self.file_frame, text="Select File", command=self.select_file)
        self.file_button.grid(row=0, column=0, padx=5)
        
        self.file_label = ttk.Label(self.file_frame, text="Drag and drop or select a file")
        self.file_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Configure drag and drop
        self.root.drop_target_register(DND_FILES)
        self.root.dnd_bind('<<Drop>>', self.handle_drop)
        
    def create_filter_frame(self):
        """Create filter controls."""
        self.filter_frame = ttk.LabelFrame(self.main_frame, text="Filters", padding="5")
        self.filter_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Severity filter
        ttk.Label(self.filter_frame, text="Min Severity:").grid(row=0, column=0, padx=5)
        self.severity_combo = ttk.Combobox(
            self.filter_frame,
            textvariable=self.severity_var,
            values=["1", "2", "3", "4", "5"],
            width=5
        )
        self.severity_combo.grid(row=0, column=1, padx=5)
        
        # Category filter
        ttk.Label(self.filter_frame, text="Category:").grid(row=0, column=2, padx=5)
        self.category_combo = ttk.Combobox(
            self.filter_frame,
            textvariable=self.category_var,
            values=["ALL", "NETWORK", "SYSTEM", "MALWARE", "EXPLOIT"],
            width=10
        )
        self.category_combo.grid(row=0, column=3, padx=5)
        
        # Current file label
        self.file_label = ttk.Label(self.filter_frame, text="")
        self.file_label.grid(row=0, column=4, padx=5)
        
        # Apply button
        self.filter_button = ttk.Button(
            self.filter_frame,
            text="Apply Filters",
            command=self.apply_filters
        )
        self.filter_button.grid(row=0, column=5, padx=5)
        
    def create_findings_area(self):
        """Create findings display area."""
        self.findings_frame = ttk.LabelFrame(self.main_frame, text="Pattern-Based Findings", padding="5")
        self.findings_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.findings_text = scrolledtext.ScrolledText(
            self.findings_frame,
            wrap=tk.WORD,
            width=80,
            height=20
        )
        self.findings_text.pack(fill=tk.BOTH, expand=True)
        
    def create_analysis_area(self):
        """Create AI analysis display area."""
        self.analysis_frame = ttk.LabelFrame(self.main_frame, text="AI Analysis", padding="5")
        self.analysis_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.analysis_text = scrolledtext.ScrolledText(
            self.analysis_frame,
            wrap=tk.WORD,
            width=80,
            height=20
        )
        self.analysis_text.pack(fill=tk.BOTH, expand=True)
        
    def create_status_bar(self):
        """Create status bar."""
        self.status_bar = ttk.Label(
            self.main_frame,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            padding="2"
        )
        self.status_bar.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=5)
        
    def setup_cleanup(self):
        """Set up cleanup handlers."""
        self.root.protocol("WM_DELETE_WINDOW", self.cleanup)
        
    def _cleanup_worker(self):
        """Background worker for cleanup tasks."""
        while True:
            try:
                # Sleep to prevent tight loop
                time.sleep(CLEANUP_INTERVAL)
                
                # Check memory
                memory_percent = psutil.virtual_memory().percent
                if memory_percent >= MEMORY_THRESHOLD * 100:
                    logger.warning(f"High memory usage detected: {memory_percent}%")
                    self._perform_cleanup()
                    
            except Exception as e:
                logger.error(f"Error in cleanup worker: {e}")
                
    def _perform_cleanup(self):
        """Perform memory cleanup."""
        try:
            # Clear text widgets
            if len(self.findings_text.get("1.0", tk.END)) > MAX_DISPLAY_ITEMS:
                self.findings_text.delete("1.0", f"{MAX_DISPLAY_ITEMS}.0")
                
            if len(self.analysis_text.get("1.0", tk.END)) > MAX_DISPLAY_ITEMS:
                self.analysis_text.delete("1.0", f"{MAX_DISPLAY_ITEMS}.0")
                
            # Force garbage collection
            gc.collect()
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            
    def _periodic_cleanup(self):
        """Periodic cleanup task."""
        try:
            if self.check_memory():
                gc.collect()
            self.cleanup_queue.put(True)
        finally:
            # Schedule next cleanup
            self.root.after(CLEANUP_INTERVAL, self._periodic_cleanup)
            
    def cleanup(self):
        """Clean up resources before closing."""
        try:
            # Stop executor
            if hasattr(self, 'executor'):
                self.executor.shutdown(wait=False)
            
            # Clean up analyzer
            if hasattr(self, 'analyzer') and self.analyzer:
                self.analyzer.cleanup()
            
            # Clean up parser
            if hasattr(self, 'parser'):
                self.parser.cleanup()
            
            # Clear queues
            while not self.cleanup_queue.empty():
                try:
                    self.cleanup_queue.get_nowait()
                except Empty:
                    break
            
            # Clear text widgets
            if hasattr(self, 'findings_text'):
                self.findings_text.delete('1.0', tk.END)
            if hasattr(self, 'analysis_text'):
                self.analysis_text.delete('1.0', tk.END)
            
            # Force garbage collection
            gc.collect()
            
            # Destroy window
            self.root.destroy()
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            self.root.destroy()
            
    def check_memory(self) -> bool:
        """Check if enough memory is available."""
        try:
            memory = psutil.virtual_memory()
            if memory.percent >= (MEMORY_THRESHOLD * 100):
                gc.collect()
                return False
            return True
        except Exception as e:
            logger.error(f"Error checking memory: {e}")
            return False
            
    def handle_drop(self, event):
        """Handle file drop with memory check."""
        try:
            if not self.check_memory():
                messagebox.showerror("Error", "Insufficient memory to process file")
                return
                
            # Get file path
            file_path = event.data
            if file_path.startswith("{") and file_path.endswith("}"):
                file_path = file_path[1:-1]
                
            self.process_file(file_path)
            
        except Exception as e:
            logger.error(f"Error handling drop: {e}")
            messagebox.showerror("Error", f"Error processing file: {e}")
            
    def select_file(self):
        """Select file with memory check."""
        try:
            if not self.check_memory():
                messagebox.showerror("Error", "Insufficient memory to process file")
                return
                
            file_path = filedialog.askopenfilename(
                title="Select Log File",
                filetypes=[
                    ("All Files", "*.*"),
                    ("PCAP Files", "*.pcap"),
                    ("JSON Files", "*.json"),
                    ("Text Files", "*.txt")
                ]
            )
            
            if file_path:
                self.process_file(file_path)
                
        except Exception as e:
            logger.error(f"Error selecting file: {e}")
            messagebox.showerror("Error", f"Error selecting file: {e}")
            
    def process_file(self, file_path: str):
        """Process file with memory management."""
        if not self.check_memory():
            self.show_warning("Insufficient memory to process file")
            return
            
        try:
            # Check if already processing
            if self.processing:
                self.show_warning("Already processing a file")
                return
                
            self.processing = True
            self.current_file = file_path
            self.current_file_name = os.path.basename(file_path)
            
            # Show loading dialog
            self.loading_dialog = LoadingDialog(self.root, "Processing File", "Reading file...")
            
            def process():
                try:
                    # Update status
                    self.loading_dialog.update_message("Parsing file...")
                    
                    # Parse file
                    findings = parse_file(file_path)
                    
                    # Store current findings
                    self.current_findings = findings
                    
                    # Update GUI
                    self.root.after(0, lambda: self.display_findings(findings))
                    
                    # Update status with file name
                    self.status_var.set(f"Found {len(findings)} findings in {self.current_file_name}")
                    
                except Exception as e:
                    logger.error(f"Error processing file: {e}")
                    # Capture exception info properly for the lambda
                    error_info = str(e)
                    self.root.after(0, lambda msg=error_info: messagebox.showerror("Error", f"Failed to process file: {msg}"))
                    
                finally:
                    # Close loading dialog
                    self.root.after(0, self.loading_dialog.destroy)
                    self.processing = False
                    
            # Start processing in thread
            self.executor.submit(process)
            
        except Exception as e:
            logger.error(f"Error starting file processing: {e}")
            if self.loading_dialog:
                self.loading_dialog.destroy()
            self.processing = False
            messagebox.showerror("Error", f"Failed to start processing: {str(e)}")
            
    def display_findings(self, findings: List[Finding]):
        """Display findings with memory management, using Finding.severity and showing context/mitigation."""
        try:
            self.findings_text.config(state='normal') # Enable text area for modification
            self.findings_text.delete('1.0', tk.END)
            
            if not findings:
                self.findings_text.insert(tk.END, f"No findings match the current filters in {self.current_file_name if self.current_file_name else 'the current file'}.")
                self.update_ai_analysis([]) 
                self.findings_text.config(state='disabled') # Disable after modification
                return
                
            displayed_count = 0
            for i in range(0, len(findings), MAX_FINDINGS_PER_PAGE): # Use pagination constant
                chunk = findings[i:i + MAX_FINDINGS_PER_PAGE]
                chunk_text = ""
                for finding in chunk:
                    if displayed_count >= MAX_DISPLAY_ITEMS: 
                         chunk_text += f"\n... Display truncated at {MAX_DISPLAY_ITEMS} findings ..."
                         break
                    
                    # Basic Finding Info
                    chunk_text += f"--- Finding {displayed_count + 1} (Severity: {finding.severity}) ---\n"
                    chunk_text += f"Timestamp: {finding.timestamp}\n"
                    chunk_text += f"Source: {finding.source_file}:{finding.line_number}\n"
                    chunk_text += f"Content: {finding.content[:400]}{'...' if len(finding.content) > 400 else ''}\n" 
                    
                    # Simplified Indicators
                    if finding.indicators:
                        chunk_text += "Indicators:\n"
                        for indicator in finding.indicators:
                            chunk_text += f"  - {indicator.get('type', '')} ({indicator.get('category', '?')}): {indicator.get('description', '')}\n"
                                
                    # Context / Reasons (from ThreatDetector)
                    if finding.context:
                         # Add a check to see if mitigation was mentioned in the context
                         mitigated = "MITIGATION:" in finding.context
                         chunk_text += f"Context & Reasoning {'(Risk Mitigated)' if mitigated else ''}:\n"
                         # Indent context lines for readability
                         context_lines = finding.context.split('\n')
                         for line in context_lines:
                              chunk_text += f"  {line}\n"

                    # Detailed Risk Factors (Optional - could be a separate view or tooltip later)
                    # if finding.risk_factors:
                    #     chunk_text += "Risk Factors (Scores):\n"
                    #     for rf in finding.risk_factors:
                    #          chunk_text += f"  - {rf.name}: {rf.score:.2f}\n"
                             
                    chunk_text += "-" * 50 + "\n\n"
                    displayed_count += 1
                    
                # Insert chunk into text area
                self.findings_text.insert(tk.END, chunk_text)
                
                # Update GUI periodically if many pages
                if i % (MAX_FINDINGS_PER_PAGE * 5) == 0:
                     self.root.update_idletasks()
                
                # Check memory
                if not self.check_memory():
                    self.show_warning("Memory usage high - stopping display")
                    # Insert truncation message if stopped early
                    if displayed_count < len(findings):
                         self.findings_text.insert(tk.END, f"\n... Display interrupted due to high memory usage ({displayed_count}/{len(findings)} shown) ...")
                    break
            
            # Final GUI update after loop
            self.root.update_idletasks()
            self.findings_text.config(state='disabled') # Disable after all updates
                    
            # Update AI Analysis with the *displayed* findings
            self.update_ai_analysis(findings[:displayed_count])
            
        except Exception as e:
            logger.exception(f"Error displaying findings: {e}") 
            # Ensure text area is disabled even if error occurs
            try:
                self.findings_text.config(state='disabled') 
            except: pass # Ignore errors during error handling
            messagebox.showerror("Error", "Failed to display findings")
            
    def update_ai_analysis(self, findings: List[Finding]):
        """Update AI analysis of findings."""
        try:
            if not findings:
                self.analysis_text.delete('1.0', tk.END)
                self.analysis_text.insert(tk.END, "No findings to analyze.")
                return
                
            # Initialize analyzer if needed
            if not self.analyzer:
                self.analyzer = NetworkAIAnalyzer()
                
            # Prepare summary for analysis
            summary = self.prepare_findings_summary(findings)
            
            # Get AI analysis
            analysis = self.analyzer(
                f"Analyze these security findings and provide a detailed summary:\n{summary}",
                max_tokens=1024
            )
            
            # Display analysis
            self.analysis_text.delete('1.0', tk.END)
            self.analysis_text.insert(tk.END, analysis)
            
        except Exception as e:
            logger.error(f"Error updating AI analysis: {e}")
            self.analysis_text.delete('1.0', tk.END)
            self.analysis_text.insert(tk.END, f"Error generating analysis: {e}")
            
    def prepare_findings_summary(self, findings: List[Finding]) -> str:
        """Prepare a more detailed summary, noting mitigations."""
        if not findings:
            return "No findings to summarize."
        summary_lines = []
        total_findings = len(findings)
        severity_counts = collections.Counter(f.severity for f in findings)
        category_counts = collections.Counter()
        high_sev_examples = {5: [], 4: []}
        risk_factor_counts = collections.Counter()
        mitigated_count = 0

        for finding in findings:
            if finding.indicators: first_indicator_cat = finding.indicators[0].get('category', 'UNKNOWN'); category_counts[first_indicator_cat] += 1
            if finding.severity >= 4 and len(high_sev_examples[finding.severity]) < 3: high_sev_examples[finding.severity].append(f"- Sev {finding.severity}: {finding.content[:120]}...")
            if finding.risk_factors: 
                 for rf in finding.risk_factors:
                     risk_factor_counts[f"{rf.category}:{rf.name}"] += 1
                     # Check specifically for the mitigation factor
                     if rf.name == "RiskMitigation":
                          mitigated_count += 1

        # --- Build Summary String --- 
        summary_lines.append(f"Executive Summary: Processed {self.current_file_name or 'file'}. Found {total_findings} notable findings (Severity >= 2).")
        # Add note about mitigation if applicable
        if mitigated_count > 0:
            summary_lines.append(f"NOTE: {mitigated_count} finding(s) had their risk score reduced due to baseline/whitelisting factors.")

        # ... (Severity Breakdown remains the same) ...
        summary_lines.append("\nSeverity Breakdown:")
        for sev in sorted(severity_counts.keys(), reverse=True): 
            if sev >= 1: summary_lines.append(f"- Severity {sev}: {severity_counts[sev]} findings") # Show sev 1 counts too

        # ... (High Severity Examples remains the same) ...
        if high_sev_examples[5] or high_sev_examples[4]: 
            summary_lines.append("\nHigh Severity Examples (Sev 4-5):"); 
            summary_lines.extend(high_sev_examples[5]); 
            summary_lines.extend(high_sev_examples[4])

        # ... (Top Finding Categories remains the same) ...
        if category_counts: 
            summary_lines.append("\nTop Finding Categories:"); 
            for cat, count in category_counts.most_common(5): summary_lines.append(f"- {cat}: {count} findings")

        # ... (Key Contributing Risk Factors remains the same) ...
        if risk_factor_counts: 
            summary_lines.append("\nKey Contributing Risk Factors (excluding mitigation):"); 
            for rf_key, count in risk_factor_counts.most_common(5): 
                 if "RiskMitigation" not in rf_key: summary_lines.append(f"- {rf_key}: Contributed to {count} findings")
                
        # --- Recommendations Refined --- 
        summary_lines.append("\nRecommendations:")
        high_priority_triggered = False
        if severity_counts[5] > 0 or severity_counts[4] > 0:
            summary_lines.append("- **High Priority:** Investigate Severity 4 and 5 findings immediately. Focus on external sources, low-trust processes, and command-line anomalies mentioned in context.")
            high_priority_triggered = True
        # Check for specific high-risk factors even if severity is lower
        if 'AUTH:Failed authentication - external' in str(risk_factor_counts) or 'PROCESS:CommandLineRisk' in str(risk_factor_counts) and any(rf.score >= 4.0 for finding in findings if finding.risk_factors for rf in finding.risk_factors if rf.name == 'CommandLineRisk'):
            if not high_priority_triggered:
                 summary_lines.append("- **High Priority:** Investigate external failed logins and processes executing high-risk commands.")
                 high_priority_triggered = True
            else: # Add to existing high priority
                 summary_lines[-1] += " Also prioritize external failed logins and high-risk commands." 
                 
        if severity_counts[3] > 0:
             summary_lines.append("- **Medium Priority:** Review Severity 3 findings. These may indicate reconnaissance, moderate anomalies, or policy violations requiring monitoring or configuration checks.")
             
        # Add note about reviewing low severity findings if many were mitigated
        if mitigated_count > 5 or (mitigated_count > 0 and not high_priority_triggered and severity_counts[3] == 0):
             summary_lines.append("- **Low Priority:** Review Severity 1-2 findings, especially those marked as mitigated, to ensure baseline/whitelists are accurate and no threats were overly downgraded.")
        elif not high_priority_triggered and severity_counts[3] == 0:
            summary_lines.append("- No high or medium priority threats detected based on current analysis. Consider reviewing baseline rules if unexpected low-severity findings occurred.")
            
        return "\n".join(summary_lines)

    def apply_filters(self):
        """Apply filters using Finding.severity and category from indicators."""
        try:
            if not self.current_findings:
                self.findings_text.delete('1.0', tk.END)
                self.findings_text.insert(tk.END, "No findings to filter.")
                self.update_ai_analysis([]) # Clear AI analysis too
                return
                
            if not self.check_memory():
                messagebox.showerror("Error", "Insufficient memory to apply filters")
                return
                
            # Get filter values
            try:
                min_severity = int(self.severity_var.get())
                # Ensure min_severity is at least 1
                min_severity = max(1, min_severity) 
            except ValueError:
                min_severity = 1 # Default to 1 if input is invalid
                self.severity_var.set("1")
                
            category = self.category_var.get()
            
            # Update file label
            if self.current_file_name:
                self.file_label.config(text=f"Current file: {self.current_file_name}")
            else:
                self.file_label.config(text="No file loaded")
            
            # Filter findings based on Finding.severity and indicator category
            filtered = []
            for finding in self.current_findings:
                # Filter by the main finding severity
                if finding.severity < min_severity:
                    continue
                    
                # Filter by category (check indicators)
                if category != "ALL":
                    matches_category = False
                    if finding.indicators:
                        for indicator in finding.indicators:
                            # Handle both dict and RiskFactor-like objects for category check
                            indicator_cat = None
                            if isinstance(indicator, dict):
                                indicator_cat = indicator.get('category')
                            elif hasattr(indicator, 'category'):
                                indicator_cat = indicator.category
                            
                            if indicator_cat == category:
                                matches_category = True
                                break
                    if not matches_category:
                        continue # Skip if no indicator matches the selected category
                
                # If finding passes both severity and category filters, add it
                filtered.append(finding)
                        
            # Display filtered findings
            self.display_findings(filtered)
            
            # Update status
            self.status_var.set(f"Showing {len(filtered)} of {len(self.current_findings)} findings in {self.current_file_name or 'N/A'}")
            
        except Exception as e:
            logger.exception(f"Error applying filters: {e}") # Log stack trace
            messagebox.showerror("Error", f"Error applying filters: {e}")
            
    def show_warning(self, message: str):
        """Show warning in GUI thread."""
        self.root.after(0, lambda: messagebox.showwarning("Warning", message))

def main():
    """Main entry point with error handling."""
    try:
        root = TkinterDnD.Tk()
        app = ForensicScannerGUI(root)
        root.mainloop()
    except Exception as e:
        logger.error(f"Error starting application: {e}")
        messagebox.showerror("Error", f"Error starting application: {e}")

if __name__ == "__main__":
    main()