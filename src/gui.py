# gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tkinter import filedialog
from tkinterdnd2 import DND_FILES, TkinterDnD
import threading
from pathlib import Path
import os
from typing import Optional, Dict, List
from log_parser import (
    parse_wireshark_log,
    parse_volatility_json,
    parse_volatility_text,
    parse_generic_text,
    Finding,
    SUSPICIOUS_PATTERNS
)
import json
from datetime import datetime
import webbrowser
from rich.console import Console
import sys
import queue
import gc
import logging

# Optional imports
try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False
    print("Warning: psutil not available. Memory monitoring disabled.")

from concurrent.futures import ThreadPoolExecutor
from ai_analyzer import NetworkAIAnalyzer

logger = logging.getLogger(__name__)

class LoadingDialog:
    def __init__(self, parent, title="Loading", message="Please wait..."):
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
        
        # Message
        tk.Label(self.top, text=message, pady=10).pack()
        
        # Progress bar
        self.progress = ttk.Progressbar(self.top, mode='indeterminate')
        self.progress.pack(padx=20, pady=10, fill=tk.X)
        self.progress.start(10)
        
        # Status label
        self.status_var = tk.StringVar(value="Initializing...")
        self.status_label = tk.Label(self.top, textvariable=self.status_var)
        self.status_label.pack(pady=5)
        
        self.top.protocol("WM_DELETE_WINDOW", lambda: None)  # Prevent closing
        
    def update_status(self, message):
        self.status_var.set(message)
        
    def destroy(self):
        self.top.destroy()

class ForensicScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Local Forensic Scanner")
        self.root.geometry("1200x800")
        
        # Initialize loading dialog
        self.loading_dialog = None
        
        # Initialize thread pool
        self._executor = ThreadPoolExecutor(max_workers=2)
        self._analysis_lock = threading.Lock()
        
        # Initialize AI analyzer with loading indicator
        self.initialize_ai_analyzer()
        
        # Configure style
        self.setup_styles()
        
        # Create menu
        self.create_menu()
        
        # Create main container
        self.main_frame = ttk.Frame(root, style="Custom.TFrame", padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create top frame for controls
        self.create_top_controls()
        
        # Create drag & drop area
        self.create_drag_drop_area()
        
        # Create file type selection
        self.create_file_type_selection()
        
        # Create filter frame
        self.create_filter_frame()
        
        # Create output area with tabs
        self.create_output_area()
        
        # Create chat interface
        self.create_chat_interface()
        
        # Create status bar
        self.create_status_bar()
        
        # Initialize queue for thread-safe GUI updates
        self.queue = queue.Queue()
        self.root.after(100, self.process_queue)
        
        # Initialize state
        self.model_loaded = False
        self.model = None
        self.tokenizer = None
        self.current_file = None
        self.current_findings = []
        
        # Statistics
        self.stats = {
            "files_scanned": 0,
            "threats_found": 0,
            "last_scan": None
        }
        
        # Load settings
        self.load_settings()
        
        # Set up cleanup
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        """Clean up resources before closing."""
        try:
            # Stop thread pool
            if hasattr(self, '_executor'):
                self._executor.shutdown(wait=False)
            
            # Clean up AI analyzer
            if hasattr(self, 'ai_analyzer') and self.ai_analyzer:
                del self.ai_analyzer
            
            # Force garbage collection
            gc.collect()
            
            # Close window
            self.root.destroy()
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            self.root.destroy()

    def setup_styles(self):
        style = ttk.Style()
        
        # Configure custom styles
        style.configure(
            "Custom.TFrame",
            background="#f0f0f0"
        )
        style.configure(
            "Header.TLabel",
            font=("Helvetica", 12, "bold"),
            padding=5
        )
        style.configure(
            "Status.TLabel",
            padding=5,
            relief="sunken"
        )
        style.configure(
            "Filter.TFrame",
            padding=5,
            relief="groove"
        )
        # Add AI button style
        style.configure(
            "AI.TButton",
            font=("Helvetica", 10, "bold"),
            padding=10
        )
        # Configure hover effect
        style.map(
            "AI.TButton",
            background=[("active", "#45a049")],
            foreground=[("active", "white")]
        )

    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open File", command=self.select_file)
        file_menu.add_command(label="Save Report", command=self.save_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Clear Output", command=self.clear_output)
        tools_menu.add_command(label="View Statistics", command=self.show_statistics)
        tools_menu.add_command(label="Export Patterns", command=self.export_patterns)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=lambda: webbrowser.open("https://github.com/yourusername/LocalForensicScanner"))
        help_menu.add_command(label="About", command=self.show_about)

    def create_top_controls(self):
        # Main control frame
        control_frame = ttk.Frame(self.main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Left side buttons frame
        left_buttons = ttk.Frame(control_frame)
        left_buttons.pack(side=tk.LEFT, fill=tk.X)
        
        # Add scan button
        self.scan_button = ttk.Button(
            left_buttons,
            text="Start Scan",
            command=self.select_file,
            style="Accent.TButton"
        )
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        # Add clear button
        self.clear_button = ttk.Button(
            left_buttons,
            text="Clear",
            command=self.clear_output
        )
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Center frame for AI button
        center_frame = ttk.Frame(control_frame)
        center_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=20)
        
        # Add AI Analysis button with distinct style
        style = ttk.Style()
        style.configure(
            "AI.TButton",
            background="#4CAF50",
            foreground="white",
            padding=10,
            font=("Helvetica", 10, "bold")
        )
        
        self.ai_button = ttk.Button(
            center_frame,
            text="▶ Run AI Analysis",
            command=self.start_ai_analysis,
            style="AI.TButton",
            state='disabled'  # Initially disabled
        )
        self.ai_button.pack(side=tk.TOP, pady=5)
        
        # Right side statistics
        self.stats_label = ttk.Label(
            control_frame,
            text="Files Scanned: 0 | Threats Found: 0",
            style="Header.TLabel"
        )
        self.stats_label.pack(side=tk.RIGHT, padx=5)

    def create_filter_frame(self):
        filter_frame = ttk.Frame(self.main_frame, style="Filter.TFrame")
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Severity filter
        ttk.Label(filter_frame, text="Min Severity:").pack(side=tk.LEFT, padx=5)
        self.severity_var = tk.StringVar(value="0")
        severity_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.severity_var,
            values=["0", "1", "2", "3", "4", "5"],
            width=5
        )
        severity_combo.pack(side=tk.LEFT, padx=5)
        
        # Category filter
        ttk.Label(filter_frame, text="Category:").pack(side=tk.LEFT, padx=5)
        self.category_var = tk.StringVar(value="ALL")
        categories = ["ALL"] + sorted(set(p.category for p in SUSPICIOUS_PATTERNS))
        category_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.category_var,
            values=categories,
            width=20
        )
        category_combo.pack(side=tk.LEFT, padx=5)
        
        # Auto-refresh checkbox
        self.auto_refresh = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            filter_frame,
            text="Auto-refresh",
            variable=self.auto_refresh
        ).pack(side=tk.LEFT, padx=5)
        
        # Apply filter button
        ttk.Button(
            filter_frame,
            text="Apply Filter",
            command=self.apply_filters
        ).pack(side=tk.RIGHT, padx=5)

    def create_output_area(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        # Create findings tab
        findings_frame = ttk.Frame(self.notebook)
        self.notebook.add(findings_frame, text="Findings")
        
        # Create findings display
        self.findings_text = scrolledtext.ScrolledText(
            findings_frame,
            wrap=tk.WORD,
            height=20,
            font=("Consolas", 10)
        )
        self.findings_text.pack(fill=tk.BOTH, expand=True)
        
        # Create AI Analysis tab
        ai_frame = ttk.Frame(self.notebook)
        self.notebook.add(ai_frame, text="AI Analysis")
        
        self.ai_text = scrolledtext.ScrolledText(
            ai_frame,
            wrap=tk.WORD,
            height=20,
            font=("Consolas", 10)
        )
        self.ai_text.pack(fill=tk.BOTH, expand=True)

    def apply_filters(self):
        """Apply filters to current findings"""
        try:
            if not hasattr(self, 'current_findings') or not self.current_findings:
                return
                
            # Get filter values
            min_severity = int(self.severity_var.get())
            category = self.category_var.get()
            
            # Apply filters
            filtered_findings = []
            for finding in self.current_findings:
                # Check if any indicator meets the severity threshold
                max_indicator_severity = max([i.severity for i in finding.indicators]) if finding.indicators else 0
                
                if max_indicator_severity >= min_severity:
                    if category == "ALL" or any(i.category == category for i in finding.indicators):
                        filtered_findings.append(finding)
            
            # Display filtered findings without triggering AI analysis
            self.display_filtered_findings(filtered_findings)
            
        except Exception as e:
            logger.error(f"Error applying filters: {e}")
            messagebox.showerror("Error", f"Failed to apply filters: {str(e)}")

    def display_filtered_findings(self, findings: List[Finding]):
        """Display filtered findings without triggering AI analysis."""
        try:
            # Clear findings display
            self.findings_text.configure(state='normal')
            self.findings_text.delete(1.0, tk.END)
            
            if not findings:
                self.findings_text.insert(tk.END, "No findings match the current filters.\n")
                self.findings_text.configure(state='disabled')
                return
            
            # Display findings
            for i, finding in enumerate(findings, 1):
                # Calculate maximum severity from indicators
                max_severity = max([i.severity for i in finding.indicators]) if finding.indicators else 0
                severity_tag = "high" if max_severity >= 4 else "medium" if max_severity >= 2 else "low"
                
                self.findings_text.insert(tk.END, f"\nFinding {i}:\n", "header")
                self.findings_text.insert(tk.END, f"Content: {finding.content}\n")
                self.findings_text.insert(tk.END, f"Severity: {max_severity}\n", severity_tag)
                self.findings_text.insert(tk.END, "Indicators:\n")
                
                for indicator in finding.indicators:
                    indicator_severity_tag = "high" if indicator.severity >= 4 else "medium" if indicator.severity >= 2 else "low"
                    self.findings_text.insert(tk.END, f"- {indicator.description} (Severity: {indicator.severity})\n", indicator_severity_tag)
                
                self.findings_text.insert(tk.END, "-" * 80 + "\n")
            
            self.findings_text.configure(state='disabled')
            
        except Exception as error:
            logger.error(f"Error displaying filtered findings: {error}")
            messagebox.showerror("Error", f"Error displaying filtered findings: {str(error)}")

    def save_report(self):
        """Save the current findings to a file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.findings_text.get(1.0, tk.END))
                messagebox.showinfo("Success", "Report saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {str(e)}")

    def show_statistics(self):
        """Show detailed statistics"""
        stats = f"""=== Scan Statistics ===
Files Scanned: {self.stats['files_scanned']}
Total Threats Found: {self.stats['threats_found']}
Last Scan: {self.stats['last_scan'] or 'Never'}

=== Threat Categories ===
"""
        if hasattr(self, 'current_findings'):
            category_stats = {}
            for finding in self.current_findings:
                for indicator in finding.indicators:
                    category_stats[indicator.category] = category_stats.get(indicator.category, 0) + 1
            
            for category, count in sorted(category_stats.items()):
                stats += f"{category}: {count}\n"
        
        self.stats_text.configure(state='normal')
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats)
        self.stats_text.configure(state='disabled')
        
        self.notebook.select(1)  # Switch to statistics tab

    def export_patterns(self):
        """Export current detection patterns"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            try:
                patterns = [{
                    "pattern": p.pattern,
                    "description": p.description,
                    "severity": p.severity,
                    "category": p.category
                } for p in SUSPICIOUS_PATTERNS]
                
                with open(file_path, 'w') as f:
                    json.dump(patterns, f, indent=2)
                messagebox.showinfo("Success", "Patterns exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export patterns: {str(e)}")

    def show_about(self):
        """Show about dialog"""
        about_text = """Local Forensic Scanner

A tool for analyzing log files and detecting suspicious activities.

Features:
- Multiple log format support
- Advanced pattern detection
- Real-time filtering
- Detailed statistics
- Report generation

Version: 1.0
"""
        messagebox.showinfo("About", about_text)

    def clear_output(self):
        """Clear all output areas"""
        self.findings_text.configure(state='normal')
        self.findings_text.delete(1.0, tk.END)
        self.findings_text.configure(state='disabled')
        
        self.ai_text.configure(state='normal')
        self.ai_text.delete(1.0, tk.END)
        self.ai_text.configure(state='disabled')

    def load_settings(self):
        """Load user settings"""
        try:
            if os.path.exists('settings.json'):
                with open('settings.json', 'r') as f:
                    settings = json.load(f)
                    self.auto_refresh.set(settings.get('auto_refresh', True))
                    self.severity_var.set(settings.get('min_severity', '0'))
                    self.category_var.set(settings.get('category', 'ALL'))
        except Exception:
            pass

    def save_settings(self):
        """Save user settings"""
        settings = {
            'auto_refresh': self.auto_refresh.get(),
            'min_severity': self.severity_var.get(),
            'category': self.category_var.get()
        }
        try:
            with open('settings.json', 'w') as f:
                json.dump(settings, f)
        except Exception:
            pass

    def update_statistics(self, findings):
        """Update statistics display"""
        self.stats['files_scanned'] += 1
        self.stats['threats_found'] += len([f for f in findings if f.indicators])
        self.stats['last_scan'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        self.stats_label.config(
            text=f"Files Scanned: {self.stats['files_scanned']} | "
                 f"Threats Found: {self.stats['threats_found']}"
        )

    def display_findings(self, findings: List[Finding]):
        """Display findings without triggering AI analysis."""
        try:
            self.current_findings = findings
            
            # Enable AI Analysis button if we have findings
            self.ai_button.configure(state='normal' if findings else 'disabled')
            
            # Display findings
            self.display_filtered_findings(findings)
                
        except Exception as error:
            logger.error(f"Error displaying findings: {error}")
            messagebox.showerror("Error", f"Error displaying findings: {str(error)}")

    def analyze_findings(self, findings: List[Finding]):
        try:
            # Re-enable AI button when analysis completes
            def enable_ai_button():
                self.ai_button.configure(state='normal')
            
            # Convert findings to dictionary format
            finding_dicts = []
            for f in findings:
                try:
                    # Calculate maximum severity from indicators
                    max_severity = max([i.severity for i in f.indicators]) if f.indicators else 0
                    
                    finding_dict = {
                        'content': str(f.content)[:1000],  # Limit content length
                        'severity': max_severity,  # Use maximum indicator severity
                        'indicators': [{'description': str(i.description), 'severity': int(i.severity)} for i in f.indicators],
                        'source_line': str(f.source_line),
                        'timestamp': str(f.timestamp)
                    }
                    finding_dicts.append(finding_dict)
                except Exception as e:
                    logger.error(f"Error converting finding to dict: {e}")
                    continue
            
            # Log analysis start
            self.log_ai_finding("Starting AI Analysis...", "info")
            
            # Analyze each finding individually
            for finding_dict in finding_dicts:
                try:
                    # Only analyze findings with severity >= 2
                    if finding_dict['severity'] >= 2:
                        # Check for false positives
                        fp_analysis = self.ai_analyzer.check_false_positive(finding_dict)
                        
                        if fp_analysis and not fp_analysis.get('IS_FALSE_POSITIVE', 'true').lower() == 'true':
                            # Analyze the finding in detail
                            analysis = self.ai_analyzer.analyze_log_entry(finding_dict['content'])
                            if analysis:
                                severity = int(analysis.get('SEVERITY', finding_dict['severity']))
                                severity_tag = "high" if severity >= 4 else "medium" if severity >= 2 else "low"
                                
                                self.log_ai_finding(
                                    f"Threat Detected:\n"
                                    f"- Type: {analysis.get('THREAT', 'Unknown')}\n"
                                    f"- Confidence: {analysis.get('CONFIDENCE', '0')}\n"
                                    f"- Severity: {severity}\n"
                                    f"- Details: {analysis.get('EXPLANATION', 'No explanation provided')}\n"
                                    f"Recommended Actions:",
                                    severity_tag
                                )
                                
                                if 'ACTIONS' in analysis:
                                    for action in str(analysis['ACTIONS']).split(','):
                                        self.log_ai_finding(f"  • {action.strip()}", severity_tag)
                                        
                except Exception as e:
                    logger.error(f"Error analyzing finding: {e}")
                    continue
            
            # Perform correlation analysis only on findings with severity >= 2
            high_severity_findings = [f for f in finding_dicts if f['severity'] >= 2]
            if len(high_severity_findings) > 1:
                try:
                    correlation = self.ai_analyzer.correlate_findings(high_severity_findings[:5])  # Limit to 5 findings
                    if correlation:
                        severity = int(correlation.get('SEVERITY', '3'))
                        severity_tag = "high" if severity >= 4 else "medium" if severity >= 2 else "low"
                        
                        self.log_ai_finding(
                            f"Correlation Analysis:\n"
                            f"- Pattern: {correlation.get('CORRELATED_THREAT', 'Unknown')}\n"
                            f"- Confidence: {correlation.get('CONFIDENCE', '0')}\n"
                            f"- Severity: {severity}\n"
                            f"- Analysis: {correlation.get('EXPLANATION', 'No explanation provided')}",
                            severity_tag
                        )
                        
                        if 'RECOMMENDED_ACTIONS' in correlation:
                            self.log_ai_finding("Recommended Actions:", severity_tag)
                            for action in str(correlation['RECOMMENDED_ACTIONS']).split(','):
                                self.log_ai_finding(f"  • {action.strip()}", severity_tag)
                                
                except Exception as e:
                    logger.error(f"Error during correlation analysis: {e}")
                    
            # Log analysis completion
            self.log_ai_finding("AI Analysis Complete", "info")
            
            # Re-enable AI button
            self.root.after(0, enable_ai_button)
                    
        except Exception as e:
            self.log_ai_finding(f"Error during AI analysis: {str(e)}", "high")
            # Re-enable AI button on error
            self.root.after(0, enable_ai_button)

    def initialize_ai_analyzer(self):
        """Initialize AI analyzer with loading dialog."""
        def init_ai():
            try:
                self.loading_dialog.update_status("Loading AI model...")
                self.ai_analyzer = NetworkAIAnalyzer(debug=True)
                self.root.after(0, self.loading_dialog.destroy)
            except Exception as e:
                logger.error(f"Failed to initialize AI analyzer: {e}")
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to initialize AI: {str(e)}"))
                self.root.after(0, self.loading_dialog.destroy)
                self.ai_analyzer = None
        
        self.loading_dialog = LoadingDialog(self.root, "Initializing AI", "Loading AI model...")
        threading.Thread(target=init_ai, daemon=True).start()

    def process_file(self, file_path: str):
        """Process a file with loading indicator."""
        def do_process():
            try:
                self.loading_dialog.update_status("Analyzing file...")
                
                # Determine file type
                ext = Path(file_path).suffix.lower()
                if ext == '.pcap' or ext == '.pcapng':
                    parser = parse_wireshark_log
                elif ext == '.json':
                    parser = parse_volatility_json
                elif ext == '.txt':
                    parser = parse_generic_text
                else:
                    parser = parse_generic_text
                
                # Parse file
                self.loading_dialog.update_status("Parsing file...")
                findings = parser(file_path)
                
                # Update UI
                self.loading_dialog.update_status("Updating display...")
                self.root.after(0, lambda: self.display_findings(findings))
                
                # Update statistics
                self.root.after(0, lambda: self.update_statistics(findings))
                
                self.root.after(0, self.loading_dialog.destroy)
                
            except Exception as error:
                logger.error(f"Error processing file: {error}")
                # Store error in a variable that will be in scope for the lambda
                error_msg = str(error)
                self.root.after(0, lambda: messagebox.showerror("Error", f"Error processing file: {error_msg}"))
                self.root.after(0, self.loading_dialog.destroy)
        
        self.loading_dialog = LoadingDialog(self.root, "Processing File", "Analyzing file...")
        threading.Thread(target=do_process, daemon=True).start()

    def select_file(self):
        """Open a file dialog to select a log file for analysis."""
        file_path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[
                ("All Log Files", "*.log;*.txt;*.json"),
                ("Wireshark Logs", "*.log"),
                ("Volatility Text", "*.txt"),
                ("Volatility JSON", "*.json"),
                ("All Files", "*.*")
            ]
        )
        if file_path:
            self.process_file(file_path)

    def create_drag_drop_area(self):
        """Create a drag and drop area for files."""
        self.drop_frame = ttk.Frame(
            self.main_frame,
            style="Custom.TFrame",
            padding="20"
        )
        self.drop_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.drop_label = ttk.Label(
            self.drop_frame,
            text="Drop log files here or click to select",
            style="Header.TLabel"
        )
        self.drop_label.pack(pady=10)
        
        # Configure drag and drop
        self.drop_frame.drop_target_register(DND_FILES)
        self.drop_frame.dnd_bind('<<Drop>>', self.handle_drop)
        
        # Make the frame clickable
        self.drop_frame.bind('<Button-1>', lambda e: self.select_file())
        self.drop_label.bind('<Button-1>', lambda e: self.select_file())

    def handle_drop(self, event):
        """Handle file drop events."""
        file_path = event.data
        # Clean up the file path (remove curly braces and quotes if present)
        file_path = file_path.strip('{}').strip('"')
        if os.path.isfile(file_path):
            self.process_file(file_path)
        else:
            messagebox.showerror(
                "Error",
                "Invalid file dropped. Please drop a valid log file."
            )

    def create_file_type_selection(self):
        """Create file type selection dropdown."""
        frame = ttk.Frame(self.main_frame)
        frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(
            frame,
            text="File Type:",
            style="Header.TLabel"
        ).pack(side=tk.LEFT, padx=5)
        
        self.file_type = tk.StringVar(value="wireshark")
        file_type_combo = ttk.Combobox(
            frame,
            textvariable=self.file_type,
            values=[
                "wireshark",
                "volatility_text",
                "volatility_json",
                "generic"
            ],
            state="readonly",
            width=20
        )
        file_type_combo.pack(side=tk.LEFT, padx=5)

    def create_status_bar(self):
        """Create status bar at the bottom of the window."""
        self.status_bar = ttk.Label(
            self.root,
            text="Ready",
            style="Status.TLabel",
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def update_status(self, message: str):
        """Update status bar message."""
        self.status_bar.config(text=message)
        self.root.update_idletasks()

    def process_queue(self):
        """Process queued GUI updates."""
        try:
            while True:
                item = self.queue.get_nowait()
                if not isinstance(item, tuple) or len(item) != 2:
                    continue
                    
                msg_type, message = item
                
                if msg_type == "chat":
                    # Convert chat messages to log entries
                    severity = "info"
                    if "Error" in message:
                        severity = "high"
                    elif "Warning" in message:
                        severity = "medium"
                    self.log_ai_finding(message, severity)
                elif msg_type == "ai_analysis":
                    self.ai_text.configure(state='normal')
                    self.ai_text.insert(tk.END, str(message))
                    self.ai_text.configure(state='disabled')
                    self.ai_text.see(tk.END)
                self.queue.task_done()
        except queue.Empty:
            self.root.after(100, self.process_queue)
        except Exception as e:
            logger.error(f"Error processing queue: {e}")
            self.root.after(100, self.process_queue)

    def append_output(self, text: str, tag: str = None):
        """Thread-safe method to append text to output."""
        def _append():
            self.findings_text.configure(state='normal')
            self.findings_text.insert(tk.END, text + "\n", tag)
            self.findings_text.configure(state='disabled')
            self.findings_text.see(tk.END)
        self.queue.put(_append)

    def create_chat_interface(self):
        # Create AI Analysis Log frame
        log_frame = ttk.LabelFrame(self.main_frame, text="AI Analysis Log", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        # Create log display area
        self.chat_display = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            height=10,
            font=("Consolas", 10)
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for different severity levels
        self.chat_display.tag_configure("high", foreground="red")
        self.chat_display.tag_configure("medium", foreground="orange")
        self.chat_display.tag_configure("low", foreground="green")
        self.chat_display.tag_configure("info", foreground="blue")
        
        # Add initial message
        self.chat_display.insert(tk.END, "AI Analysis Log - Findings will be displayed here\n\n", "info")
        self.chat_display.configure(state='disabled')

    def log_ai_finding(self, message: str, severity: str = "info"):
        """Add a finding to the AI analysis log with appropriate severity coloring."""
        self.chat_display.configure(state='normal')
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.chat_display.insert(tk.END, f"[{timestamp}] ", "info")
        self.chat_display.insert(tk.END, f"{message}\n\n", severity)
        self.chat_display.configure(state='disabled')
        self.chat_display.see(tk.END)

    def start_ai_analysis(self):
        """Start AI analysis when button is clicked."""
        if not self.current_findings:
            messagebox.showinfo("Info", "No findings to analyze.")
            return
            
        if not self.ai_analyzer:
            messagebox.showerror("Error", "AI analyzer not initialized.")
            return
            
        # Clear previous AI analysis
        self.chat_display.configure(state='normal')
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.insert(tk.END, "AI Analysis Log - Starting new analysis...\n\n", "info")
        self.chat_display.configure(state='disabled')
        
        # Start analysis in a separate thread
        threading.Thread(target=self.analyze_findings, args=(self.current_findings,), daemon=True).start()
        
        # Disable the button while analysis is running
        self.ai_button.configure(state='disabled')

def main():
    root = TkinterDnD.Tk()
    app = ForensicScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 