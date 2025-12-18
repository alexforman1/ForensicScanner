# 🔍 ForensicScanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge)
![AI](https://img.shields.io/badge/AI-Local%20LLM-FF6B6B?style=for-the-badge)
![GUI](https://img.shields.io/badge/GUI-Tkinter-0066CC?style=for-the-badge)

<h3>Advanced forensic log analysis tool with local AI-powered threat detection and analysis</h3>

**[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Project Structure](#-project-structure) • [Configuration](#-configuration)**

</div>

---

## 📖 Overview

**ForensicScanner** is a comprehensive Python-based forensic analysis tool designed to analyze security logs, network traffic, and system artifacts for potential threats. It combines pattern-based detection with local AI-powered analysis to provide detailed security insights without requiring cloud connectivity.

### 🎯 Key Objectives

- **Local AI Analysis** - Process sensitive logs offline using local GGUF models (Mistral 7B, Llama 2)
- **Multi-Format Support** - Analyze Wireshark PCAP files, Volatility memory dumps (JSON/text), and generic log files
- **Threat Detection** - Advanced pattern matching with dynamic severity scoring
- **GUI & CLI Interfaces** - Both graphical and command-line interfaces for different workflows
- **Real-time Analysis** - Memory-efficient processing with intelligent resource management

---

## ✨ Features

### 🔎 Log Processing
- **📁 Multi-Format Support**
  - Wireshark PCAP files and log exports
  - Volatility memory analysis outputs (JSON and text formats)
  - Generic text logs with pattern detection
- **🔍 Pattern-Based Detection**
  - Pre-configured threat indicators (malware, exploits, network attacks)
  - Customizable pattern matching rules
  - Severity-based scoring (1-5 scale)
- **⏱️ Temporal Analysis**
  - Timestamp extraction and correlation
  - Time-based filtering and search
  - Anomaly detection based on activity timing

### 🤖 AI-Powered Analysis
- **🧠 Local LLM Integration**
  - Supports Mistral 7B (recommended) and Llama 2 models
  - GGUF format for efficient CPU-based inference
  - No cloud dependency - all processing local
- **📊 Context-Aware Scoring**
  - Dynamic risk factor calculation
  - Process and network behavior analysis
  - Business hours vs. after-hours risk adjustment
- **💡 Intelligent Recommendations**
  - Suggested actions based on findings
  - False positive detection
  - Severity-based prioritization

### 🖥️ User Interface
- **🎨 Modern GUI Application**
  - Drag-and-drop file support
  - Real-time findings display
  - Filterable results by severity and category
  - Interactive AI analysis panel
- **⌨️ Command-Line Interface**
  - Batch processing support
  - Scriptable workflows
  - Configurable output formats
  - Rich terminal output with tables and progress bars

### 🔒 Security & Performance
- **🛡️ Memory Management**
  - Intelligent resource cleanup
  - Large file handling with chunked processing
  - Memory threshold monitoring
- **⚡ Performance Optimization**
  - Multi-threaded processing
  - Efficient pattern matching
  - Background analysis tasks
- **📝 Audit Trail**
  - Comprehensive logging
  - Exportable analysis reports
  - Finding history tracking

---

## 🚀 Installation

### Prerequisites

- **Python 3.8+** 
- **8GB+ RAM** (16GB recommended for AI models)
- **~5GB free disk space** (for AI models)
- **CPU with AVX2 support** (most modern CPUs)

### Step-by-Step Installation

1. **Clone the Repository**
```bash
git clone https://github.com/alexforman1/ForensicScanner.git
cd ForensicScanner
```

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

3. **Download AI Model (Optional but Recommended)**

The application works without an AI model but provides enhanced analysis with one. Download a recommended model:

**Option A: Mistral 7B (Recommended)**
- Download from: [TheBloke/Mistral-7B-Instruct-v0.2-GGUF](https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF)
- Recommended file: `mistral-7b-instruct-v0.2.Q4_K_M.gguf` (~4GB)
- Place in `models/` directory

**Option B: Llama 2 7B (Alternative)**
- Download from: [TheBloke/Llama-2-7B-Chat-GGUF](https://huggingface.co/TheBloke/Llama-2-7B-Chat-GGUF)
- Recommended file: `llama-2-7b-chat.Q4_K_M.gguf` (~4GB)
- Place in `models/` directory

The application will automatically detect and use available models in the `models/` directory.

4. **Verify Installation**
```bash
python main.py --help
```

---

## 💻 Usage

### GUI Mode

Launch the graphical interface:
```bash
python gui.py
```

**Features:**
- Drag and drop log files directly into the window
- Use "Select File" button to browse for files
- Filter findings by severity (1-5) and category (NETWORK, SYSTEM, MALWARE, EXPLOIT, ALL)
- View pattern-based findings in the top panel
- Review AI analysis in the bottom panel
- Export results using the save functionality

### CLI Mode

**Basic Usage:**
```bash
python main.py --file <log_file> --type <log_type> [options]
```

**Log Types:**
- `wireshark` - Wireshark PCAP or log files
- `volatility_json` - Volatility output in JSON format
- `volatility_text` - Volatility output in text format
- `generic` - Generic text log files

**Examples:**

Analyze a Wireshark log:
```bash
python main.py --file network_traffic.pcap --type wireshark
```

Process Volatility JSON output with detailed analysis:
```bash
python main.py --file memory_dump.json --type volatility_json --mode detailed --output report.txt
```

Search for specific patterns in generic logs:
```bash
python main.py --file system.log --type generic --search "failed login"
```

Analyze with custom configuration:
```bash
python main.py --file logs.txt --type generic --config config.json --mode technical
```

**Command-Line Options:**
```
--file, -f          Path to the log file (required)
--type, -t          Type of log file: wireshark, volatility_json, volatility_text, generic (required)
--search, -s        Optional search term to filter findings
--config, -c        Path to configuration file
--output, -o        Path to save the summary
--mode, -m          Summarization mode: brief, detailed, technical (default: detailed)
```

---

## 📁 Project Structure

```
ForensicScanner/
│
├── 📂 config/                      # Configuration files
│   ├── baseline.yaml              # Baseline behavior rules
│   └── network_rules.json         # Network analysis rules
│
├── 📂 models/                      # AI model storage
│   └── README.md                  # Model installation guide
│
├── 📂 logs/                        # Application logs
│   └── *.log                      # Various log files
│
├── 📂 src/                         # Source code modules
│   ├── ai_analyzer.py             # AI analysis engine
│   ├── gui.py                     # GUI application
│   ├── log_parser.py              # Log parsing and pattern matching
│   └── utils/                     # Utility modules
│
├── 📄 main.py                     # CLI entry point
├── 📄 gui.py                      # GUI entry point
├── 📄 ai_analyzer.py              # AI analyzer module
├── 📄 log_parser.py               # Log parser module
├── 📄 searcher.py                 # Search functionality
├── 📄 summarize.py                # Summarization module
├── 📄 settings.json               # Application settings
├── 📄 requirements.txt            # Python dependencies
└── 📄 README.md                   # This file
```

---

## ⚙️ Configuration

### Settings File (`settings.json`)

```json
{
  "auto_refresh": true,
  "min_severity": "0",
  "category": "ALL"
}
```

### Baseline Configuration (`config/baseline.yaml`)

Define baseline behaviors and whitelisting rules to reduce false positives. The scanner uses these to adjust severity scores based on known-good patterns.

### Network Rules (`config/network_rules.json`)

Configure network analysis parameters, port whitelisting, and connection frequency thresholds.

---

## 🛠️ Tools & Technologies

### Development Tools
- ![VS Code](https://img.shields.io/badge/VS%20Code-007ACC?style=flat-square&logo=visual-studio-code&logoColor=white) Code Editor
- ![Git](https://img.shields.io/badge/Git-F05032?style=flat-square&logo=git&logoColor=white) Version Control

### Tech Stack
- ![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white) Python 3.8+ - Core language
- ![LLM](https://img.shields.io/badge/LLM-Llama.cpp-FF6B6B?style=flat-square) llama-cpp-python - Local AI inference
- ![GUI](https://img.shields.io/badge/GUI-Tkinter-0066CC?style=flat-square) Tkinter - GUI framework
- ![Rich](https://img.shields.io/badge/Rich-Terminal%20UI-FFD700?style=flat-square) Rich - CLI formatting
- ![YAML](https://img.shields.io/badge/YAML-Configuration-CB171E?style=flat-square) YAML - Configuration files

### Key Libraries
- `llama-cpp-python` - GGUF model inference
- `rich` - Beautiful terminal output
- `tkinterdnd2` - Drag-and-drop support
- `psutil` - System resource monitoring
- `pandas` - Data manipulation (when needed)

---

## 🔒 Security Features

- ✅ **Local Processing** - All analysis happens locally, no data leaves your system
- ✅ **Pattern-Based Detection** - Multi-layer threat detection with severity scoring
- ✅ **Memory Safety** - Intelligent memory management for large file processing
- ✅ **False Positive Reduction** - Baseline-aware scoring reduces noise
- ✅ **Audit Logging** - Comprehensive logging of all operations
- ✅ **Resource Monitoring** - Automatic cleanup and resource management

---

## 🐛 Troubleshooting

### Common Issues

1. **AI Model Not Found**
   - **Symptom**: AI analysis shows "model not available" message
   - **Solution**: 
     - Download a GGUF model from the recommended sources
     - Place the `.gguf` file in the `models/` directory
     - Ensure you have at least 8GB RAM available
     - The application will work without a model but with reduced analysis capabilities

2. **Memory Errors**
   - **Symptom**: Application crashes or shows memory warnings
   - **Solution**:
     - Close other applications to free RAM
     - Process smaller log files or split large files
     - Reduce `MAX_THREADS` in configuration if needed
     - Use CLI mode which has lower memory overhead than GUI

3. **Import Errors**
   - **Symptom**: `ModuleNotFoundError` when running
   - **Solution**:
     ```bash
     pip install -r requirements.txt
     ```
     Ensure you're using Python 3.8 or higher

4. **Slow Processing**
   - **Symptom**: Analysis takes a very long time
   - **Solution**:
     - Check if AI model is loaded (adds processing time but provides better results)
     - Reduce log file size if possible
     - Use `--mode brief` for faster CLI analysis
     - Consider processing during off-peak hours

5. **GUI Not Starting**
   - **Symptom**: GUI window doesn't appear or crashes
   - **Solution**:
     - Ensure `tkinter` is installed: `sudo apt-get install python3-tk` (Linux)
     - Check logs in `logs/` directory for error messages
     - Try running with `--debug` flag for more information
     - Use CLI mode as alternative

### Debug Mode

Run with debug logging for more detailed information:
```bash
python main.py --file <file> --type <type> --debug
```

Check log files in the `logs/` directory for detailed error messages.

---

## 📊 Supported Threat Categories

- **NETWORK** - Network-based attacks, port scans, suspicious connections
- **SYSTEM** - System-level anomalies, privilege escalation attempts
- **MALWARE** - Malware indicators, suspicious processes, file modifications
- **EXPLOIT** - Exploit attempts, vulnerability exploitation patterns
- **AUTH** - Authentication failures, brute force attempts
- **RECON** - Reconnaissance activities, information gathering

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details (if available).

---

## 🙏 Acknowledgments

- Mistral AI for the Mistral 7B model
- Meta AI for the Llama 2 model
- The llama.cpp project for efficient model inference
- TheBloke for providing quantized GGUF model formats

---

<div align="center">

**ForensicScanner** - Local AI-Powered Forensic Analysis Tool

Built with ❤️ for security professionals and forensic analysts

[Report Bug](https://github.com/alexforman1/ForensicScanner/issues) • [Request Feature](https://github.com/alexforman1/ForensicScanner/issues) • [Documentation](https://github.com/alexforman1/ForensicScanner)

</div>
