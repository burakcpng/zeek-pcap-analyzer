<h1 align="center">🔍 Zeek PCAP Analyzer</h1>
<p align="center">
  <strong>Advanced PCAP Analysis Tool using Zeek for Threat Detection</strong>
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Zeek-Network%20Security-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge">
</p>



<!-- ======================== ASCII HEADER ======================== -->


Zeek PCAP Analyzer
Advanced Threat Detection for Network Analysts

---

````markdown
```markdown
# Zeek PCAP Analyzer

This Python tool analyzes PCAP files using **Zeek**, detects malicious network traffic, and generates detailed reports.

## Features

- Process PCAP files with Zeek  
- Detect suspicious network connections  
- Analyze DNS tunneling and malicious domain queries  
- Detect malicious HTTP activity  
- Inspect SSL/TLS certificate anomalies  
- Analyze Zeek notices and weird events  
- Generate detailed reports in JSON format  

## Requirements

Install Python dependencies:

```bash
pip install -r requirements.txt
```
```

Zeek must also be installed on your system:

* **Ubuntu/Debian:** `sudo apt-get install zeek`
* **CentOS/RHEL:** `sudo yum install zeek`
* **macOS:** `brew install zeek`

## Usage

### Basic Usage

```bash
python zeek_pcap_analyzer.py sample.pcap
```

### Advanced Usage

```bash
# Specify output directory
python zeek_pcap_analyzer.py sample.pcap -o /path/to/output

# Specify Zeek binary path
python zeek_pcap_analyzer.py sample.pcap -z /usr/bin/zeek

# Full example
