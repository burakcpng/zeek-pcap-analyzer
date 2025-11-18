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
pip install pandas
````

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
python zeek_pcap_analyzer.py sample.pcap -o analysis_results -z /usr/local/zeek/bin/zeek
```

## Detected Threats

### 1. Suspicious Port Activity

* Connections to SSH (22), Telnet (23), SMB (445), RDP (3389), etc.
* Unauthorized access attempts to management ports

### 2. DNS Anomalies

* DNS tunneling (long queries)
* Malicious domain names (containing malware, botnet, phishing)

### 3. HTTP Threats

* Suspicious User-Agent strings (bot, scanner, exploit)
* Malicious URI accesses (/admin, /wp-admin, command injection)

### 4. SSL/TLS Issues

* Self-signed certificates
* Certificate validation failures

### 5. Zeek Alerts

* Zeek notice events
* Weird network events

## Output Files

The tool generates:

1. **Zeek Log Files**: conn.log, dns.log, http.log, ssl.log, etc.
2. **malicious_traffic_report.json**: Detailed analysis report
3. **zeek_analyzer.log**: Tool execution log

### Example Report Structure

```json
{
  "analysis_timestamp": "2024-01-15T10:30:00",
  "total_suspicious_activities": 5,
  "summary": {
    "total_suspicious_events": 150,
    "activity_breakdown": {
      "Suspicious Port Activity": 45,
      "Potential DNS Tunneling": 12,
      "Suspicious User Agent": 93
    }
  },
  "detailed_findings": [...]
}
```

## Customization

You can modify detection rules by editing the relevant analysis functions:

* `analyze_suspicious_connections()` — connection analysis
* `analyze_dns_activity()` — DNS analysis
* `analyze_http_activity()` — HTTP analysis
* `analyze_ssl_activity()` — SSL analysis

## Limitations

* Zeek must be installed on your system
* Large PCAP files require sufficient disk space
* Analysis duration depends on PCAP file size

## License

MIT License

```

