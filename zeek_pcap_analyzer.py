#!/usr/bin/env python3
"""
Zeek PCAP Analyzer Tool
Analyzes PCAP files using Zeek and generates malicious traffic reports
"""

import os
import sys
import json
import subprocess
import argparse
import pandas as pd
from datetime import datetime
from pathlib import Path
import logging

class ZeekPCAPAnalyzer:
    def __init__(self, zeek_path="/usr/local/zeek/bin/zeek"):
        self.zeek_path = zeek_path
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('zeek_analyzer.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def check_zeek_installation(self):
        """Check if Zeek is installed and accessible"""
        try:
            result = subprocess.run([self.zeek_path, "--version"], 
                                  capture_output=True, text=True, check=True)
            self.logger.info(f"Zeek version: {result.stdout.strip()}")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.logger.error("Zeek not found. Please install Zeek or provide correct path.")
            return False
    
    def process_pcap_with_zeek(self, pcap_file, output_dir):
        """Process PCAP file with Zeek"""
        if not os.path.exists(pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Run Zeek on PCAP file
        cmd = [
            self.zeek_path,
            "-r", pcap_file,
            "-C",  # Ignore checksums
            f"Log::default_logdir={output_dir}"
        ]
        
        self.logger.info(f"Processing PCAP with Zeek: {pcap_file}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            self.logger.info("Zeek processing completed successfully")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Zeek processing failed: {e.stderr}")
            return False
    
    def load_zeek_logs(self, log_dir):
        """Load Zeek log files into pandas DataFrames"""
        logs = {}
        log_files = {
            'conn': 'conn.log',
            'dns': 'dns.log',
            'http': 'http.log',
            'ssl': 'ssl.log',
            'files': 'files.log',
            'notice': 'notice.log',
            'weird': 'weird.log',
            'intel': 'intel.log'
        }
        
        for log_type, filename in log_files.items():
            log_path = os.path.join(log_dir, filename)
            if os.path.exists(log_path):
                try:
                    # Read Zeek log file (TSV format with comments)
                    df = pd.read_csv(log_path, sep='\t', comment='#', 
                                   na_values=['-'], low_memory=False)
                    logs[log_type] = df
                    self.logger.info(f"Loaded {log_type}.log: {len(df)} records")
                except Exception as e:
                    self.logger.warning(f"Failed to load {log_type}.log: {e}")
        
        return logs
    
    def analyze_suspicious_connections(self, conn_df):
        """Analyze suspicious network connections"""
        suspicious = []
        
        if conn_df.empty:
            return suspicious
        
        # Check for suspicious ports
        suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5900]
        for port in suspicious_ports:
            if 'id.resp_p' in conn_df.columns:
                port_connections = conn_df[conn_df['id.resp_p'] == port]
                if not port_connections.empty:
                    suspicious.append({
                        'type': 'Suspicious Port Activity',
                        'description': f'Connections to port {port}',
                        'count': len(port_connections),
                        'details': port_connections[['id.orig_h', 'id.resp_h', 'id.resp_p']].to_dict('records')[:10]
                    })
        
        # Check for high data transfer
        if 'orig_bytes' in conn_df.columns and 'resp_bytes' in conn_df.columns:
            conn_df['total_bytes'] = pd.to_numeric(conn_df['orig_bytes'], errors='coerce').fillna(0) + \
                                   pd.to_numeric(conn_df['resp_bytes'], errors='coerce').fillna(0)
            high_transfer = conn_df[conn_df['total_bytes'] > 10000000]  # > 10MB
            if not high_transfer.empty:
                suspicious.append({
                    'type': 'High Data Transfer',
                    'description': 'Connections with unusually high data transfer',
                    'count': len(high_transfer),
                    'details': high_transfer[['id.orig_h', 'id.resp_h', 'total_bytes']].to_dict('records')[:10]
                })
        
        return suspicious
    
    def analyze_dns_activity(self, dns_df):
        """Analyze suspicious DNS activity"""
        suspicious = []
        
        if dns_df.empty:
            return suspicious
        
        # Check for DNS tunneling (long queries)
        if 'query' in dns_df.columns:
            long_queries = dns_df[dns_df['query'].str.len() > 50]
            if not long_queries.empty:
                suspicious.append({
                    'type': 'Potential DNS Tunneling',
                    'description': 'Unusually long DNS queries detected',
                    'count': len(long_queries),
                    'details': long_queries[['id.orig_h', 'query']].to_dict('records')[:10]
                })
        
        # Check for suspicious domains
        suspicious_keywords = ['malware', 'botnet', 'phishing', 'trojan', 'backdoor']
        if 'query' in dns_df.columns:
            for keyword in suspicious_keywords:
                suspicious_domains = dns_df[dns_df['query'].str.contains(keyword, case=False, na=False)]
                if not suspicious_domains.empty:
                    suspicious.append({
                        'type': 'Suspicious Domain Query',
                        'description': f'DNS queries containing "{keyword}"',
                        'count': len(suspicious_domains),
                        'details': suspicious_domains[['id.orig_h', 'query']].to_dict('records')[:10]
                    })
        
        return suspicious
    
    def analyze_http_activity(self, http_df):
        """Analyze suspicious HTTP activity"""
        suspicious = []
        
        if http_df.empty:
            return suspicious
        
        # Check for suspicious user agents
        suspicious_agents = ['bot', 'crawler', 'scanner', 'exploit']
        if 'user_agent' in http_df.columns:
            for agent in suspicious_agents:
                suspicious_ua = http_df[http_df['user_agent'].str.contains(agent, case=False, na=False)]
                if not suspicious_ua.empty:
                    suspicious.append({
                        'type': 'Suspicious User Agent',
                        'description': f'HTTP requests with "{agent}" in user agent',
                        'count': len(suspicious_ua),
                        'details': suspicious_ua[['id.orig_h', 'host', 'user_agent']].to_dict('records')[:5]
                    })
        
        # Check for suspicious URIs
        suspicious_uris = ['/admin', '/wp-admin', '/phpmyadmin', '.php?', 'cmd=', 'exec=']
        if 'uri' in http_df.columns:
            for uri_pattern in suspicious_uris:
                suspicious_uri = http_df[http_df['uri'].str.contains(uri_pattern, case=False, na=False)]
                if not suspicious_uri.empty:
                    suspicious.append({
                        'type': 'Suspicious URI Access',
                        'description': f'HTTP requests to URIs containing "{uri_pattern}"',
                        'count': len(suspicious_uri),
                        'details': suspicious_uri[['id.orig_h', 'host', 'uri']].to_dict('records')[:5]
                    })
        
        return suspicious
    
    def analyze_ssl_activity(self, ssl_df):
        """Analyze suspicious SSL/TLS activity"""
        suspicious = []
        
        if ssl_df.empty:
            return suspicious
        
        # Check for self-signed certificates
        if 'validation_status' in ssl_df.columns:
            self_signed = ssl_df[ssl_df['validation_status'].str.contains('self signed', case=False, na=False)]
            if not self_signed.empty:
                suspicious.append({
                    'type': 'Self-Signed Certificates',
                    'description': 'Connections using self-signed SSL certificates',
                    'count': len(self_signed),
                    'details': self_signed[['id.orig_h', 'id.resp_h', 'server_name']].to_dict('records')[:10]
                })
        
        return suspicious
    
    def analyze_notices_and_weird(self, notice_df, weird_df):
        """Analyze Zeek notices and weird events"""
        suspicious = []
        
        if not notice_df.empty:
            suspicious.append({
                'type': 'Zeek Notices',
                'description': 'Security notices generated by Zeek',
                'count': len(notice_df),
                'details': notice_df[['note', 'msg', 'src', 'dst']].to_dict('records')[:10] if 'note' in notice_df.columns else []
            })
        
        if not weird_df.empty:
            suspicious.append({
                'type': 'Weird Events',
                'description': 'Unusual network events detected by Zeek',
                'count': len(weird_df),
                'details': weird_df[['name', 'id.orig_h', 'id.resp_h']].to_dict('records')[:10] if 'name' in weird_df.columns else []
            })
        
        return suspicious
    
    def generate_report(self, suspicious_activities, output_file):
        """Generate malicious traffic report"""
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_suspicious_activities': len(suspicious_activities),
            'summary': {},
            'detailed_findings': suspicious_activities
        }
        
        # Generate summary
        activity_types = {}
        total_events = 0
        for activity in suspicious_activities:
            activity_type = activity['type']
            count = activity['count']
            activity_types[activity_type] = activity_types.get(activity_type, 0) + count
            total_events += count
        
        report['summary'] = {
            'total_suspicious_events': total_events,
            'activity_breakdown': activity_types
        }
        
        # Save report as JSON
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.info(f"Report saved to: {output_file}")
        return report
    
    def print_summary(self, report):
        """Print analysis summary to console"""
        print("\n" + "="*60)
        print("ZEEK PCAP ANALYSIS REPORT")
        print("="*60)
        print(f"Analysis Time: {report['analysis_timestamp']}")
        print(f"Total Suspicious Activities: {report['total_suspicious_activities']}")
        print(f"Total Suspicious Events: {report['summary']['total_suspicious_events']}")
        
        print("\nActivity Breakdown:")
        for activity_type, count in report['summary']['activity_breakdown'].items():
            print(f"  - {activity_type}: {count} events")
        
        print("\nDetailed Findings:")
        for i, activity in enumerate(report['detailed_findings'], 1):
            print(f"\n{i}. {activity['type']}")
            print(f"   Description: {activity['description']}")
            print(f"   Count: {activity['count']} events")
            if activity['details']:
                print("   Sample events:")
                for j, detail in enumerate(activity['details'][:3], 1):
                    print(f"     {j}. {detail}")
        
        print("\n" + "="*60)
    
    def analyze_pcap(self, pcap_file, output_dir=None):
        """Main analysis function"""
        if not self.check_zeek_installation():
            return None
        
        if output_dir is None:
            output_dir = f"zeek_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Process PCAP with Zeek
        if not self.process_pcap_with_zeek(pcap_file, output_dir):
            return None
        
        # Load Zeek logs
        logs = self.load_zeek_logs(output_dir)
        
        # Analyze for suspicious activities
        suspicious_activities = []
        
        if 'conn' in logs:
            suspicious_activities.extend(self.analyze_suspicious_connections(logs['conn']))
        
        if 'dns' in logs:
            suspicious_activities.extend(self.analyze_dns_activity(logs['dns']))
        
        if 'http' in logs:
            suspicious_activities.extend(self.analyze_http_activity(logs['http']))
        
        if 'ssl' in logs:
            suspicious_activities.extend(self.analyze_ssl_activity(logs['ssl']))
        
        if 'notice' in logs or 'weird' in logs:
            notice_df = logs.get('notice', pd.DataFrame())
            weird_df = logs.get('weird', pd.DataFrame())
            suspicious_activities.extend(self.analyze_notices_and_weird(notice_df, weird_df))
        
        # Generate report
        report_file = os.path.join(output_dir, 'malicious_traffic_report.json')
        report = self.generate_report(suspicious_activities, report_file)
        
        # Print summary
        self.print_summary(report)
        
        return report

def main():
    parser = argparse.ArgumentParser(description='Zeek PCAP Analyzer - Detect malicious traffic')
    parser.add_argument('pcap_file', help='Path to PCAP file to analyze')
    parser.add_argument('-o', '--output', help='Output directory for analysis results')
    parser.add_argument('-z', '--zeek-path', default='/usr/local/zeek/bin/zeek', 
                       help='Path to Zeek binary (default: /usr/local/zeek/bin/zeek)')
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = ZeekPCAPAnalyzer(zeek_path=args.zeek_path)
    
    # Run analysis
    try:
        report = analyzer.analyze_pcap(args.pcap_file, args.output)
        if report:
            print(f"\nAnalysis completed successfully!")
            print(f"Results saved in: {args.output or f'zeek_analysis_{datetime.now().strftime(\"%Y%m%d_%H%M%S\")}'}")
        else:
            print("Analysis failed. Check logs for details.")
            sys.exit(1)
    except Exception as e:
        print(f"Error during analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()